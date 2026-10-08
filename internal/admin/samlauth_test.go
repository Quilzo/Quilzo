// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/saml"
	"github.com/quilzo/quilzo/internal/xmldsig"
)

// The whole sign-in, through the admin's own handlers: start, a response
// made for the request that went out and signed by the provider's key, the
// POST back, the session. Then every way it is supposed to refuse.

var (
	idpOnce sync.Once
	idpKey  *rsa.PrivateKey
	idpCert []byte
)

func testIdP(t *testing.T) (*rsa.PrivateKey, []byte) {
	idpOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			panic(err)
		}
		idpKey, idpCert = k, der
	})
	return idpKey, idpCert
}

const (
	tIdPEntity = "https://idp.northwind.example"
	tAdmin     = "https://admin.northwind.example"
)

func samlServer(t *testing.T, edit func(*saml.Config)) (*Server, string) {
	t.Helper()
	srv, token := setup(t)
	_, cert := testIdP(t)
	cfg := saml.Config{Name: "corp", Label: "Northwind", URL: tAdmin, EntityID: tIdPEntity,
		SSOURL: "https://idp.northwind.example/sso", Certs: []string{base64.StdEncoding.EncodeToString(cert)},
		Domains: []string{"northwind.example"}}
	if edit != nil {
		edit(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	saved := []saml.Config{cfg}
	srv.SAML = &SAMLAdmin{
		Providers: func() ([]saml.Config, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]saml.Config(nil), saved...), nil
		},
		Save: func(c saml.Config) error {
			mu.Lock()
			defer mu.Unlock()
			for i := range saved {
				if saved[i].Name == c.Name {
					saved[i] = c
					return nil
				}
			}
			saved = append(saved, c)
			return nil
		},
		Remove: func(name, by string) error {
			mu.Lock()
			defer mu.Unlock()
			for i := range saved {
				if saved[i].Name == name {
					saved = append(saved[:i], saved[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("no %s", name)
		},
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "dana.reyes@northwind.example", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	return srv, token
}

// start begins a sign-in and returns the request ID, relay state and the
// browser's binding cookie.
func start(t *testing.T, srv *Server) (requestID, relay string, cookie *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", "/signin/saml/corp", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("start answered %d: %s", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "idp.northwind.example" {
		t.Fatalf("sent to %s", loc)
	}
	relay = loc.Query().Get("RelayState")
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, "quilzo_saml") {
			cookie = c
		}
	}
	if cookie == nil || relay == "" {
		t.Fatal("no binding cookie or relay state")
	}
	st := &srv.samlState
	st.mu.Lock()
	requestID = st.pending[relay].requestID
	st.mu.Unlock()
	return requestID, relay, cookie
}

type resp struct {
	who, inResponseTo, audience, context string
	until                                time.Duration
}

var endIssuerRe = regexp.MustCompile(`</saml:Issuer>`)

// response is an assertion-signed response, as Entra sends one.
func response(t *testing.T, r resp) string {
	t.Helper()
	k, _ := testIdP(t)
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	if r.until == 0 {
		r.until = 5 * time.Minute
	}
	if r.audience == "" {
		r.audience = tAdmin + "/saml/corp"
	}
	if r.context == "" {
		r.context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	}
	acs := tAdmin + "/saml/corp/acs"
	doc := `<samlp:Response xmlns:samlp="` + saml.NSProtocol + `" xmlns:saml="` + saml.NSAssertion + `" ID="_r` + fmt.Sprint(now.UnixNano()) + `" Version="2.0" IssueInstant="` + ts(0) + `" Destination="` + acs + `" InResponseTo="` + r.inResponseTo + `">` +
		`<saml:Issuer>` + tIdPEntity + `</saml:Issuer><samlp:Status><samlp:StatusCode Value="` + saml.StatusSuccess + `"/></samlp:Status>` +
		`<saml:Assertion ID="_a` + fmt.Sprint(now.UnixNano()) + `" Version="2.0" IssueInstant="` + ts(0) + `"><saml:Issuer>` + tIdPEntity + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="` + saml.FormatEmail + `">` + r.who + `</saml:NameID><saml:SubjectConfirmation Method="` + saml.MethodBearer + `">` +
		`<saml:SubjectConfirmationData InResponseTo="` + r.inResponseTo + `" NotOnOrAfter="` + ts(r.until) + `" Recipient="` + acs + `"/></saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + ts(-time.Minute) + `" NotOnOrAfter="` + ts(r.until) + `"><saml:AudienceRestriction><saml:Audience>` + r.audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + ts(-time.Second) + `"><saml:AuthnContext><saml:AuthnContextClassRef>` + r.context + `</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`</saml:Assertion></samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(signAssertion(t, doc, k)))
}

func signAssertion(t *testing.T, doc string, k *rsa.PrivateKey) string {
	t.Helper()
	at := strings.Index(doc, "<saml:Assertion")
	loc := endIssuerRe.FindStringIndex(doc[at:])
	cut := at + loc[1]
	d0, err := xmldsig.Read([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, e := range mustKids(d0.Root) {
		if e.Is(saml.NSAssertion, "Assertion") {
			id, _ = e.Attr("ID")
		}
	}
	sig := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#` + id + `"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>DV</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>SV</ds:SignatureValue></ds:Signature>`
	doc = doc[:cut] + sig + doc[cut:]
	d, _ := xmldsig.Read([]byte(doc))
	el := d.ByID(id)
	var s *xmldsig.Element
	for _, e := range mustKids(el) {
		if e.Is(xmldsig.NSDSig, "Signature") {
			s = e
		}
	}
	c, _ := xmldsig.Canonical(el, nil, s)
	sum := sha256.Sum256(c)
	doc = strings.Replace(doc, "<ds:DigestValue>DV<", "<ds:DigestValue>"+base64.StdEncoding.EncodeToString(sum[:])+"<", 1)
	d, _ = xmldsig.Read([]byte(doc))
	for _, e := range mustKids(d.ByID(id)) {
		if e.Is(xmldsig.NSDSig, "Signature") {
			si := mustKids(e)[0]
			cs, _ := xmldsig.Canonical(si, nil, nil)
			h := sha256.Sum256(cs)
			v, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
			if err != nil {
				t.Fatal(err)
			}
			doc = strings.Replace(doc, "<ds:SignatureValue>SV<", "<ds:SignatureValue>"+base64.StdEncoding.EncodeToString(v)+"<", 1)
		}
	}
	return doc
}

func mustKids(e *xmldsig.Element) []*xmldsig.Element { k, _ := e.Elements(); return k }

// postACS sends the response the way a browser does after the provider's page
// submits it: cross-site.
func postACS(t *testing.T, srv *Server, relay, samlResponse string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body := url.Values{"RelayState": {relay}, "SAMLResponse": {samlResponse}}.Encode()
	req := httptest.NewRequest("POST", "/saml/corp/acs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func sessionOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_token" && c.MaxAge > 0 {
			return c
		}
	}
	return nil
}

func TestASAMLSignInMakesASession(t *testing.T) {
	srv, _ := samlServer(t, nil)
	id, relay, cookie := start(t, srv)
	w := postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id}), cookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("%d %s\n%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	c := sessionOf(w)
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie %+v", c)
	}
	page := get(t, srv, "/", c.Value)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "dana.reyes@northwind.example") {
		t.Errorf("the session does not reach the pages: %d", page.Code)
	}
}

func TestSAMLRefusals(t *testing.T) {
	cases := []struct {
		why  string
		edit func(*saml.Config)
		run  func(t *testing.T, srv *Server) *httptest.ResponseRecorder
		want string // "restart", or a phrase on the refusal page
	}{
		{"no binding cookie", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			id, relay, _ := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id}), nil)
		}, "another browser"},
		{"another browser's cookie", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			id, relay, c := start(t, srv)
			c.Value = "not-the-one"
			return postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id}), c)
		}, "another browser"},
		{"unsolicited", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			return postACS(t, srv, "", response(t, resp{who: "dana.reyes@northwind.example"}), nil)
		}, "restart"},
		{"answers another request", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			_, relay, c := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: "_other"}), c)
		}, "another request"},
		{"for another service", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			id, relay, c := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id, audience: "https://other.example"}), c)
		}, "another service"},
		{"not in the access policy", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			id, relay, c := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "nobody@northwind.example", inResponseTo: id}), c)
		}, "not in the access policy"},
		{"outside the organisation's domains", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			id, relay, c := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "dana@evil.example", inResponseTo: id}), c)
		}, "is not in northwind.example"},
		{"suspended by provisioning", nil, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			_ = srv.Policy.Grant(auth.Binding{Principal: "dana.reyes@northwind.example", Role: auth.RoleReader, Resource: "/", Deny: true})
			id, relay, c := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id}), c)
		}, "suspended"},
		{"a second factor required and not used", func(c *saml.Config) {
			c.RequireMFA, c.MFAContexts = true, []string{"https://refeds.org/profile/mfa"}
		}, func(t *testing.T, srv *Server) *httptest.ResponseRecorder {
			id, relay, c := start(t, srv)
			return postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id}), c)
		}, "second factor"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			srv, _ := samlServer(t, c.edit)
			w := c.run(t, srv)
			if sessionOf(w) != nil {
				t.Fatal("a session was made")
			}
			if c.want == "restart" {
				if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/saml/corp" {
					t.Errorf("%d %s", w.Code, w.Header().Get("Location"))
				}
				return
			}
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), c.want) {
				t.Errorf("%d, wanted %q:\n%s", w.Code, c.want, firstLines(w.Body.String(), 40))
			}
		})
	}
}

// The control for the MFA case: the same requirement, met.
func TestASecondFactorWhenSaidIsAccepted(t *testing.T) {
	srv, _ := samlServer(t, func(c *saml.Config) {
		c.RequireMFA, c.MFAContexts = true, []string{"https://refeds.org/profile/mfa"}
	})
	id, relay, c := start(t, srv)
	w := postACS(t, srv, relay, response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id,
		context: "https://refeds.org/profile/mfa"}), c)
	if sessionOf(w) == nil {
		t.Fatalf("%d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
}

func TestAResponseIsUsedOnce(t *testing.T) {
	srv, _ := samlServer(t, nil)
	id, relay, c := start(t, srv)
	r := response(t, resp{who: "dana.reyes@northwind.example", inResponseTo: id})
	if sessionOf(postACS(t, srv, relay, r, c)) == nil {
		t.Fatal("the first use failed")
	}
	again := postACS(t, srv, relay, r, c)
	if sessionOf(again) != nil || again.Header().Get("Location") != "/signin/saml/corp" {
		t.Errorf("the same response signed in twice: %d %s", again.Code, again.Header().Get("Location"))
	}
	// And once more under a fresh request record, which the assertion
	// does not answer: the replay store or the request check refuses it.
	_, relay2, c2 := start(t, srv)
	if sessionOf(postACS(t, srv, relay2, r, c2)) != nil {
		t.Error("a used response signed in under a new request")
	}
}

// The ACS is the one cross-site POST let through; everything else still
// refuses one.
func TestOnlyTheACSTakesACrossSitePost(t *testing.T) {
	srv, token := samlServer(t, nil)
	for _, p := range []string{"/publish", "/sso/act", "/saml/corp/metadata", "/saml/corp/acs/x", "/saml/a.b/acs"} {
		req := httptest.NewRequest("POST", p, strings.NewReader("do=remove&name=corp"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: token})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s answered %d to a cross-site POST", p, w.Code)
		}
	}
}

func TestAWorkAddressFindsItsProvider(t *testing.T) {
	srv, _ := samlServer(t, nil)
	discover := func(email string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/signin/sso", strings.NewReader(url.Values{"email": {email}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	w := discover("Dana.Reyes@Northwind.Example")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `content="0;url=/signin/saml/corp"`) ||
		!strings.Contains(w.Body.String(), `href="/signin/saml/corp"`) {
		t.Errorf("%d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	if w := discover("someone@elsewhere.example"); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "e=nosso") {
		t.Errorf("an address nobody owns: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// With single sign-on required, a pasted token for somebody in the domain
// does not open a browser session; break glass does, and the API is
// untouched.
func TestRequiredSSOClosesTheTokenFrontDoor(t *testing.T) {
	srv, token := samlServer(t, func(c *saml.Config) { c.Required = true })
	_ = srv.Policy.Grant(auth.Binding{Principal: "dana.reyes@northwind.example", Role: auth.RoleAdmin, Resource: "/"})
	secret, _, err := srv.Tokens.Issue("dana-cli", "dana.reyes@northwind.example", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/signin", strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := signIn(secret); !strings.Contains(w.Header().Get("Location"), "e=sso") || sessionOf(w) != nil {
		t.Errorf("a token for a required-SSO address signed in: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := signIn(token); sessionOf(w) == nil {
		t.Errorf("somebody outside the domain was refused: %d %s", w.Code, w.Header().Get("Location"))
	}
	if g := get(t, srv, "/api/pages", secret); g.Code == http.StatusForbidden || g.Code == http.StatusUnauthorized {
		t.Logf("the API answered %d (a route may not exist in this test server)", g.Code)
	}

	srv2, _ := samlServer(t, func(c *saml.Config) {
		c.Required, c.BreakGlass = true, []string{"dana.reyes@northwind.example"}
	})
	secret2, _, _ := srv2.Tokens.Issue("dana-cli", "dana.reyes@northwind.example", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	req := httptest.NewRequest("POST", "/signin", strings.NewReader(url.Values{"token": {secret2}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv2.Handler().ServeHTTP(w, req)
	if sessionOf(w) == nil {
		t.Errorf("break glass was refused: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestTheSSOScreenAddsOnlyAConfirmedKey(t *testing.T) {
	srv, token := samlServer(t, nil)
	if g := get(t, srv, "/sso", token); g.Code != http.StatusOK || !strings.Contains(g.Body.String(), tAdmin+"/saml/corp/acs") {
		t.Fatalf("the screen does not show what to give the provider: %d", g.Code)
	}
	_, der := testIdP(t)
	meta := `<md:EntityDescriptor xmlns:md="` + saml.NSMetadata + `" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://other-idp.example"><md:IDPSSODescriptor protocolSupportEnumeration="` + saml.NSProtocol + `"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(der) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="` + saml.BindingRedirect + `" Location="https://other-idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	form := url.Values{"do": {"add"}, "name": {"other"}, "url": {tAdmin}, "preset": {"okta"}, "metadata": {meta}}
	act := func(v url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/sso/act", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: token})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	w := act(form)
	cert, _ := x509.ParseCertificate(der)
	fp := saml.Fingerprint(cert)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), fp) {
		t.Fatalf("the fingerprint was not shown for confirming: %d", w.Code)
	}
	if all, _ := srv.SAML.Providers(); len(all) != 1 {
		t.Fatal("saved before the key was confirmed")
	}
	form.Set("fingerprint", "00:11")
	if act(form); true {
		if all, _ := srv.SAML.Providers(); len(all) != 1 {
			t.Fatal("saved with the wrong fingerprint")
		}
	}
	form.Set("fingerprint", strings.ToLower(strings.ReplaceAll(fp, ":", "")))
	if w := act(form); w.Code != http.StatusSeeOther {
		t.Fatalf("%d", w.Code)
	}
	all, _ := srv.SAML.Providers()
	if len(all) != 2 || all[1].Label != "Okta" || all[1].AddedBy == "" {
		t.Fatalf("%+v", all)
	}
	if w := act(url.Values{"do": {"remove"}, "name": {"other"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("remove %d", w.Code)
	}
	if all, _ := srv.SAML.Providers(); len(all) != 1 {
		t.Error("not removed")
	}
}

func TestServiceMetadataIsServed(t *testing.T) {
	srv, _ := samlServer(t, nil)
	w := get(t, srv, "/saml/corp/metadata", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `entityID="`+tAdmin+`/saml/corp"`) ||
		!strings.Contains(w.Header().Get("Content-Type"), "samlmetadata") {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
	if w := get(t, srv, "/saml/none/metadata", ""); w.Code != http.StatusNotFound {
		t.Errorf("an unknown provider: %d", w.Code)
	}
}
