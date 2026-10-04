// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/saml"
)

// SAML sign-in, beside OIDC, passkeys and tokens. internal/saml decides
// whether a response is acceptable; this file decides what happens around
// it, and it is deliberately the same as what happens around an OIDC
// sign-in: the provider says who somebody is, the access policy says what
// they may do, and the session is this program's own.
//
// # The request is bound to the browser that made it
//
// Starting a sign-in stores, on this server, the request's ID and a hash of
// a random value set as a cookie in the browser. The response is accepted
// only if its relay state finds that record, the same browser presents the
// cookie, and the signed assertion answers that request ID. So a response
// captured from one browser cannot be used in another, a response nobody
// asked for signs nobody in (it starts a sign-in instead), and each record
// is used once.
//
// # Why the assertion consumer service takes a cross-site POST
//
// Every other form here refuses a request from another site. This address
// cannot: the identity provider's page posts the response to it, which is
// what the POST binding is. It is safe to let through because nothing
// happens here unless a signed assertion answers a request this browser
// made, which no other site can produce.

// SAMLAdmin is SAML as the admin reaches it.
type SAMLAdmin struct {
	// Providers reads the configured providers, fresh on each use, so one
	// added or removed from the command line applies at once.
	Providers func() ([]saml.Config, error)
	// Fetch reads metadata from an address, through the egress policy.
	Fetch func(addr string) ([]byte, error)
	// Save and Remove change the configuration; both are recorded.
	Save   func(c saml.Config) error
	Remove func(name, by string) error
}

type samlPending struct {
	provider  string
	requestID string
	binding   [32]byte
	created   time.Time
}

// samlState is what sign-ins in progress need, kept in this process.
type samlState struct {
	mu      sync.Mutex
	pending map[string]*samlPending
	seen    saml.Seen
}

const (
	samlPendingTTL = 10 * time.Minute
	samlMaxPending = 1000
)

func (s *Server) samlProvider(name string) (*saml.Config, error) {
	if s.SAML == nil || s.SAML.Providers == nil {
		return nil, errors.New("single sign-on with SAML is not set up")
	}
	all, err := s.SAML.Providers()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("there is no identity provider called %q", name)
}

// samlRoute splits /saml/NAME/what and /signin/saml/NAME.
func samlRoute(path, prefix string) (name, rest string) {
	p := strings.TrimPrefix(path, prefix)
	name, rest, _ = strings.Cut(p, "/")
	return name, rest
}

// isSAMLACS reports whether a request is the one cross-site POST the
// admin accepts. Named here so the exemption in sameSiteOnly and the route
// cannot drift apart.
func isSAMLACS(r *http.Request) bool {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/saml/") {
		return false
	}
	name, rest := samlRoute(r.URL.Path, "/saml/")
	return rest == "acs" && name != "" && !strings.Contains(name, ".")
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// samlCookie is where the browser's half of the binding lives. __Host- and
// SameSite=None over TLS, because the response arrives as a cross-site
// POST; on a loopback deployment without TLS, a plain Lax cookie, which a
// provider on the same machine is same-site to.
func (s *Server) samlCookie(r *http.Request) (name string, secure bool, same http.SameSite) {
	if r.TLS != nil || s.behindTLSProxy() {
		return "__Host-quilzo_saml", true, http.SameSiteNoneMode
	}
	return "quilzo_saml", false, http.SameSiteLaxMode
}

// handleSAMLStart sends the browser to the identity provider.
func (s *Server) handleSAMLStart(w http.ResponseWriter, r *http.Request) {
	name, rest := samlRoute(r.URL.Path, "/signin/saml/")
	if rest != "" {
		http.NotFound(w, r)
		return
	}
	cfg, err := s.samlProvider(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := cfg.Provider()
	if err != nil {
		s.refuseSignIn(w, r, "This identity provider's configuration cannot be used: "+err.Error(), "")
		return
	}
	id, err := saml.NewRequestID()
	if err != nil {
		http.Error(w, "cannot begin sign-in", http.StatusInternalServerError)
		return
	}
	relay, err := randomToken(24)
	if err != nil {
		http.Error(w, "cannot begin sign-in", http.StatusInternalServerError)
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		http.Error(w, "cannot begin sign-in", http.StatusInternalServerError)
		return
	}
	target, err := p.AuthnRequestURL(id, relay, time.Now())
	if err != nil {
		s.refuseSignIn(w, r, err.Error(), "")
		return
	}
	st := &s.samlState
	st.mu.Lock()
	if st.pending == nil {
		st.pending = map[string]*samlPending{}
	}
	now := time.Now()
	for k, v := range st.pending {
		if now.Sub(v.created) > samlPendingTTL {
			delete(st.pending, k)
		}
	}
	if len(st.pending) >= samlMaxPending {
		st.mu.Unlock()
		http.Error(w, "too many sign-ins in progress", http.StatusTooManyRequests)
		return
	}
	st.pending[relay] = &samlPending{provider: name, requestID: id,
		binding: sha256.Sum256([]byte(secret)), created: now}
	st.mu.Unlock()

	cn, secure, same := s.samlCookie(r)
	http.SetCookie(w, &http.Cookie{Name: cn, Value: secret, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: same, MaxAge: int(samlPendingTTL.Seconds())})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// takeSAMLPending consumes the record a relay state names, so it cannot be
// used twice.
func (s *Server) takeSAMLPending(relay string) *samlPending {
	st := &s.samlState
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, v := range st.pending {
		if subtle.ConstantTimeCompare([]byte(k), []byte(relay)) == 1 {
			delete(st.pending, k)
			if time.Since(v.created) > samlPendingTTL {
				return nil
			}
			return v
		}
	}
	return nil
}

// handleSAML answers /saml/NAME/acs and /saml/NAME/metadata.
func (s *Server) handleSAML(w http.ResponseWriter, r *http.Request) {
	name, rest := samlRoute(r.URL.Path, "/saml/")
	cfg, err := s.samlProvider(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch rest {
	case "metadata":
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Header().Set("Content-Disposition", `attachment; filename="quilzo-`+cfg.Name+`.xml"`)
		_, _ = w.Write(saml.ServiceMetadata(cfg.ServiceEntityID(), cfg.ACS(), time.Now().AddDate(1, 0, 0)))
	case "acs":
		s.samlACS(w, r, cfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) samlACS(w http.ResponseWriter, r *http.Request, cfg *saml.Config) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the identity provider posts here", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	cn, secure, same := s.samlCookie(r)
	clear := func() {
		http.SetCookie(w, &http.Cookie{Name: cn, Value: "", Path: "/", HttpOnly: true,
			Secure: secure, SameSite: same, MaxAge: -1})
	}
	restart := func() {
		clear()
		http.Redirect(w, r, "/signin/saml/"+cfg.Name, http.StatusSeeOther)
	}
	fail := func(reason string) {
		clear()
		s.audit("signin.saml.refused", "/", map[string]string{"provider": cfg.Name, "why": reason})
		s.refuseSignIn(w, r, reason, "")
	}

	pending := s.takeSAMLPending(r.PostFormValue("RelayState"))
	if pending == nil {
		// Nothing this browser started: a tile on the provider's dashboard,
		// a stale tab, or somebody else's response. None of them signs
		// anybody in; the first two get a sign-in that works.
		restart()
		return
	}
	c, err := r.Cookie(cn)
	if err != nil || pending.provider != cfg.Name {
		fail("This sign-in was started in another browser, or for another identity provider. Start again here.")
		return
	}
	got := sha256.Sum256([]byte(c.Value))
	if subtle.ConstantTimeCompare(got[:], pending.binding[:]) != 1 {
		fail("This sign-in was started in another browser. Start again here.")
		return
	}
	p, err := cfg.Provider()
	if err != nil {
		fail("This identity provider's configuration cannot be used: " + err.Error())
		return
	}
	now := time.Now()
	a, err := p.ParseResponse(r.PostFormValue("SAMLResponse"), pending.requestID, now)
	var se *saml.StatusError
	switch {
	case errors.Is(err, saml.ErrUnsolicited):
		restart()
		return
	case errors.As(err, &se):
		code := se.Code
		if se.Second != "" {
			code += ", " + se.Second
		}
		fail(label(cfg) + " did not sign you in (" + code + ").")
		return
	case err != nil:
		fail("The response from " + label(cfg) + " was refused: " + err.Error())
		return
	}
	if !s.samlState.seen.Use(a.ID, a.Until, now) {
		fail("This response has already been used.")
		return
	}
	principal, err := cfg.PrincipalOf(a)
	if err != nil {
		fail(err.Error())
		return
	}
	if cfg.RequireMFA && !cfg.MFA(a) {
		fail(label(cfg) + " did not say you used a second factor, and this site requires one. " +
			"Sign in at " + label(cfg) + " with your second factor and try again.")
		return
	}
	s.finishSSO(w, r, principal, "saml:"+cfg.Name, saml.SessionTTL(a, DefaultSessionTTL, now),
		map[string]string{"provider": cfg.Name, "issuer": a.Issuer, "assertion": a.ID,
			"context": a.AuthnContext}, clear)
}

func label(c *saml.Config) string {
	if c.Label != "" {
		return c.Label
	}
	return "the identity provider"
}

// finishSSO is the end every single sign-on shares: refused if suspended or
// not in the access policy, otherwise a session of this program's own.
func (s *Server) finishSSO(w http.ResponseWriter, r *http.Request, principal, how string,
	ttl time.Duration, detail map[string]string, before func()) {
	if s.suspended(principal) {
		before()
		s.refuseSignIn(w, r, principal+" is suspended here: the identity provider deactivated or removed them.", "")
		return
	}
	if !s.knownPrincipal(principal) {
		before()
		s.refuseSignIn(w, r,
			fmt.Sprintf("%s signed in successfully, but is not in the access policy for this site.", principal),
			fmt.Sprintf("An administrator can add them:  quilzo auth grant %s author", principal))
		return
	}
	if ttl < time.Minute {
		before()
		s.refuseSignIn(w, r, "The identity provider's own session ends in under a minute. Sign in there again.", "")
		return
	}
	secret, tok, err := s.Tokens.IssueSession(how+":"+principal, principal, s.roleFor(principal), "/", ttl, auth.RoleAdmin)
	if err != nil {
		before()
		s.refuseSignIn(w, r, "the session could not be created: "+err.Error(), "")
		return
	}
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			before()
			s.refuseSignIn(w, r, "the session could not be stored: "+err.Error(), "")
			return
		}
	}
	d := map[string]string{"by": principal, "session": tok.ID, "how": how}
	for k, v := range detail {
		d[k] = v
	}
	s.audit("session.start", "/", d)
	stepUp, serr := s.signInCheck(r, principal, tok.ID, "sso", false)
	if serr != nil {
		before()
		s.refuseSignIn(w, r, serr.Error(), "")
		return
	}
	s.signInDone(r, tok.ID)
	before()
	http.SetCookie(w, &http.Cookie{
		Name: "quilzo_token", Value: secret, Path: "/", HttpOnly: true,
		// Lax for the same reason as OIDC: the browser arrives here from
		// the identity provider, and Strict would drop the cookie on the
		// way in. Lax still keeps it off other sites' POSTs.
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || s.behindTLSProxy(),
		MaxAge: int(ttl.Seconds()),
	})
	if stepUp {
		http.Redirect(w, r, "/signin/verify", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// suspended reports whether provisioning has suspended somebody: a deny on
// the whole site, which a sign-in must not route around by minting a
// session that every screen would then refuse.
func (s *Server) suspended(principal string) bool {
	for _, b := range s.Policy.Snapshot() {
		if b.Deny && b.Resource == "/" && strings.EqualFold(b.Principal, principal) {
			return true
		}
	}
	return false
}

// ssoProviderRow is one way in, as the sign-in page offers it.
type ssoProviderRow struct {
	Name, Label, Href string
}

// ssoChoices are the SAML providers, for the sign-in page.
func (s *Server) ssoChoices() []ssoProviderRow {
	if s.SAML == nil || s.SAML.Providers == nil {
		return nil
	}
	all, err := s.SAML.Providers()
	if err != nil {
		return nil
	}
	var out []ssoProviderRow
	for _, c := range all {
		out = append(out, ssoProviderRow{Name: c.Name, Label: label(&c), Href: "/signin/saml/" + c.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// handleSSODiscover sends a work address to the provider that owns its
// domain. Domains are claimed by an administrator here, never by the
// identity provider, so an address cannot choose where it is sent.
func (s *Server) handleSSODiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the sign-in page posts a work address here", http.StatusMethodNotAllowed)
		return
	}
	addr := strings.TrimSpace(r.FormValue("email"))
	// Not a redirect. The admin's policy says form-action 'self', and a
	// browser applies that to every hop a form submission is redirected
	// through, so a 303 that ends at the identity provider is stopped,
	// silently, at the first hop off this origin. A page that moves on by
	// itself is a navigation, not a form submission, and has a link besides.
	onward := func(href, name string) {
		s.render(w, r, "signin.html", map[string]any{"Title": "Sign in",
			"Continue": ssoProviderRow{Label: name, Href: href}})
	}
	if s.SAML != nil && s.SAML.Providers != nil {
		if all, err := s.SAML.Providers(); err == nil {
			for _, c := range all {
				if c.Owns(addr) {
					onward("/signin/saml/"+c.Name, label(&c))
					return
				}
			}
		}
	}
	if s.OIDC != nil {
		if _, d, ok := strings.Cut(strings.ToLower(addr), "@"); ok {
			for _, want := range s.OIDC.Domains {
				if strings.EqualFold(d, want) {
					name := s.oidcLabel()
					if name == "" {
						name = "your organisation"
					}
					onward("/signin/oidc", name)
					return
				}
			}
		}
	}
	signInAgain(w, r, "nosso")
}

// ssoRequired names the provider somebody must use, or "" if they may sign
// in with a token or a passkey.
func (s *Server) ssoRequired(principal string) string {
	if s.SAML == nil || s.SAML.Providers == nil {
		return ""
	}
	all, err := s.SAML.Providers()
	if err != nil {
		return ""
	}
	for _, c := range all {
		if !c.Required || !c.Owns(principal) {
			continue
		}
		glass := false
		for _, b := range c.BreakGlass {
			glass = glass || strings.EqualFold(b, principal)
		}
		if !glass {
			return label(&c)
		}
	}
	return ""
}

// -- the Single sign-on screen ----------------------------------------------

type samlCertRow struct {
	Subject, Fingerprint, Expires string
	Soon                          bool
}

type samlRow struct {
	saml.Config
	SP, ACS, Metadata string
	CertRows          []samlCertRow
	Problem           string
}

func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	s.renderSSO(w, r, p, nil)
}

func (s *Server) renderSSO(w http.ResponseWriter, r *http.Request, p principal, preview map[string]any) {
	data := map[string]any{"Title": "Single sign-on", "Nav": "sso", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"), "Preview": preview,
		"OIDC": s.OIDC != nil, "OIDCLabel": s.oidcLabel(), "Presets": samlPresetRows()}
	if s.OIDC != nil {
		data["OIDCDomains"] = strings.Join(s.OIDC.Domains, ", ")
	}
	if s.SAML == nil || s.SAML.Providers == nil {
		data["Unavailable"] = "This build was started without SAML."
		s.render(w, r, "sso.html", data)
		return
	}
	all, err := s.SAML.Providers()
	if err != nil {
		data["Unavailable"] = "The identity providers could not be read: " + err.Error()
		s.render(w, r, "sso.html", data)
		return
	}
	now := time.Now()
	var rows []samlRow
	for _, c := range all {
		row := samlRow{Config: c, SP: c.ServiceEntityID(), ACS: c.ACS(), Metadata: c.MetadataURL()}
		certs, err := c.Certificates()
		if err != nil {
			row.Problem = err.Error()
		}
		for _, cert := range certs {
			row.CertRows = append(row.CertRows, samlCertRow{Subject: cert.Subject.CommonName,
				Fingerprint: saml.Fingerprint(cert), Expires: cert.NotAfter.UTC().Format("2 Jan 2006"),
				Soon: cert.NotAfter.Before(now.Add(30 * 24 * time.Hour))})
		}
		if err := c.Validate(); err != nil && row.Problem == "" {
			row.Problem = err.Error()
		}
		rows = append(rows, row)
	}
	data["Providers"] = rows
	s.render(w, r, "sso.html", data)
}

type presetRow struct{ Key, Label, Where string }

// samlPresetRows are the presets in the order people use them, so the
// form starts on the likeliest one rather than on whichever sorts first.
func samlPresetRows() []presetRow {
	var out []presetRow
	for _, k := range saml.PresetOrder {
		v := saml.Presets[k]
		out = append(out, presetRow{Key: k, Label: v.Label, Where: v.Where})
	}
	return out
}

func (s *Server) handleSSOAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if s.SAML == nil || s.SAML.Save == nil {
		http.Error(w, "this build has no SAML", http.StatusServiceUnavailable)
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/sso?"+url.Values{key: {msg}}.Encode(), http.StatusSeeOther)
	}
	switch r.FormValue("do") {
	case "remove":
		name := r.FormValue("name")
		if err := s.SAML.Remove(name, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		back("m", name+" is removed. Nobody can sign in through it.")
	case "add":
		c, meta, err := s.samlFromForm(r)
		if err != nil {
			back("e", err.Error())
			return
		}
		// The fingerprint is the decision. Shown first, saved only once a
		// person has typed back the one they checked at the provider.
		want := strings.ToUpper(strings.TrimSpace(r.FormValue("fingerprint")))
		match := false
		var fps []string
		for _, cert := range meta.Certs {
			fp := saml.Fingerprint(cert)
			fps = append(fps, fp)
			match = match || (want != "" && strings.ReplaceAll(fp, ":", "") == strings.ReplaceAll(want, ":", ""))
		}
		if !match {
			s.renderSSO(w, r, p, map[string]any{"Name": c.Name, "Entity": meta.EntityID, "SSO": meta.SSOURL,
				"Fingerprints": fps, "WantsSigned": meta.WantsSignedRequests, "Form": r.PostForm})
			return
		}
		c.Added, c.AddedBy = time.Now().Unix(), p.Name
		if err := s.SAML.Save(c); err != nil {
			back("e", err.Error())
			return
		}
		back("m", label(&c)+" is set up. Give it the values below, then try signing in.")
	default:
		http.NotFound(w, r)
	}
}

// samlFromForm builds a configuration from the add form: metadata pasted or
// fetched, every certificate in it trusted once its fingerprint is confirmed.
func (s *Server) samlFromForm(r *http.Request) (saml.Config, *saml.IdPMetadata, error) {
	c := saml.Config{Name: strings.TrimSpace(r.FormValue("name")), URL: strings.TrimSpace(r.FormValue("url")),
		Preset: r.FormValue("preset"), Principal: strings.TrimSpace(r.FormValue("principal")),
		Required: r.FormValue("required") == "on", RequireMFA: r.FormValue("mfa") == "on"}
	if pr, ok := saml.Presets[c.Preset]; ok {
		c.Label, c.MFAContexts, c.MFAAttribute, c.MFAValues, c.NameIDFormat =
			pr.Label, pr.MFAContexts, pr.MFAAttribute, pr.MFAValues, pr.NameIDFormat
	}
	if l := strings.TrimSpace(r.FormValue("label")); l != "" {
		c.Label = l
	}
	for _, d := range strings.FieldsFunc(strings.ToLower(r.FormValue("domains")), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r'
	}) {
		c.Domains = append(c.Domains, d)
	}
	for _, b := range strings.Fields(r.FormValue("break_glass")) {
		c.BreakGlass = append(c.BreakGlass, strings.ToLower(b))
	}
	raw := []byte(r.FormValue("metadata"))
	if addr := strings.TrimSpace(r.FormValue("metadata_url")); addr != "" {
		if s.SAML.Fetch == nil {
			return c, nil, errors.New("this build cannot fetch metadata; paste it instead")
		}
		b, err := s.SAML.Fetch(addr)
		if err != nil {
			return c, nil, fmt.Errorf("the metadata could not be read from %s: %v", addr, err)
		}
		raw = b
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return c, nil, errors.New("paste the identity provider's metadata, or give its address")
	}
	meta, err := saml.ParseMetadata(raw)
	if err != nil {
		return c, nil, err
	}
	c.EntityID, c.SSOURL = meta.EntityID, meta.SSOURL
	for _, cert := range meta.Certs {
		c.Certs = append(c.Certs, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	if err := c.Validate(); err != nil {
		return c, nil, err
	}
	if existing, _ := s.samlProvider(c.Name); existing != nil && r.FormValue("replace") != "on" {
		return c, nil, fmt.Errorf("%s is already set up; tick “replace” to change it", c.Name)
	}
	return c, meta, nil
}
