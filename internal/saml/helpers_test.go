// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/xmldsig"
)

// The JDK-signed fixtures live with the package that verifies signatures.
var fixtureDir = filepath.Join("..", "xmldsig", "testdata")

const fixtureRequest = "_4f2a9c1e7b3d5a6f8e0c2b4d6a8f0e1c"

var fixtureNow = time.Date(2026, 10, 3, 12, 0, 0, 123e6, time.UTC)

var issuers = map[string]string{
	"okta":     "http://www.okta.com/exk8northwind",
	"entra":    "https://sts.windows.net/9b1c0d2e-0000-4000-8000-000000000001/",
	"keycloak": "https://id.northwind.example/realms/staff",
	"google":   "https://accounts.google.com/o/saml2?idpid=C01northwind",
}

type fixture struct {
	Name   string   `json:"name"`
	IdP    string   `json:"idp"`
	Key    string   `json:"key"`
	Signed []string `json:"signed"`
}

func fixtures(t testing.TB) []fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "saml", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []fixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureXML(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, "saml", name+".xml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func certKey(t testing.TB, name string) crypto.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "keys", name+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.PublicKey
}

// fixtureProvider is the configuration that accepts a fixture's shape.
func fixtureProvider(t testing.TB, idp string) *Provider {
	return &Provider{
		EntityID:        issuers[idp],
		SSOURL:          "https://idp.example/sso",
		Keys:            []crypto.PublicKey{certKey(t, "rsa"), certKey(t, "ec")},
		ServiceEntityID: "https://quilzo.example/saml/" + idp,
		ACS:             "https://quilzo.example/saml/" + idp + "/acs",
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// -- a signer for tests ------------------------------------------------------
//
// The fixtures prove that real signatures verify. These tests are about what
// is done with a verified assertion, and need many variants with times and
// audiences of their choosing; they are signed here with a key made for the
// test run, using this repository's own canonicalisation.

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func key(t testing.TB) *rsa.PrivateKey {
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

var endIssuer = regexp.MustCompile(`</([A-Za-z0-9]+:)?Issuer>`)

const sigTemplate = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
	`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
	`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
	`<ds:Reference URI="#%s"><ds:Transforms>` +
	`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
	`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>` +
	`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
	`<ds:DigestValue>DIGESTVALUE</ds:DigestValue></ds:Reference></ds:SignedInfo>` +
	`<ds:SignatureValue>SIGNATUREVALUE</ds:SignatureValue></ds:Signature>`

// sign puts an enveloped signature into the element with this ID, after its
// Issuer, made with k.
func sign(t testing.TB, doc, id string, k *rsa.PrivateKey) string {
	t.Helper()
	return signWith(t, doc, id, k, "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
}

// signWith names firstTransform as the first transform, while computing the
// digest the way enveloped-signature does.
func signWith(t testing.TB, doc, id string, k *rsa.PrivateKey, firstTransform string) string {
	t.Helper()
	at := strings.Index(doc, `ID="`+id+`"`)
	if at < 0 {
		t.Fatalf("no element %s", id)
	}
	loc := endIssuer.FindStringIndex(doc[at:])
	if loc == nil {
		t.Fatalf("element %s has no Issuer", id)
	}
	cut := at + loc[1]
	tmpl := strings.Replace(sigTemplate, "http://www.w3.org/2000/09/xmldsig#enveloped-signature", firstTransform, 1)
	doc = doc[:cut] + fmt.Sprintf(tmpl, id) + doc[cut:]

	d, err := xmldsig.Read([]byte(doc))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	el := d.ByID(id)
	var sig, si *xmldsig.Element
	kids, _ := el.Elements()
	for _, c := range kids {
		if c.Is(xmldsig.NSDSig, "Signature") && sig == nil {
			sig = c // the one just put after the Issuer
		}
	}
	content, err := xmldsig.Canonical(el, nil, sig)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	doc = strings.Replace(doc, "DIGESTVALUE", base64.StdEncoding.EncodeToString(sum[:]), 1)

	d, err = xmldsig.Read([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	kids, _ = d.ByID(id).Elements()
	for _, c := range kids {
		if c.Is(xmldsig.NSDSig, "Signature") && si == nil {
			parts, _ := c.Elements()
			si = parts[0]
		}
	}
	canon, err := xmldsig.Canonical(si, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(doc, "SIGNATUREVALUE", base64.StdEncoding.EncodeToString(s), 1)
}

// -- responses made to order ------------------------------------------------

type shape struct {
	Destination, Issuer, Status, InResponseTo                 string
	AssertionIssuer, Audience, Recipient, ConfirmationRequest string
	NotBefore, NotOnOrAfter, ConfirmUntil, AuthnInstant       string
	SessionUntil, NameID, Method, ExtraCondition, Version     string
	ExtraAssertionChild, ExtraResponseChild                   string
	NoConditions, NoAuthn, NoConfirmation, OmitDestination    bool
}

const (
	tIdP = "https://idp.northwind.example"
	tSP  = "https://quilzo.example/saml/test"
	tACS = "https://quilzo.example/saml/test/acs"
	tReq = "_00112233445566778899aabbccddeeff"
)

var tNow = time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)

func ts(d time.Duration) string { return tNow.Add(d).Format(time.RFC3339Nano) }

func good() shape {
	return shape{
		Destination: tACS, Issuer: tIdP, Status: StatusSuccess, InResponseTo: tReq,
		AssertionIssuer: tIdP, Audience: tSP, Recipient: tACS, ConfirmationRequest: tReq,
		NotBefore: ts(-time.Minute), NotOnOrAfter: ts(5 * time.Minute), ConfirmUntil: ts(5 * time.Minute),
		AuthnInstant: ts(-2 * time.Second), SessionUntil: ts(8 * time.Hour),
		NameID: "dana.reyes@northwind.example", Method: MethodBearer, Version: "2.0",
	}
}

func (s shape) xml() string {
	var b strings.Builder
	b.WriteString(`<samlp:Response xmlns:samlp="` + NSProtocol + `" xmlns:saml="` + NSAssertion + `" ID="_resp1" Version="2.0" IssueInstant="` + ts(0) + `"`)
	if !s.OmitDestination {
		b.WriteString(` Destination="` + s.Destination + `"`)
	}
	if s.InResponseTo != "" {
		b.WriteString(` InResponseTo="` + s.InResponseTo + `"`)
	}
	b.WriteString(`><saml:Issuer>` + s.Issuer + `</saml:Issuer>`)
	b.WriteString(`<samlp:Status><samlp:StatusCode Value="` + s.Status + `"/></samlp:Status>`)
	b.WriteString(s.ExtraResponseChild)
	b.WriteString(`<saml:Assertion ID="_assert1" Version="` + s.Version + `" IssueInstant="` + ts(0) + `">`)
	b.WriteString(`<saml:Issuer>` + s.AssertionIssuer + `</saml:Issuer>`)
	b.WriteString(`<saml:Subject><saml:NameID Format="` + FormatEmail + `">` + s.NameID + `</saml:NameID>`)
	if !s.NoConfirmation {
		b.WriteString(`<saml:SubjectConfirmation Method="` + s.Method + `"><saml:SubjectConfirmationData`)
		if s.ConfirmationRequest != "" {
			b.WriteString(` InResponseTo="` + s.ConfirmationRequest + `"`)
		}
		b.WriteString(` NotOnOrAfter="` + s.ConfirmUntil + `" Recipient="` + s.Recipient + `"/></saml:SubjectConfirmation>`)
	}
	b.WriteString(`</saml:Subject>`)
	if !s.NoConditions {
		b.WriteString(`<saml:Conditions NotBefore="` + s.NotBefore + `" NotOnOrAfter="` + s.NotOnOrAfter + `">`)
		b.WriteString(`<saml:AudienceRestriction><saml:Audience>` + s.Audience + `</saml:Audience></saml:AudienceRestriction>`)
		b.WriteString(s.ExtraCondition + `</saml:Conditions>`)
	}
	if !s.NoAuthn {
		b.WriteString(`<saml:AuthnStatement AuthnInstant="` + s.AuthnInstant + `" SessionIndex="_s1" SessionNotOnOrAfter="` + s.SessionUntil + `">`)
		b.WriteString(`<saml:AuthnContext><saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`)
	}
	b.WriteString(`<saml:AttributeStatement><saml:Attribute Name="email" FriendlyName="mail"><saml:AttributeValue>dana.reyes@northwind.example</saml:AttributeValue></saml:Attribute>`)
	b.WriteString(`<saml:Attribute Name="groups"><saml:AttributeValue>analysts</saml:AttributeValue><saml:AttributeValue>staff</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`)
	b.WriteString(s.ExtraAssertionChild)
	b.WriteString(`</saml:Assertion></samlp:Response>`)
	return b.String()
}

func testProvider(t testing.TB) *Provider {
	return &Provider{EntityID: tIdP, SSOURL: "https://idp.northwind.example/sso",
		Keys: []crypto.PublicKey{&key(t).PublicKey}, ServiceEntityID: tSP, ACS: tACS}
}

// signedAssertion is the shape with its assertion signed, as Entra does.
func (s shape) signedAssertion(t testing.TB) string {
	return sign(t, s.xml(), "_assert1", key(t))
}

// signedResponse is the shape with only the response signed, as Keycloak
// and Google do.
func (s shape) signedResponse(t testing.TB) string {
	return sign(t, s.xml(), "_resp1", key(t))
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

var (
	otherKeyOnce sync.Once
	otherTestKey *rsa.PrivateKey
)

// otherKey is a key nobody trusts.
func otherKey(t testing.TB) *rsa.PrivateKey {
	otherKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		otherTestKey = k
	})
	return otherTestKey
}
