// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/xmldsig"
)

// Responses shaped as Okta, Entra ID, Keycloak and Google shape theirs,
// signed by the JDK, sign in the person they name.
func TestRealShapesSignIn(t *testing.T) {
	want := map[string]string{
		"okta": "hana.sato@northwind.example", "entra": "sam.rivera@northwind.example",
		"keycloak": "dana.reyes@northwind.example", "google": "nia.adeyemi@northwind.example",
	}
	n := 0
	for _, f := range fixtures(t) {
		if f.Key != "rsa" && f.Key != "ec" {
			continue
		}
		p := fixtureProvider(t, f.IdP)
		a, err := p.ParseResponse(b64(fixtureXML(t, f.Name)), fixtureRequest, fixtureNow)
		if err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		n++
		if a.NameID != want[f.IdP] || a.Issuer != issuers[f.IdP] {
			t.Errorf("%s: %q from %q", f.Name, a.NameID, a.Issuer)
		}
		signedR := strings.Contains(strings.Join(f.Signed, " "), "response")
		signedA := strings.Contains(strings.Join(f.Signed, " "), "assertion")
		if a.ResponseSigned != signedR || a.AssertionSigned != signedA {
			t.Errorf("%s: signed response %v assertion %v", f.Name, a.ResponseSigned, a.AssertionSigned)
		}
		if a.Until.IsZero() || a.AuthnInstant.IsZero() {
			t.Errorf("%s: times not read", f.Name)
		}
	}
	if n != 9 {
		t.Fatalf("%d fixtures signed in", n)
	}

	// What each one carries, read from the signed bytes.
	a, _ := fixtureProvider(t, "okta").ParseResponse(b64(fixtureXML(t, "okta-both")), fixtureRequest, fixtureNow)
	if g := a.Attributes["groups"]; len(g) != 2 || g[0] != "Security & Risk" {
		t.Errorf("okta groups %q", g)
	}
	if a.Attribute("email") != "hana.sato@northwind.example" || a.SessionNotOnOrAfter.IsZero() {
		t.Errorf("okta email %q", a.Attribute("email"))
	}
	e, _ := fixtureProvider(t, "entra").ParseResponse(b64(fixtureXML(t, "entra-assertion")), fixtureRequest, fixtureNow)
	if m := e.Attributes["http://schemas.microsoft.com/claims/authnmethodsreferences"]; len(m) != 2 ||
		m[1] != "http://schemas.microsoft.com/claims/multipleauthn" {
		t.Errorf("entra methods %q", m)
	}
	k, _ := fixtureProvider(t, "keycloak").ParseResponse(b64(fixtureXML(t, "keycloak-response")), fixtureRequest, fixtureNow)
	if k.Attribute("Role") != "analyst" {
		t.Errorf("keycloak role %q", k.Attribute("Role"))
	}
}

func TestTheWrongSignerIsRefused(t *testing.T) {
	for _, name := range []string{"okta-other-key", "okta-weak"} {
		p := fixtureProvider(t, "okta")
		if _, err := p.ParseResponse(b64(fixtureXML(t, name)), fixtureRequest, fixtureNow); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// And the control: the other key, when it is the trusted one, is fine.
	p := fixtureProvider(t, "okta")
	p.Keys = append(p.Keys, certKey(t, "rsa-other"))
	if _, err := p.ParseResponse(b64(fixtureXML(t, "okta-other-key")), fixtureRequest, fixtureNow); err != nil {
		t.Errorf("a key added for a rollover is not used: %v", err)
	}
}

// Every rule, one at a time. Each case changes one thing from a response
// that signs in, and both the assertion-signed and the response-signed
// forms must be refused. The first case is the control.
func TestEachRuleRefusesOnItsOwn(t *testing.T) {
	cases := []struct {
		why  string
		edit func(*shape)
		now  time.Duration
		req  string
		want error // nil for the control; ErrRefused, ErrUnsolicited or a *StatusError
	}{
		{why: "the control", edit: func(*shape) {}},
		{why: "destination elsewhere", edit: func(s *shape) { s.Destination = "https://evil.example/acs" }, want: ErrRefused},
		{why: "response issuer another", edit: func(s *shape) { s.Issuer = "https://evil.example" }, want: ErrRefused},
		{why: "assertion issuer another", edit: func(s *shape) { s.AssertionIssuer = "https://evil.example" }, want: ErrRefused},
		{why: "audience another service", edit: func(s *shape) { s.Audience = "https://other.example/saml" }, want: ErrRefused},
		{why: "recipient another service", edit: func(s *shape) { s.Recipient = "https://other.example/acs" }, want: ErrRefused},
		{why: "answers another request", edit: func(s *shape) { s.ConfirmationRequest = "_other" }, want: ErrRefused},
		{why: "response answers another request", edit: func(s *shape) { s.InResponseTo = "_other" }, want: ErrRefused},
		{why: "nothing was asked", edit: func(*shape) {}, req: "none", want: ErrUnsolicited},
		{why: "unsolicited (no InResponseTo)", edit: func(s *shape) { s.InResponseTo = ""; s.ConfirmationRequest = "" }, want: ErrUnsolicited},
		{why: "expired conditions", edit: func(*shape) {}, now: 7 * time.Minute, want: ErrRefused},
		{why: "not yet valid", edit: func(s *shape) { s.NotBefore = ts(10 * time.Minute) }, want: ErrRefused},
		{why: "confirmation expired", edit: func(s *shape) { s.ConfirmUntil = ts(-2 * time.Minute) }, want: ErrRefused},
		{why: "not a bearer", edit: func(s *shape) { s.Method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" }, want: ErrRefused},
		{why: "no confirmation", edit: func(s *shape) { s.NoConfirmation = true }, want: ErrRefused},
		{why: "no conditions", edit: func(s *shape) { s.NoConditions = true }, want: ErrRefused},
		{why: "no authentication statement", edit: func(s *shape) { s.NoAuthn = true }, want: ErrRefused},
		{why: "the provider's session ended", edit: func(s *shape) { s.SessionUntil = ts(-time.Second) }, want: ErrRefused},
		{why: "signed in in the future", edit: func(s *shape) { s.AuthnInstant = ts(10 * time.Minute) }, want: ErrRefused},
		{why: "an unknown condition", edit: func(s *shape) { s.ExtraCondition = `<saml:Condition xmlns:x="urn:x"/>` }, want: ErrRefused},
		{why: "a second audience restriction for another service", edit: func(s *shape) {
			s.ExtraCondition = `<saml:AudienceRestriction><saml:Audience>https://other.example</saml:Audience></saml:AudienceRestriction>`
		}, want: ErrRefused},
		{why: "an Advice (assertions inside an assertion)", edit: func(s *shape) { s.ExtraAssertionChild = `<saml:Advice/>` }, want: ErrRefused},
		{why: "a name with a control character", edit: func(s *shape) { s.NameID = "dana&#xA;admin" }, want: ErrRefused},
		{why: "SAML 1.1", edit: func(s *shape) { s.Version = "1.1" }, want: ErrRefused},
		{why: "the provider said no", edit: func(s *shape) { s.Status = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, want: &StatusError{}},
		{why: "an encrypted assertion beside", edit: func(s *shape) { s.ExtraResponseChild = `<saml:EncryptedAssertion/>` }, want: ErrRefused},
		{why: "an assertion in Extensions", edit: func(s *shape) {
			s.ExtraResponseChild = `<samlp:Extensions><saml:Assertion ID="_x" Version="2.0"/></samlp:Extensions>`
		}, want: ErrRefused},
	}
	for _, c := range cases {
		s := good()
		c.edit(&s)
		req := tReq
		if c.req == "none" {
			req = ""
		}
		for form, doc := range map[string]string{"assertion signed": s.signedAssertion(t), "response signed": s.signedResponse(t)} {
			_, err := testProvider(t).ParseResponse(b64(doc), req, tNow.Add(c.now))
			var se *StatusError
			switch {
			case c.want == nil && err != nil:
				t.Errorf("%s (%s): refused: %v", c.why, form, err)
			case c.want == nil:
			case errors.As(c.want, &se):
				if !errors.As(err, &se) {
					t.Errorf("%s (%s): %v", c.why, form, err)
				}
			case !errors.Is(err, c.want):
				t.Errorf("%s (%s): got %v", c.why, form, err)
			}
		}
	}
}

// A signed response must say where it was sent; an assertion-signed one
// whose response says nothing about it is still fine, as Entra sends it.
func TestDestinationIsRequiredOnlyWhenTheResponseIsSigned(t *testing.T) {
	s := good()
	s.OmitDestination = true
	if _, err := testProvider(t).ParseResponse(b64(s.signedResponse(t)), tReq, tNow); !errors.Is(err, ErrRefused) {
		t.Errorf("signed response without a destination: %v", err)
	}
	if _, err := testProvider(t).ParseResponse(b64(s.signedAssertion(t)), tReq, tNow); err != nil {
		t.Errorf("assertion-signed response without a destination: %v", err)
	}
}

func TestUnsignedIsRefused(t *testing.T) {
	if _, err := testProvider(t).ParseResponse(b64(good().xml()), tReq, tNow); !errors.Is(err, ErrRefused) {
		t.Errorf("an unsigned response: %v", err)
	}
}

// A response signed, then given a second signature that is wrong, is
// refused even though the first is good.
func TestABadSignatureBesideAGoodOneIsRefused(t *testing.T) {
	// The assertion signed by a key nobody trusts, then the whole response
	// signed by the trusted one, so the response signature is good over a
	// document that carries a bad one.
	inner := sign(t, good().xml(), "_assert1", otherKey(t))
	mixed := sign(t, inner, "_resp1", key(t))
	if _, err := testProvider(t).ParseResponse(b64(mixed), tReq, tNow); !errors.Is(err, ErrRefused) {
		t.Errorf("a wrong assertion signature inside a good response signature: %v", err)
	}
}

func TestReplayIsRefused(t *testing.T) {
	var seen Seen
	a, err := testProvider(t).ParseResponse(b64(good().signedAssertion(t)), tReq, tNow)
	if err != nil {
		t.Fatal(err)
	}
	if !seen.Use(a.ID, a.Until, tNow) {
		t.Fatal("the first use was refused")
	}
	if seen.Use(a.ID, a.Until, tNow.Add(time.Minute)) {
		t.Error("the same assertion was used twice")
	}
	if !seen.Use("_another", a.Until, tNow) {
		t.Error("another assertion was refused")
	}
}

func TestOversizedOrNotBase64IsRefused(t *testing.T) {
	p := testProvider(t)
	if _, err := p.ParseResponse("@@@", tReq, tNow); !errors.Is(err, ErrRefused) {
		t.Errorf("not base64: %v", err)
	}
	if _, err := p.ParseResponse(strings.Repeat("A", 1<<20), tReq, tNow); !errors.Is(err, ErrRefused) {
		t.Errorf("a megabyte: %v", err)
	}
}

// Signatures that verify cryptographically and are still refused, because
// what they sign or how is outside the allow-list. Signed properly here, so
// the refusal is the allow-list's and not a broken signature's.
func TestProperlySignedButDisallowedSignatures(t *testing.T) {
	// A signature in the response whose reference names the assertion: it
	// signs one element and sits in another.
	doc := sign(t, good().xml(), "_assert1", key(t))
	sig := doc[strings.Index(doc, "<ds:Signature") : strings.Index(doc, "</ds:Signature>")+len("</ds:Signature>")]
	moved := strings.Replace(doc, sig, "", 1)
	moved = strings.Replace(moved, "</saml:Issuer>", "</saml:Issuer>"+sig, 1)
	if _, err := testProvider(t).ParseResponse(b64(moved), tReq, tNow); err == nil ||
		!strings.Contains(err.Error(), "refers to") {
		t.Errorf("a signature naming another element: %v", err)
	}

	// An XPath transform where enveloped-signature belongs, with a digest
	// that matches what enveloped-signature would give.
	xp := signWith(t, good().xml(), "_assert1", key(t), "http://www.w3.org/TR/1999/REC-xpath-19991116")
	if _, err := testProvider(t).ParseResponse(b64(xp), tReq, tNow); err == nil ||
		!strings.Contains(err.Error(), "enveloped-signature") {
		t.Errorf("an XPath transform: %v", err)
	}
}

// Two signatures on one element, the first good: refused, because which of
// several signatures counts is a question with more than one answer.
func TestTwoSignaturesOnTheAssertionAreRefused(t *testing.T) {
	once := sign(t, good().xml(), "_assert1", otherKey(t))
	twice := sign(t, once, "_assert1", key(t)) // first after the Issuer, and valid
	if _, err := testProvider(t).ParseResponse(b64(twice), tReq, tNow); err == nil ||
		!strings.Contains(err.Error(), "signatures") {
		t.Errorf("two signatures: %v", err)
	}
}

// The assertion's own confirmation refuses to stand in for a request when
// none was made, whatever the response around it says.
func TestTheConfirmationAloneRefusesAnUnsolicitedAssertion(t *testing.T) {
	s := good()
	s.ConfirmationRequest = ""
	d := mustRead(t, s.xml())
	var sc *xmldsig.Element
	var find func(e *xmldsig.Element)
	find = func(e *xmldsig.Element) {
		if e.Is(NSAssertion, "SubjectConfirmation") {
			sc = e
		}
		for _, k := range mustElements(e) {
			find(k)
		}
	}
	find(d.Root)
	for _, req := range []string{"", tReq} {
		if _, err := testProvider(t).bearer(sc, req, tNow); err == nil {
			t.Errorf("request %q: a confirmation answering nothing was accepted", req)
		}
	}
}

func mustRead(t testing.TB, s string) *xmldsig.Document {
	t.Helper()
	d, err := xmldsig.Read([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}
