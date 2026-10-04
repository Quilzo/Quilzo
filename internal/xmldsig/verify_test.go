// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package xmldsig

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
)

type fixture struct {
	Name        string   `json:"name"`
	IdP         string   `json:"idp"`
	Key         string   `json:"key"`
	Signature   string   `json:"signature"`
	Signed      []string `json:"signed"`
	ResponseID  string   `json:"response_id"`
	AssertionID string   `json:"assertion_id"`
}

func fixtures(t testing.TB) []fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "saml", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []fixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureBytes(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "saml", name+".xml"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func certKey(t testing.TB, name string) crypto.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "keys", name+".crt"))
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

func signedElement(t testing.TB, d *Document, f fixture, which string) *Element {
	t.Helper()
	id := f.AssertionID
	if which == "response" {
		id = f.ResponseID
	}
	e := d.ByID(id)
	if e == nil {
		t.Fatalf("%s: no element %s", f.Name, id)
	}
	return e
}

// Every fixture the JDK signed verifies here with the key that signed it,
// and the element handed back is the one that was signed, read again.
func TestSignaturesFromTheJDKVerify(t *testing.T) {
	rsa, ec := certKey(t, "rsa"), certKey(t, "ec")
	n := 0
	for _, f := range fixtures(t) {
		if f.Key != "rsa" && f.Key != "ec" {
			continue
		}
		d, err := Read(fixtureBytes(t, f.Name))
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		for _, which := range f.Signed {
			e := signedElement(t, d, f, which)
			v, err := VerifyEnveloped(e, []crypto.PublicKey{rsa, ec})
			if err != nil {
				t.Errorf("%s (%s): %v", f.Name, which, err)
				continue
			}
			n++
			if v.SignatureAlgorithm != f.Signature {
				t.Errorf("%s: algorithm %s", f.Name, v.SignatureAlgorithm)
			}
			if v.Element.Parent != nil || !v.Element.Is(e.Space, e.Local) {
				t.Errorf("%s: the element handed back is not the signed one, alone", f.Name)
			}
			// The signature itself is not in what is handed back.
			kids, _ := v.Element.Elements()
			for _, k := range kids {
				if k.Is(NSDSig, "Signature") {
					t.Errorf("%s: the enveloped signature survived", f.Name)
				}
			}
		}
	}
	if n < 11 {
		t.Fatalf("only %d signatures checked", n)
	}
}

func TestTheWrongKeyAndAWeakKeyAreRefused(t *testing.T) {
	for _, f := range fixtures(t) {
		d, err := Read(fixtureBytes(t, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		e := signedElement(t, d, f, f.Signed[0])
		switch f.Key {
		case "rsa-other":
			if _, err := VerifyEnveloped(e, []crypto.PublicKey{certKey(t, "rsa")}); !errors.Is(err, ErrRefused) {
				t.Errorf("signed by another key, and it verified: %v", err)
			}
			if _, err := VerifyEnveloped(e, []crypto.PublicKey{certKey(t, "rsa-other")}); err != nil {
				t.Errorf("the control: the right key should verify: %v", err)
			}
		case "rsa1024":
			if _, err := VerifyEnveloped(e, []crypto.PublicKey{certKey(t, "rsa1024")}); !errors.Is(err, ErrRefused) {
				t.Errorf("a 1024-bit RSA signature verified: %v", err)
			}
		case "ec":
			// An RSA key never checks an ECDSA signature, and the reverse.
			if _, err := VerifyEnveloped(e, []crypto.PublicKey{certKey(t, "rsa")}); err == nil {
				t.Error("an ECDSA signature verified with an RSA key")
			}
		}
	}
}

// One byte changed anywhere in what was signed, and it no longer verifies.
func TestAChangedValueIsRefused(t *testing.T) {
	key := certKey(t, "rsa")
	src := string(fixtureBytes(t, "entra-assertion"))
	for _, edit := range [][2]string{
		{"sam.rivera@northwind.example</NameID>", "hana.sato@northwind.example</NameID>"},
		{`NotOnOrAfter="2026-10-03T12:05:00.123Z" Recipient`, `NotOnOrAfter="2027-10-03T12:05:00.123Z" Recipient`},
		{"<Audience>https://quilzo.example/saml/entra</Audience>", "<Audience>https://evil.example</Audience>"},
	} {
		changed := strings.Replace(src, edit[0], edit[1], 1)
		if changed == src {
			t.Fatalf("the edit %q did not apply", edit[0])
		}
		d, err := Read([]byte(changed))
		if err != nil {
			t.Fatal(err)
		}
		f := fixtures(t)[2]
		if _, err := VerifyEnveloped(signedElement(t, d, f, "assertion"), []crypto.PublicKey{key}); !errors.Is(err, ErrRefused) {
			t.Errorf("%q: %v", edit[1], err)
		}
	}
}

func TestAnUnsignedElementSaysSo(t *testing.T) {
	d, err := Read(fixtureBytes(t, "entra-assertion"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnveloped(d.Root, []crypto.PublicKey{certKey(t, "rsa")}); !errors.Is(err, ErrUnsigned) {
		t.Errorf("the response is unsigned in this fixture: %v", err)
	}
}

// The signature's own parts are an allow-list. Each of these is a document
// the JDK signed and then had one part of its signature changed to something
// the standard allows and this package does not.
func TestSignatureOptionsOutsideTheAllowListAreRefused(t *testing.T) {
	key := certKey(t, "rsa")
	src := string(fixtureBytes(t, "entra-assertion"))
	for _, c := range []struct{ old, new, why string }{
		{`#rsa-sha256"`, `#rsa-sha1"`, "SHA-1"},
		{`xmlenc#sha256"`, `xmldsig#sha1"`, "a SHA-1 digest"},
		{`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`,
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>`, "comments kept"},
		{`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`,
			`<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>`, "an XPath transform"},
		{`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`, ``, "no enveloped transform"},
		{`</ds:SignedInfo>`, `<ds:Reference URI="#x"/></ds:SignedInfo>`, "a second reference"},
		{`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`,
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"><ds:HMACOutputLength>8</ds:HMACOutputLength></ds:SignatureMethod>`, "HMAC truncation"},
		{`</ds:Signature>`, `<ds:Object/></ds:Signature>`, "an Object"},
		{`<ds:Reference URI="#`, `<ds:Reference URI="#other`, "a reference to another element"},
		{`<ds:Reference URI="#`, `<ds:Reference Type="x" Foo="y" URI="#`, "an unexpected reference attribute"},
	} {
		changed := strings.Replace(src, c.old, c.new, 1)
		if changed == src {
			t.Fatalf("%s: the edit did not apply", c.why)
		}
		d, err := Read([]byte(changed))
		if err != nil {
			continue // refused by the reader: also a refusal
		}
		f := fixtures(t)[2]
		if _, err := VerifyEnveloped(signedElement(t, d, f, "assertion"), []crypto.PublicKey{key}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s was not refused: %v", c.why, err)
		}
	}
}

func TestDefaultInPrefixListIsRefused(t *testing.T) {
	src := strings.Replace(string(fixtureBytes(t, "okta-assertion")), `PrefixList="xs"`, `PrefixList="#default xs"`, 1)
	d, err := Read([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	f := fixtures(t)[1]
	if _, err := VerifyEnveloped(signedElement(t, d, f, "assertion"), []crypto.PublicKey{certKey(t, "rsa")}); err == nil ||
		!strings.Contains(err.Error(), "disagree") {
		t.Errorf("#default in the PrefixList: %v", err)
	}
}

// Two signatures on one element are refused, even when both are valid.
func TestTwoSignaturesOnOneElementAreRefused(t *testing.T) {
	src := string(fixtureBytes(t, "entra-assertion"))
	start := strings.Index(src, "<ds:Signature")
	end := strings.Index(src, "</ds:Signature>") + len("</ds:Signature>")
	sig := src[start:end]
	twice := src[:end] + strings.Replace(sig, `xmlns:ds=`, `xmlns:ds=`, 1) + src[end:]
	if _, err := Read([]byte(twice)); err == nil {
		d, _ := Read([]byte(twice))
		f := fixtures(t)[2]
		if _, err := VerifyEnveloped(signedElement(t, d, f, "assertion"), []crypto.PublicKey{certKey(t, "rsa")}); !errors.Is(err, ErrRefused) {
			t.Errorf("two signatures: %v", err)
		}
	}
}
