// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"errors"
	"strings"
	"testing"
)

// The attack corpus. Each document is built from a response the JDK signed,
// keeping that real signature, which is what a wrapping attack does: it
// cannot make a new signature, so it moves the signed part and puts its own
// where the reader looks. The XSW numbering is Somorovsky et al., "On
// Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012); the
// later entries are the 2018–2026 bypasses named beside them.

func cut(s, from, to string) (before, part, after string) {
	i := strings.Index(s, from)
	j := strings.LastIndex(s, to)
	if i < 0 || j < i {
		panic("cut: " + from)
	}
	j += len(to)
	return s[:i], s[i:j], s[j:]
}

func between(s, from, to string) string {
	i := strings.Index(s, from)
	j := strings.Index(s[i:], to)
	return s[i : i+j+len(to)]
}

// evil is a copy of the signed assertion, unsigned, naming somebody else.
func evil(assertion, oldID, newID string) string {
	e := strings.Replace(assertion, `ID="`+oldID+`"`, `ID="`+newID+`"`, 1)
	if sig := between(e, "<ds:Signature", "</ds:Signature>"); sig != "" {
		e = strings.Replace(e, sig, "", 1)
	}
	return strings.Replace(e, "hana.sato@northwind.example</saml2:NameID>", "admin@northwind.example</saml2:NameID>", 1)
}

func TestTheAttackCorpusIsRefused(t *testing.T) {
	okta := fixtureXML(t, "okta-assertion") // the assertion is signed
	const aid = "_a01c0ffeeoktaassertion"
	pre, assertion, post := cut(okta, "<saml2:Assertion", "</saml2:Assertion>")
	signature := between(assertion, "<ds:Signature", "</ds:Signature>")
	unsignedOriginal := strings.Replace(assertion, signature, "", 1)
	bad := evil(assertion, aid, "_evil")
	badSameID := evil(assertion, aid, aid)
	issuerEnd := strings.Index(bad, "</saml2:Issuer>") + len("</saml2:Issuer>")
	withSig := func(inside string) string {
		s := strings.Replace(signature, "</ds:Signature>", inside+"</ds:Signature>", 1)
		return bad[:issuerEnd] + s + bad[issuerEnd:]
	}

	kc := fixtureXML(t, "keycloak-response") // the response is signed
	const rid = "_r04c0ffeekeycloakresponse"
	kcSig := between(kc, "<ds:Signature", "</ds:Signature>")
	kcBody := kc[strings.Index(kc, "<samlp:Response"):]
	kcEvil := strings.Replace(strings.Replace(kcBody, kcSig, "", 1), `ID="`+rid+`"`, `ID="_evilresponse"`, 1)
	kcEvil = strings.Replace(kcEvil, "dana.reyes@northwind.example", "admin@northwind.example", 1)
	kcIssuerEnd := strings.Index(kcEvil, "</saml:Issuer>") + len("</saml:Issuer>")

	cases := []struct{ name, doc, idp string }{
		// Signed assertion, wrapped.
		{"XSW3: an evil assertion before the signed one", pre + bad + assertion + post, "okta"},
		{"XSW3 with the same ID (a duplicate identifier)", pre + badSameID + assertion + post, "okta"},
		{"XSW4: the signed assertion inside the evil one", pre + strings.Replace(bad, "</saml2:Assertion>", assertion+"</saml2:Assertion>", 1) + post, "okta"},
		{"XSW5: evil assertion carrying the signature, original after", pre + withSig("") + post[:len(post)-len("</saml2p:Response>")] + unsignedOriginal + "</saml2p:Response>", "okta"},
		{"XSW6: the original inside the evil assertion's signature", pre + withSig(unsignedOriginal) + post, "okta"},
		{"XSW7: the signed assertion in Extensions", strings.Replace(pre, "<saml2p:Status>", "<saml2p:Extensions>"+assertion+"</saml2p:Extensions><saml2p:Status>", 1) + bad + post, "okta"},
		{"XSW8: the original in an Object of a copied signature", pre + withSig("<ds:Object>"+unsignedOriginal+"</ds:Object>") + post, "okta"},
		{"signature stripped and the name changed", pre + bad + post, "okta"},
		{"the signed assertion moved under a new parent", pre + "<saml2p:Wrapper>" + assertion + "</saml2p:Wrapper>" + bad + post, "okta"},
		{"an extra unsigned assertion after the signed one", pre + assertion + bad + post, "okta"},
		{"comment truncation in the name (CVE-2017-11427)", strings.Replace(okta, "hana.sato@northwind.example</saml2:NameID>", "hana.sato@northwind.example<!---->.evil</saml2:NameID>", 1), "okta"},
		{"attribute pollution: a second ID (Fragile Lock)", strings.Replace(okta, `ID="`+aid+`"`, `ID="`+aid+`" saml2:ID="_evil"`, 1), "okta"},
		{"namespace confusion: xml rebound (Fragile Lock)", strings.Replace(okta, `<saml2:Subject>`, `<saml2:Subject xmlns:xml="http://www.w3.org/2000/09/xmldsig#">`, 1), "okta"},
		{"void canonicalisation: a relative namespace (Fragile Lock)", strings.Replace(okta, `<saml2:Subject>`, `<saml2:Subject xmlns:ns="1">`, 1), "okta"},
		{"a DOCTYPE with an entity (ruby-saml CVE-2025-25291)", strings.Replace(okta, `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`, `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "admin">]>`, 1), "okta"},
		{"a processing instruction (node-saml CVE-2025-54419)", strings.Replace(okta, `<saml2:Subject>`, `<saml2:Subject><?x y?>`, 1), "okta"},
		{"the assertion encrypted beside", strings.Replace(okta, "</saml2p:Response>", `<saml2:EncryptedAssertion xmlns:saml2="`+NSAssertion+`"/></saml2p:Response>`, 1), "okta"},

		// Signed response, wrapped.
		{"XSW1: evil response holding the signature over the original", kcEvil[:kcIssuerEnd] + strings.Replace(kcSig, "</ds:Signature>", "<ds:Object>"+strings.Replace(kcBody, kcSig, "", 1)+"</ds:Object></ds:Signature>", 1) + kcEvil[kcIssuerEnd:], "keycloak"},
		{"XSW2: the original response inside the evil one", kcEvil[:kcIssuerEnd] + kcSig + kcBody + kcEvil[kcIssuerEnd:], "keycloak"},
		{"the signed response's assertion edited", strings.Replace(kc, "dana.reyes@northwind.example", "admin@northwind.example", 1), "keycloak"},
		{"a second assertion added to a signed response", strings.Replace(kc, "</samlp:Response>", strings.Replace(between(kcEvil, "<saml:Assertion", "</saml:Assertion>"), `ID="_a04`, `ID="_b04`, 1)+"</samlp:Response>", 1), "keycloak"},
		{"the signed response in Extensions of an unsigned one", kcEvil[:kcIssuerEnd] + "<samlp:Extensions>" + kcBody + "</samlp:Extensions>" + kcEvil[kcIssuerEnd:], "keycloak"},
	}
	for _, c := range cases {
		_, err := fixtureProvider(t, c.idp).ParseResponse(b64(c.doc), fixtureRequest, fixtureNow)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: not refused (%v)", c.name, err)
		}
	}
	if len(cases) < 20 {
		t.Fatal("the corpus shrank")
	}

	// The controls: the untouched fixtures sign in, so the refusals above are
	// about the attacks and not about the fixtures.
	for _, c := range []struct{ name, idp string }{{"okta-assertion", "okta"}, {"keycloak-response", "keycloak"}} {
		if _, err := fixtureProvider(t, c.idp).ParseResponse(b64(fixtureXML(t, c.name)), fixtureRequest, fixtureNow); err != nil {
			t.Errorf("control %s: %v", c.name, err)
		}
	}
}
