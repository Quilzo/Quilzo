// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/saml"
)

// keycloakDescriptor is the realm metadata a running Keycloak served, and
// the fingerprint of its key, as a person confirms it at saml add.
func keycloakDescriptor(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "saml", "testdata", "keycloak", "descriptor.xml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := saml.ParseMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	return path, saml.Fingerprint(m.Certs[0])
}

// Keycloak lets a person change their own address, and leaves it
// unverified unless the realm says otherwise. Set up from its preset, a
// sign-in it does not say is verified is refused, as OIDC refuses the same
// person; an operator who decides otherwise says so in as many words.
func TestAKeycloakProviderSignsInOnlyAddressesItVerified(t *testing.T) {
	root := connectStore(t)
	meta, fp := keycloakDescriptor(t)
	add := func(name string, more ...string) *saml.Config {
		t.Helper()
		args := append([]string{name, "--metadata", meta, "--url", "https://admin.qz.test",
			"--preset", "keycloak", "--domain", "qz.test", "--fingerprint", fp}, more...)
		if _, err := samlAdd(root, args); err != nil {
			t.Fatal(err)
		}
		c, err := findSAML(root, name)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	assertion := func(verified ...string) *saml.Assertion {
		a := &saml.Assertion{NameID: "unverified@qz.test", Attributes: map[string][]string{},
			FriendlyAttributes: map[string][]string{}}
		if len(verified) > 0 {
			a.Attributes["email_verified"] = verified
		}
		return a
	}

	kc := add("kc")
	if p, err := kc.PrincipalOf(assertion()); err == nil {
		t.Errorf("Keycloak said nothing about %s being verified, and it signed in", p)
	}
	if _, err := kc.PrincipalOf(assertion("false")); err == nil {
		t.Error("an address Keycloak says is unverified signed in")
	}
	if p, err := kc.PrincipalOf(assertion("true")); err != nil || p != "unverified@qz.test" {
		t.Errorf("a verified address: %q, %v", p, err)
	}

	// As oidc configure --allow-unverified-email: the operator decided, and
	// the address is taken as Keycloak sends it.
	open := add("kc-open", "--allow-unverified-email")
	for _, said := range [][]string{nil, {"false"}} {
		if p, err := open.PrincipalOf(assertion(said...)); err != nil || p != "unverified@qz.test" {
			t.Errorf("--allow-unverified-email, email_verified %v: %q, %v", said, p, err)
		}
	}

	// Another provider's attribute, named at saml add.
	named := add("kc-named", "--verified-attribute", "emailVerified")
	if _, err := named.PrincipalOf(assertion("true")); err == nil {
		t.Error("email_verified was read in place of the attribute named")
	}
	a := assertion()
	a.Attributes["emailVerified"] = []string{"true"}
	if p, err := named.PrincipalOf(a); err != nil || p != "unverified@qz.test" {
		t.Errorf("--verified-attribute emailVerified: %q, %v", p, err)
	}
}

// A Keycloak added before its preset asked for email_verified is stored
// without it, and signs in an address it has not verified while it says
// nothing either way. The posture scan names it, so the store the finding
// was reproduced on is told rather than left as it was.
func TestAKeycloakAddedBeforeItWasAskedIsReported(t *testing.T) {
	root := connectStore(t)
	meta, fp := keycloakDescriptor(t)
	if _, err := samlAdd(root, []string{"kc", "--metadata", meta, "--url", "https://admin.qz.test",
		"--preset", "keycloak", "--domain", "qz.test", "--fingerprint", fp}); err != nil {
		t.Fatal(err)
	}
	c, err := findSAML(root, "kc")
	if err != nil {
		t.Fatal(err)
	}
	c.VerifiedAttribute = "" // as saml add stored it before
	if err := saveSAML(root, *c); err != nil {
		t.Fatal(err)
	}
	st := Observe(root, t.TempDir(), posture.ServerFacts{})
	if len(st.SSO.Providers) != 1 || st.SSO.Providers[0].Unverified != "email_verified" {
		t.Fatalf("%+v", st.SSO.Providers)
	}
	found := false
	for _, f := range posture.Scan(st, nil).Findings {
		found = found || (f.Rule == "sso.unverified-addresses" && f.Resource == "saml/kc")
	}
	if !found {
		t.Error("the posture scan does not say kc signs in addresses it has not said it verified")
	}
}
