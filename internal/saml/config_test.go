// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package saml

import "testing"

// A provider that says an address is not verified is believed, whatever
// else it was set up to send. Keycloak's user unverified, an author here,
// signed in through SAML as that address while OIDC refused the same person
// for it: whoever can set their own address at the provider to a
// colleague's became that colleague here.
func TestAnAddressTheProviderSaysIsUnverifiedIsNobody(t *testing.T) {
	c := Config{Name: "corp", Domains: []string{"qz.test"}}
	said := func(v ...string) *Assertion {
		a := &Assertion{NameID: "unverified@qz.test", Attributes: map[string][]string{},
			FriendlyAttributes: map[string][]string{}}
		if len(v) > 0 {
			a.Attributes["email_verified"] = v
		}
		return a
	}
	if _, err := c.PrincipalOf(said("false")); err == nil {
		t.Error("an address the provider says it has not verified signed in")
	}
	if p, err := c.PrincipalOf(said("true")); err != nil || p != "unverified@qz.test" {
		t.Errorf("a verified address: %q, %v", p, err)
	}
	// Saying nothing is not saying no: Okta, Entra and Google send no such
	// attribute, and their directories are what set the address.
	if p, err := c.PrincipalOf(said()); err != nil || p != "unverified@qz.test" {
		t.Errorf("a provider that says nothing about it: %q, %v", p, err)
	}
}
