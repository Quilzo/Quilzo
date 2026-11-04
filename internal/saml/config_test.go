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

// Whether a provider verified an address is asked only of a principal that
// is one. A provider set up to sign people in by a username or an opaque
// NameID refused everybody whose address it had not verified, though the
// address was not who they became here: OIDC asks email_verified only of
// the email claim, and a sign-in by sub or preferred_username goes on.
func TestOnlyAnAddressIsAskedWhetherItWasVerified(t *testing.T) {
	a := &Assertion{NameID: "f3a9c1d2", Attributes: map[string][]string{"uid": {"alice"},
		"email": {"alice@qz.test"}, "email_verified": {"false"}}, FriendlyAttributes: map[string][]string{}}
	for _, c := range []Config{
		{Name: "corp", Principal: "attribute:uid"},
		{Name: "kc", Principal: "attribute:uid", VerifiedAttribute: "email_verified"},
	} {
		if p, err := c.PrincipalOf(a); err != nil || p != "alice" {
			t.Errorf("%s by uid, with the address unverified: %q, %v", c.Name, p, err)
		}
	}
	if p, err := (&Config{Name: "persistent"}).PrincipalOf(a); err != nil || p != "f3a9c1d2" {
		t.Errorf("an opaque NameID, with the address unverified: %q, %v", p, err)
	}
	// The address itself, as the principal, is still asked.
	if p, err := (&Config{Name: "corp", Principal: "attribute:email"}).PrincipalOf(a); err == nil {
		t.Errorf("an address the provider says it has not verified signed in as %q", p)
	}
}
