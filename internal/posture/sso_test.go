// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"strings"
	"testing"
	"time"
)

func TestAnIdentityProviderCertificateEndingSoonIsFound(t *testing.T) {
	s := clean(t)
	s.SSO = SSOFacts{Checked: true, Providers: []SSOProvider{
		{Name: "okta", Expires: []time.Time{s.Now.Add(10 * 24 * time.Hour), s.Now.Add(400 * 24 * time.Hour)}},
		{Name: "entra", Expires: []time.Time{s.Now.Add(90 * 24 * time.Hour)}},
		{Name: "old", Expires: []time.Time{s.Now.Add(-time.Hour)}},
	}}
	rep := Scan(s, nil)
	n := 0
	for _, f := range rep.Findings {
		if f.Rule == "sso.cert-expiring" {
			n++
			if f.Resource != "saml/okta" && f.Resource != "saml/old" {
				t.Errorf("flagged %s", f.Resource)
			}
		}
	}
	if n != 2 {
		t.Errorf("%d certificates flagged; one ending in ten days and one ended", n)
	}
}

func TestAnUnusableIdentityProviderIsFound(t *testing.T) {
	s := clean(t)
	s.SSO = SSOFacts{Checked: true, Providers: []SSOProvider{{Name: "okta", Problem: "a 1024-bit key"}, {Name: "fine"}}}
	if f := has(Scan(s, nil), "sso.unusable"); f == nil || f.Resource != "saml/okta" {
		t.Errorf("%+v", f)
	}
}

// A Keycloak added before saml add asked for the attribute it says an
// address is verified in signs in an address it has not verified, as long
// as it says nothing either way: the store the finding was reproduced on
// still let a person who set their own address to a colleague's in as
// that colleague after the fix. Asking for the attribute now would refuse
// everybody until the realm sends it, so the scan says so instead.
func TestAProviderThatSignsInUnverifiedAddressesIsFound(t *testing.T) {
	s := clean(t)
	s.SSO = SSOFacts{Checked: true, Providers: []SSOProvider{{Name: "keycloak", Unverified: "email_verified"},
		{Name: "okta"}}}
	var found []Finding
	for _, f := range Scan(s, nil).Findings {
		if f.Rule == "sso.unverified-addresses" {
			found = append(found, f)
		}
	}
	if len(found) != 1 || found[0].Resource != "saml/keycloak" ||
		!strings.Contains(found[0].Fix, "--verified-attribute email_verified") {
		t.Errorf("%+v", found)
	}
}
