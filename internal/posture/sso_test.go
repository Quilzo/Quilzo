// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package posture

import (
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
