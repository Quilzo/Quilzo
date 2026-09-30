// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"testing"

	"github.com/quilzo/quilzo/internal/oidc"
)

func claims(email string, verified bool, raw map[string]any) *oidc.Claims {
	return &oidc.Claims{Email: email, EmailVerified: verified, Raw: raw}
}

// A personal Google account can carry a work address, and outlives the job.
func TestAGoogleSignInMustBeManagedByTheWorkspace(t *testing.T) {
	o := &OIDC{Claim: "email", RequireVerifiedEmail: true,
		HostedDomains: []string{"acme.com"}}
	for name, c := range map[string]*oidc.Claims{
		"personal account, work address": claims("ann@acme.com", true, map[string]any{}),
		"another company's Workspace": claims("ann@acme.com", true,
			map[string]any{"hd": "evil.example"}),
		"managed, address unverified": claims("ann@acme.com", false,
			map[string]any{"hd": "acme.com"}),
	} {
		if p, err := o.principalFor(c); err == nil {
			t.Errorf("%s signed in as %s", name, p)
		}
	}
	p, err := o.principalFor(claims("ann@acme.com", true,
		map[string]any{"hd": "ACME.com"}))
	if err != nil || p != "ann@acme.com" {
		t.Errorf("a managed account was refused: %v", err)
	}
}

// nOAuth: Entra's email claim is an attribute any tenant's administrator can
// set to anything.
func TestAMicrosoftSignInIsTheTenantsSignInNameAndNotItsEmail(t *testing.T) {
	const tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	o := &OIDC{Claim: "preferred_username", Tenant: tenant,
		Domains: []string{"acme.com"}}
	cases := map[string]struct {
		c    *oidc.Claims
		want string
	}{
		"the tenant's own user": {claims("", false, map[string]any{
			"tid": tenant, "preferred_username": "Ann@Acme.com"}), "ann@acme.com"},
		"another tenant": {claims("", false, map[string]any{
			"tid":                "00000000-0000-0000-0000-000000000000",
			"preferred_username": "ann@acme.com"}), ""},
		"an email claim set to the CEO's": {claims("ceo@acme.com", true,
			map[string]any{"tid": tenant,
				"preferred_username": "guest@partner.example"}), ""},
		"no sign-in name": {claims("ceo@acme.com", true,
			map[string]any{"tid": tenant}), ""},
	}
	for name, tc := range cases {
		p, err := o.principalFor(tc.c)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("%s signed in as %s", name, p)
		case tc.want != "" && p != tc.want:
			t.Errorf("%s: %q, %v", name, p, err)
		}
	}
}
