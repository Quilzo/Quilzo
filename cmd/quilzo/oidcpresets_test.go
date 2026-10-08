// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"testing"
)

func TestTheSignInPresetsRefuseWhatWouldLetOutsidersIn(t *testing.T) {
	root := connectStore(t)
	base := []string{"--client-id", "abc", "--redirect-uri",
		"https://cms.acme.com/auth/callback"}
	for name, args := range map[string][]string{
		"Google with no domain":    {"--provider", "google"},
		"Microsoft common":         {"--provider", "microsoft", "--tenant", "common"},
		"Microsoft organizations":  {"--provider", "microsoft", "--tenant", "organizations"},
		"Microsoft by domain name": {"--provider", "microsoft", "--tenant", "acme.com"},
		"a provider nobody preset": {"--provider", "github"},
		"a domain that is not one": {"--provider", "google", "--domain", "acme com"},
	} {
		if err := oidcConfigure(root, append(args, base...)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	if err := oidcConfigure(root, append([]string{"--provider", "google",
		"--domain", "Acme.com, acme.co.uk"}, base...)); err != nil {
		t.Fatal(err)
	}
	c, _ := loadOIDC(root)
	if c.Issuer != "https://accounts.google.com" || c.Claim != "email" ||
		!c.RequireVerifiedEmail || len(c.Domains) != 2 ||
		c.Domains[0] != "acme.com" || c.providerLabel() != "Google" {
		t.Errorf("google preset: %+v", c)
	}

	const tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	if err := oidcConfigure(root, append([]string{"--provider", "microsoft",
		"--tenant", tenant, "--domain", "acme.com"}, base...)); err != nil {
		t.Fatal(err)
	}
	c, _ = loadOIDC(root)
	if c.Issuer != "https://login.microsoftonline.com/"+tenant+"/v2.0" ||
		c.Claim != "preferred_username" || c.Tenant != tenant {
		t.Errorf("microsoft preset: %+v", c)
	}
}
