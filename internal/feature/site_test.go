// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"strings"
	"testing"
)

func withSite(s Site) *Package {
	return &Package{Format: Format, Name: "bakery", Version: "1.0", Title: "Hart's Bakery",
		Purpose: "The bakery's website.", Site: &s}
}

// A site block is held to what a site's name and look are held to
// anywhere else, and is the first thing its card says.
func TestASiteBlockIsCheckedLikeTheSiteItself(t *testing.T) {
	good := Site{Name: "Hart's Bakery", Description: "Bread baked before dawn.", Starter: "landing",
		Style: "soft", Colour: "#c2410c", Motion: "subtle", Tokens: map[string]string{"icons": "outlined"}}
	p := withSite(good)
	if err := p.Validate(Checks{}); err != nil {
		t.Fatal(err)
	}
	if p.Blocks() != 1 || len(p.Refs()) != 1 || p.Refs()[0] != SiteRef || p.Block(SiteRef) != p.Site {
		t.Fatalf("the site is not a block: %d %v", p.Blocks(), p.Refs())
	}
	c := p.MakeCard()
	if len(c.Shows) == 0 || !strings.Contains(c.Shows[0].Text, `Names the site "Hart's Bakery"`) ||
		!strings.Contains(c.Shows[0].Text, "the soft style") || c.Approvers != 1 {
		t.Fatalf("the card says %+v", c)
	}

	for name, bad := range map[string]Site{
		"no name":            {},
		"a control in it":    {Name: "Bakery\n<script>"},
		"a long name":        {Name: strings.Repeat("a", MaxSiteName+1)},
		"a long description": {Name: "B", Description: strings.Repeat("a", MaxSiteDescription+1)},
		"no such starter":    {Name: "B", Starter: "wordpress"},
		"no such style":      {Name: "B", Style: "brutalist"},
		"not a colour":       {Name: "B", Colour: "orange"},
		"no such token":      {Name: "B", Tokens: map[string]string{"javascript": "x"}},
		"unreadable":         {Name: "B", Tokens: map[string]string{"on-surface": "#ffffff", "surface": "#ffffff"}},
	} {
		if err := withSite(bad).Validate(Checks{}); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "site:") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
