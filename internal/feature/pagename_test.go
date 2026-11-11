// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// A package ships any page the store holds, by the store's own rule.
//
// Its rule was lower-case words joined by hyphens, described as "a page's
// name as the store has it", and the store holds About_Us and docs/v1.2: a
// site made of them could not be shipped as a package.
func TestAPackageShipsAnyPageTheStoreHolds(t *testing.T) {
	oid := strings.Repeat("0", 64)
	for _, name := range []string{"About_Us", "docs/v1.2", "about", "fr/about"} {
		if err := store.CheckTreeEntries(map[string]string{name: oid}); err != nil {
			t.Fatalf("the store does not hold %q: %v", name, err)
		}
		p := sample(t)
		p.Pages = append(p.Pages, Page{Name: name, Body: map[string]any{"title": "x"}})
		if err := p.Validate(checks); err != nil {
			t.Errorf("a package with the page %q: %v", name, err)
		}
	}
	for _, name := range []string{"../etc", "a//b", ".hidden", strings.Repeat("a", 129)} {
		p := sample(t)
		p.Pages = append(p.Pages, Page{Name: name, Body: map[string]any{"title": "x"}})
		if p.Validate(checks) == nil {
			t.Errorf("a package with the page %q was accepted", name)
		}
	}
}
