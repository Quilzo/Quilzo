// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package personalise

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// A rule serves any page the store holds at any other, and when it refuses
// a name it says which.
//
// It had a rule of its own, lower case with no dot, and its refusal was
// "rule x7p needs a page and a different page to serve there" for two
// pages that both existed and differed: the rule had refused docs/v1.2
// and About_Us-b as names and said something else.
func TestARuleServesAnyPageTheStoreHolds(t *testing.T) {
	oid := strings.Repeat("0", 64)
	for _, pair := range [][2]string{{"docs/v1.2", "About_Us-b"}, {"About_Us", "About_Us-b"}, {"home", "home-b"}} {
		if err := store.CheckTreeEntries(map[string]string{pair[0]: oid, pair[1]: oid}); err != nil {
			t.Fatalf("the store does not hold %v: %v", pair, err)
		}
		r := Rule{Name: "x7p", Page: pair[0], Variant: pair[1], When: []Condition{{Field: Campaign, Values: []string{"spring"}}}}
		if err := r.Validate(); err != nil {
			t.Errorf("a rule serving %s at %s: %v", pair[1], pair[0], err)
		}
	}
	r := Rule{Name: "x7p", Page: "docs", Variant: "../etc", When: []Condition{{Field: Campaign, Values: []string{"spring"}}}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), `"../etc"`) {
		t.Errorf("a name no page can have was refused as %v, not by name", err)
	}
}
