// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package experiment

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// An experiment runs on any page the store holds, by the store's own rule.
//
// It had a rule of its own, lower case with no dot, and the store holds
// About_Us and docs/v1.2: `quilzo add About_Us=…` worked and `quilzo
// experiment add x --page About_Us` said "About_Us" is not a page name.
func TestAnExperimentRunsOnAnyPageTheStoreHolds(t *testing.T) {
	oid := strings.Repeat("0", 64)
	for _, page := range []string{"About_Us", "docs/v1.2", "pricing", "fr/about", "blog/2026/launch.notes"} {
		if err := store.CheckTreeEntries(map[string]string{page: oid}); err != nil {
			t.Fatalf("the store does not hold %q: %v", page, err)
		}
		e := Experiment{Name: "x7", Page: page, Goal: "page:/" + page,
			Variants: []Variant{{Name: "a", Page: page, Weight: 50}, {Name: "b", Page: page + "-b", Weight: 50}}}
		if err := e.Validate(); err != nil {
			t.Errorf("an experiment on %q: %v", page, err)
		}
	}
	// What no page can be is still refused, and the cap stays.
	for _, page := range []string{"../etc", "a//b", "a/.hidden", "", strings.Repeat("a", 64) + "/" + strings.Repeat("b", 64) + "/" + strings.Repeat("c", 64) + "/" + strings.Repeat("d", 10)} {
		e := Experiment{Name: "x7", Page: page, Goal: "form:c", Variants: pricing.Variants}
		if e.Validate() == nil {
			t.Errorf("an experiment on %q was accepted", page)
		}
	}
	for _, goal := range []string{"page:/", "page:/contact", "page:/blog/"} {
		e := pricing
		e.Goal = goal
		if err := e.Validate(); err != nil {
			t.Errorf("the goal %q, a goal before, is refused: %v", goal, err)
		}
	}
}
