// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every rule that ships validates, fires on the event it says it fires on,
// stays quiet on the one beside it, and says what it does not catch.
func TestEveryShippedRuleAgreesWithItsOwnFixtures(t *testing.T) {
	files, err := Pack()
	if err != nil {
		t.Fatal(err)
	}
	rules, quiet := 0, 0
	platforms := map[string]bool{}
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		var r Rule
		if err := json.Unmarshal(f.Body, &r); err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		rules++
		if r.ID+".json" != f.Name {
			t.Errorf("%s holds the rule %s", f.Name, r.ID)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		for _, res := range r.Test() {
			if !res.OK() {
				t.Errorf("%s: %q should match=%v and matched=%v", r.ID,
					res.Fixture, res.Want, res.Got)
			}
		}
		if strings.TrimSpace(r.Blind) == "" {
			t.Errorf("%s does not say what it misses", r.ID)
		}
		if r.Quiet {
			quiet++
		}
		for _, s := range r.Sources {
			platforms[strings.SplitN(s, "/", 2)[0]] = true
		}
	}
	if rules < 18 || quiet != 3 {
		t.Errorf("%d rules, %d of them quiet", rules, quiet)
	}
	for _, want := range []string{"okta", "entra", "workspace", "github",
		"aws", "evm"} {
		if !platforms[want] {
			t.Errorf("no rule reads %s", want)
		}
	}
}
