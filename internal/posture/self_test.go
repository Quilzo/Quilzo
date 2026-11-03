// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A flaw in this build that is being exploited is contained at once only
// when CISA's catalogue says it is being exploited, and the catalogue is a
// file an operator gives. Without it, or with one long out of date, that
// never happens, and nothing said so.
func TestAMissingOrOldExploitedCatalogueIsReported(t *testing.T) {
	r := ruleByID(t, "self.kev-missing")
	now := time.Now()
	if got := r.Check(State{Now: now}); len(got) != 0 {
		t.Errorf("facts nobody gathered: %+v", got)
	}
	got := r.Check(State{Now: now, Self: SelfFacts{Checked: true}})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "no catalogue") || !strings.Contains(got[0].Fix, "quilzo self kev") {
		t.Errorf("no catalogue: %+v", got)
	}
	got = r.Check(State{Now: now, Self: SelfFacts{Checked: true, Exploited: true, ExploitedOf: now.AddDate(0, 0, -31)}})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "31 days") {
		t.Errorf("a catalogue 31 days old: %+v", got)
	}
	if got := r.Check(State{Now: now, Self: SelfFacts{Checked: true, Exploited: true, ExploitedOf: now.AddDate(0, 0, -29)}}); len(got) != 0 {
		t.Errorf("a catalogue 29 days old: %+v", got)
	}
	got = r.Check(State{Now: now, Self: SelfFacts{Checked: true, Problem: "self/kev.json cannot be read"}})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "cannot be read") {
		t.Errorf("a catalogue that cannot be read: %+v", got)
	}
	// Not looked at is not passing.
	if rep := Scan(State{}, nil); !slices.Contains(rep.Skipped, "self.kev-missing") {
		t.Error("a scan that did not look for the catalogue says it is there")
	}
}
