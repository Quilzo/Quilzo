// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A shield's record that cannot be read was said only on the Shield
// screen, to whoever happened to open it, and there it said that what the
// record held stayed in force. A server started since enforces none of it,
// so it is a high finding, which the drift check tells the security
// contact of.
func TestAShieldRecordThatCannotBeReadIsReported(t *testing.T) {
	r := ruleByID(t, "shield.record-unreadable")
	now := time.Now()
	if got := r.Check(State{Now: now}); len(got) != 0 {
		t.Errorf("facts nobody gathered: %+v", got)
	}
	if got := r.Check(State{Now: now, Shield: ShieldFacts{Checked: true}}); len(got) != 0 {
		t.Errorf("a record that reads: %+v", got)
	}
	got := r.Check(State{Now: now, Shield: ShieldFacts{Checked: true, Unreadable: "shield/state.json: unexpected end of JSON input"}})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "unexpected end of JSON input") ||
		!strings.Contains(got[0].Detail, "a server started since enforces no block") ||
		!strings.HasPrefix(got[0].Fix, "quilzo shield repair") {
		t.Fatalf("a record that cannot be read: %+v", got)
	}
	if r.Severity != High {
		t.Errorf("severity %s: the drift check tells the security contact of high and critical only", r.Severity)
	}
	// Not looked at is not passing.
	if rep := Scan(State{}, nil); !slices.Contains(rep.Skipped, "shield.record-unreadable") {
		t.Error("a scan that did not read the shield's record says it reads")
	}
}

// A network declared trusted is never blocked or slowed, and nothing said
// when one was as wide as a provider, a country or the internet. Each is
// a finding by its own name, so one can be accepted, with a reason and an
// end, without accepting the next.
func TestAWideTrustedNetworkIsReported(t *testing.T) {
	r := ruleByID(t, "shield.trusts-widely")
	now := time.Now()
	if got := r.Check(State{Now: now, Shield: ShieldFacts{Wide: []string{"10.0.0.0/8"}}}); len(got) != 0 {
		t.Errorf("facts nobody gathered: %+v", got)
	}
	if got := r.Check(State{Now: now, Shield: ShieldFacts{Checked: true}}); len(got) != 0 {
		t.Errorf("no wide network: %+v", got)
	}
	rep := Scan(State{Now: now, Shield: ShieldFacts{Checked: true, Wide: []string{"10.0.0.0/8", "2001:db8::/32"}, Most: []string{"0.0.0.0/0"}}}, nil)
	found := map[string]Finding{}
	for _, f := range rep.Findings {
		if f.Rule == "shield.trusts-widely" {
			found[f.Resource] = f
		}
	}
	if len(found) != 3 {
		t.Fatalf("%d findings, want one for each network: %+v", len(found), found)
	}
	if f := found["0.0.0.0/0"]; f.Severity != High || !strings.Contains(f.Detail, "more than any one network") ||
		!strings.HasPrefix(f.Fix, "quilzo shield trust remove 0.0.0.0/0") {
		t.Errorf("most of the internet: %+v", f)
	}
	if f := found["10.0.0.0/8"]; f.Severity != Medium || !strings.HasPrefix(f.Fix, "quilzo shield trust remove 10.0.0.0/8") ||
		!strings.Contains(f.Fix, "quilzo posture suppress") {
		t.Errorf("a wide network: %+v", f)
	}
	// Accepting one does not silence another.
	rep = Scan(State{Now: now, Shield: ShieldFacts{Checked: true, Wide: []string{"10.0.0.0/8", "2001:db8::/32"}}},
		[]Suppression{{ID: found["10.0.0.0/8"].ID(), Reason: "the whole office network", By: "dana", Until: now.Add(time.Hour).Unix()}})
	if len(rep.Suppressed) != 1 || len(rep.Findings) != 1 || rep.Findings[0].Resource != "2001:db8::/32" {
		t.Errorf("accepting one network: %d suppressed, findings %+v", len(rep.Suppressed), rep.Findings)
	}
}
