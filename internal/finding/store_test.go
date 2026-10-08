// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

func sample(src, who string) Finding {
	return Finding{
		Kind: FromDetection, Title: "Sign-in from a new country",
		Source: src, Entity: telemetry.ID{Issuer: "okta", Value: who},
		Severity: telemetry.SeverityHigh, State: Open,
		Evidence: []Evidence{{What: "signed in from NZ", Source: "okta/system",
			Tainted: true}},
	}
}

// TestTheRegisterSurvivesBeingWrittenDown.
func TestTheRegisterSurvivesBeingWrittenDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	reg := NewRegister()
	t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	reg.Record(sample("rule.geo", "dana"), t0)
	reg.Record(sample("rule.geo", "dana"), t0.Add(time.Hour))
	reg.Record(sample("rule.geo", "sam"), t0)
	cur := map[string]time.Time{"detect": t0.Add(2 * time.Hour)}
	if err := Save(path, reg, cur); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the register is not private to its owner: %v %v", fi.Mode(), err)
	}

	back, cursors, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Len() != 2 {
		t.Fatalf("%d findings came back, want 2", back.Len())
	}
	if !cursors["detect"].Equal(cur["detect"]) {
		t.Fatal("the cursor was lost, so the next run would count events twice")
	}
	// And recording into what was loaded still deduplicates.
	f, isNew := back.Record(sample("rule.geo", "dana"), t0.Add(3*time.Hour))
	if isNew || f.Seen != 3 {
		t.Fatalf("a loaded register did not fold a repeat: new=%v seen=%d", isNew, f.Seen)
	}
}

// TestAMissingRegisterIsEmptyAndABrokenOneIsNot.
func TestAMissingRegisterIsEmptyAndABrokenOneIsNot(t *testing.T) {
	dir := t.TempDir()
	reg, _, err := Load(filepath.Join(dir, "none.json"))
	if err != nil || reg.Len() != 0 {
		t.Fatalf("a missing register: %v, %d", err, reg.Len())
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(bad); err == nil ||
		!strings.Contains(err.Error(), "nothing is wrong") {
		t.Fatalf("a corrupt register loaded as empty: %v", err)
	}
}

// TestFixedThenSeenAgainIsOpen — the projection bug.
//
// Record reopened a finding the scanners saw again, and Apply then put the
// "fixed" decision back on top of it, so a vulnerability marked fixed stayed
// fixed while the scanner reported it daily.
func TestFixedThenSeenAgainIsOpen(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	reg := NewRegister()
	f, _ := reg.Record(sample("rule.geo", "dana"), t0)
	fixed := Decision{Finding: f.ID, At: t0.Add(time.Hour), By: "sam",
		Kind: audit.KindHuman, To: Fixed}

	if got := View(reg, []Decision{fixed}, t0.Add(2*time.Hour)); got[0].State != Fixed {
		t.Fatalf("not seen since: state %s, want fixed", got[0].State)
	}
	reg.Record(sample("rule.geo", "dana"), t0.Add(3*time.Hour))
	if got := View(reg, []Decision{fixed}, t0.Add(4*time.Hour)); got[0].State != Open {
		t.Fatalf("seen again after being fixed: state %s, want open", got[0].State)
	}
}

// TestVerdictsNeedReasonsAndBehaveDifferently.
func TestVerdictsNeedReasonsAndBehaveDifferently(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	for _, to := range []State{FalsePositive, Benign} {
		d := Decision{Finding: "x", At: t0, By: "sam", Kind: audit.KindHuman, To: to}
		if err := d.Validate(); err == nil {
			t.Errorf("%s was accepted with no reason", to)
		}
		d.Because = "the VPN egresses in NZ"
		if err := d.Validate(); err != nil {
			t.Errorf("%s with a reason: %v", to, err)
		}
		if !to.Closed() {
			t.Errorf("%s does not take a finding off the queue", to)
		}
	}
	// A model still cannot give one.
	ai := Decision{Finding: "x", At: t0, By: "agent", Kind: audit.KindAI,
		To: FalsePositive, Because: "looks fine"}
	if err := ai.Validate(); err == nil {
		t.Fatal("a model recorded a verdict")
	}

	reg := NewRegister()
	f, _ := reg.Record(sample("rule.geo", "dana"), t0)
	fp := Decision{Finding: f.ID, At: t0.Add(time.Hour), By: "sam",
		Kind: audit.KindHuman, To: FalsePositive, Because: "VPN"}
	benign := fp
	benign.To = Benign
	reg.Record(sample("rule.geo", "dana"), t0.Add(2*time.Hour))

	if got := View(reg, []Decision{fp}, t0.Add(3*time.Hour))[0]; got.State != Open {
		t.Errorf("a false positive seen again stayed closed: %s", got.State)
	}
	if got := View(reg, []Decision{benign}, t0.Add(3*time.Hour))[0]; got.State != Benign {
		t.Errorf("expected activity recurring reopened: %s", got.State)
	}
	// The reason is kept with the verdict, while nothing has recurred.
	once := NewRegister()
	once.Record(sample("rule.geo", "dana"), t0)
	if got := View(once, []Decision{fp}, t0.Add(90*time.Minute))[0]; got.Because != "VPN" ||
		got.State != FalsePositive {
		t.Errorf("the verdict lost its reason: %s %q", got.State, got.Because)
	}
	// Closed findings weigh nothing.
	if w := (Finding{State: FalsePositive, Severity: telemetry.SeverityCritical}).Weight(t0); w != 0 {
		t.Errorf("a false positive weighs %v", w)
	}
}

// TestEvidenceIsBounded.
func TestEvidenceIsBounded(t *testing.T) {
	reg := NewRegister()
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 500; i++ {
		f := sample("rule.geo", "dana")
		f.Evidence[0].What = "event " + time.Duration(i).String()
		reg.Record(f, t0.Add(time.Duration(i)*time.Minute))
	}
	got := reg.All(t0.Add(time.Hour * 24))[0]
	if len(got.Evidence) > MaxEvidence {
		t.Fatalf("%d pieces of evidence kept", len(got.Evidence))
	}
	if got.Evidence[0].What != "event 0s" {
		t.Fatal("the evidence the finding was opened on was dropped")
	}
	if got.Seen != 500 {
		t.Fatalf("the count stopped counting: %d", got.Seen)
	}
}
