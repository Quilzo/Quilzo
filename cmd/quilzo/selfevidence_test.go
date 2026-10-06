// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/posture"
)

// Scans are moments; evidence is periods. Nothing is written while an
// outcome holds within a day; a change or a new day closes a record, which
// goes into the audit chain too, and the controls appear in the assurance
// report without anybody declaring them.
func TestQuilzosControlsGatherEvidenceOverTime(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	clean := posture.Report{}
	failingAC3 := posture.Report{Findings: []posture.Finding{{Rule: "access.no-policy", Controls: []string{"AC-3"}}}}

	if n, err := recordSelfEvidence(root, clean, day); err != nil || n != 0 {
		t.Fatalf("the first scan opened, and closed %d: %v", n, err)
	}
	if n, _ := recordSelfEvidence(root, clean, day.Add(time.Hour)); n != 0 {
		t.Fatalf("an unchanged hour closed %d records", n)
	}
	n, _ := recordSelfEvidence(root, failingAC3, day.Add(2*time.Hour))
	if n != 1 {
		t.Fatalf("AC-3 starting to fail closed %d records, want 1", n)
	}
	next := day.Add(24 * time.Hour)
	if n, _ := recordSelfEvidence(root, failingAC3, next); n < 10 {
		t.Fatalf("a new day closed only %d records", n)
	}

	ev, err := loadEvidence(root)
	if err != nil {
		t.Fatal(err)
	}
	var ac3 []assurance.Evidence
	for _, e := range ev {
		if e.Control == "quilzo/AC-3" {
			ac3 = append(ac3, e)
		}
	}
	if len(ac3) != 2 || ac3[0].Outcome != assurance.Operated || ac3[1].Outcome != assurance.Failed ||
		!ac3[0].To.Equal(ac3[1].From) {
		t.Fatalf("AC-3's evidence is not one period operated then one failed: %+v", ac3)
	}
	events, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range events {
		if e.Action == "control.failed" && strings.Contains(e.Resource, "quilzo/AC-3") {
			found = true
		}
	}
	if !found {
		t.Fatal("the failed period is not in the audit chain")
	}
	ctl, err := loadControls(root)
	if err != nil {
		t.Fatal(err)
	}
	built := false
	for _, c := range ctl {
		if c.ID == "quilzo/AC-3" && c.Automated && c.Cadence == assurance.Continuous {
			built = true
		}
	}
	if !built {
		t.Fatal("Quilzo's AC-3 is not a control the assurance report knows")
	}
}
