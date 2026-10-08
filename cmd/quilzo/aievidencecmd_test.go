// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/aievidence"
	"github.com/quilzo/quilzo/internal/audit"
)

// The evidence is read from the store: its agents and who answers for
// them, and the period's runs in the signed log.
func TestTheEvidenceIsReadFromTheStore(t *testing.T) {
	root, _ := identityStore(t) // dana declared tidy
	record(root, audit.Record{Action: "agent.run", Resource: "/", Outcome: audit.Success, Principal: "agent/tidy",
		Kind: audit.KindAI, Model: "m", Verified: true, Detail: map[string]string{"agent": "tidy", "on_behalf_of": "dana"}})
	in, err := aiEvidenceInputs(root, 30, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if in.Sponsors["tidy"] != "dana" || !in.Standing["tidy"] || len(in.Agents) != 1 {
		t.Fatalf("%+v %+v", in.Sponsors, in.Standing)
	}
	var d aievidence.Item
	for _, it := range aievidence.Deployer(in) {
		if it.Ref == "Art. 26(1)" {
			d = it
		}
	}
	if !strings.Contains(strings.Join(d.Evidence, " "), "1 runs") {
		t.Fatalf("%+v", d)
	}
	f := filepath.Join(t.TempDir(), "ai-bom.json")
	if err := complianceAI(root, "aibom", []string{f}); err != nil {
		t.Fatal(err)
	}
	var bom aievidence.BOM
	b, _ := os.ReadFile(f)
	if err := json.Unmarshal(b, &bom); err != nil || bom.SpecVersion != "1.6" || len(bom.Components) == 0 {
		t.Fatalf("%v %s", err, b)
	}
	if err := complianceAI(root, "ai-act", []string{"--days", "0"}); err == nil {
		t.Fatal("a period of no days was counted")
	}
	if err := complianceAI(root, "iso42001", nil); err != nil {
		t.Fatal(err)
	}
}
