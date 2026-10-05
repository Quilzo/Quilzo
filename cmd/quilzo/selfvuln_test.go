// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/shield"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/compliance"
	"github.com/quilzo/quilzo/internal/sca"
)

// Quilzo's own bill of materials, read the way any bill is read, names its
// standard library as the Go vulnerability database does: before, it said
// pkg:generic/go and no Go advisory could ever match it.
func TestOurOwnBillMatchesTheGoDatabase(t *testing.T) {
	s, err := compliance.Generate(time.Now())
	if err != nil {
		t.Skip("no build info")
	}
	body, err := compliance.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sca.ReadBOM(body)
	if err != nil {
		t.Fatalf("our own bill does not read as CycloneDX: %v", err)
	}
	found := false
	for _, p := range b.Flat() {
		eco, name, ok := sca.ParsePURL(p.PURL)
		if ok && name == "stdlib" {
			found = true
			if eco != "Go" && eco != "go" && eco != "golang" {
				t.Errorf("ecosystem %q", eco)
			}
		}
	}
	if !found {
		t.Fatal("the standard library is not in our bill as the Go database names it")
	}
}

func TestASettingWeakenedByHandIsPutBackAndADecisionIsNot(t *testing.T) {
	root := shieldRoot(t)
	// Edited into the file: most of the internet may write its own address.
	if err := os.WriteFile(configPath(root), []byte(`{"values":{"network.trusted_proxies":"0.0.0.0/0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reverted, err := revertDrift(root, time.Now())
	if err != nil || len(reverted) != 1 || reverted[0].Was != "0.0.0.0/0" || !strings.Contains(reverted[0].Again, "--accept-risk") {
		t.Fatalf("%+v %v", reverted, err)
	}
	cfg, _ := loadConfig(root)
	if !cfg.IsDefault("network.trusted_proxies") {
		t.Fatal("not put back")
	}
	if b, _ := os.ReadFile(revertedPath(root)); !strings.Contains(string(b), "0.0.0.0/0") {
		t.Fatal("what it was is not kept")
	}
	// Set with a reason, it is a decision, and stays.
	if err := cfg.Set("network.trusted_proxies", "0.0.0.0/0", "a test rig behind a load balancer we do not control", "dana"); err != nil {
		t.Fatal(err)
	}
	saveConfig(root, cfg)
	if reverted, _ := revertDrift(root, time.Now()); len(reverted) != 0 {
		t.Fatalf("a decision was undone: %+v", reverted)
	}
	// Somebody was told: a case was opened for the first.
	st, _ := shield.Load(root)
	if len(st.Responses) == 0 || st.Responses[0].Playbook != "setting-reverted" {
		t.Fatalf("%+v", st.Responses)
	}
}
