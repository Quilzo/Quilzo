// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

func writeTemplate(t *testing.T, root string, f customTemplateFile) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(templatesDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templatesDir(root), f.Kind+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func triager() customTemplateFile {
	return customTemplateFile{Kind: "triager", Summary: "sorts incoming requests",
		Manifest: agent.Manifest{Kind: "triager", Purpose: "Sort requests by what they need",
			Capabilities: []string{"read_page", "list_pages"}, Autonomy: agent.AutonomyPropose,
			Budget: agent.Budget{Steps: 8, Tools: 4, Duration: agent.Duration(120e9)}}}
}

// A kind a store's template declares makes agents like a built-in one does,
// and they validate wherever a declaration is checked.
func TestAStoresTemplateMakesAgentsOfItsKind(t *testing.T) {
	root, _ := identityStore(t)
	writeTemplate(t, root, triager())
	set, err := loadCustomTemplates(root)
	if err != nil {
		t.Fatal(err)
	}
	m, err := agent.From(set["triager"], "intake", knownCapabilities(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatalf("an agent of a store's kind could not be declared: %v", err)
	}
	if err := m.ValidateWith(knownCapabilities(root), customKinds(root)); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(knownCapabilities(root)); err == nil {
		t.Fatal("a kind no template declares validated without one")
	}
}

// A template cannot claim a built-in kind, cannot smuggle the supervisor's
// powers through its manifest, and must validate as written.
func TestATemplateIsRefusedWhatItCannotBe(t *testing.T) {
	root, _ := identityStore(t)
	known := knownCapabilities(root)
	builtin := triager()
	builtin.Kind, builtin.Manifest.Kind = "supervisor", "supervisor"
	smuggled := triager()
	smuggled.Kind, smuggled.Manifest.Kind = "boss", "supervisor"
	widened := triager()
	widened.Manifest.Capabilities = append(widened.Manifest.Capabilities, "no_such_capability")
	unnamed := triager()
	unnamed.Kind, unnamed.Manifest.Kind = "X!", "X!"
	for name, f := range map[string]customTemplateFile{"built-in": builtin, "supervisor": smuggled,
		"invalid": widened, "badly named": unnamed} {
		if _, err := f.template("t.json", known, nil); err == nil {
			t.Errorf("%s template was accepted", name)
		}
	}
	if _, err := triager().template("t.json", known, nil); err != nil {
		t.Fatalf("a valid template was refused: %v", err)
	}
}

// Removing a template its agents still need is refused, naming them.
func TestATemplateInUseIsNotRemoved(t *testing.T) {
	root, _ := identityStore(t)
	writeTemplate(t, root, triager())
	set, _ := loadCustomTemplates(root)
	m, err := agent.From(set["triager"], "intake", knownCapabilities(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	using, err := agentsOfKind(root, "triager")
	if err != nil || strings.Join(using, ",") != "intake" {
		t.Fatalf("agents of the kind: %v %v", using, err)
	}
	if using, _ := agentsOfKind(root, "retrieval"); len(using) != 0 && using[0] == "intake" {
		t.Fatal("an agent was counted under another kind")
	}
}
