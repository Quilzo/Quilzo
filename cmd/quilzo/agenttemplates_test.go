// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
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

// `quilzo agent template save FILE`, `list` and `remove KIND` are what the
// help, the `agent templates` footer and NEWS tell a person to type. The
// dispatch had a case for `templates` and none for `template`, so every one
// of them printed the agent usage and exited 1, and the only way to declare
// a store's own archetype was to write the file into the store by hand,
// past the grant check and the record the save path makes.
func TestTheTemplateCommandsAreReachedFromTheCommandLine(t *testing.T) {
	root := demoStore(t)
	file := filepath.Join(t.TempDir(), "triager.json")
	b, err := json.Marshal(triager())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAgent(root, []string{"template", "save", file}); err != nil {
		t.Fatalf("`agent template save` did not save: %v", err)
	}
	if set, err := loadCustomTemplates(root); err != nil || set["triager"].Summary == "" {
		t.Fatalf("the saved template is not a kind here: %v %v", set, err)
	}
	for _, args := range [][]string{{"template"}, {"template", "list"}} {
		if err := cmdAgent(root, args); err != nil {
			t.Errorf("`agent %s`: %v", strings.Join(args, " "), err)
		}
	}
	// And the list answers --json with the kind in it.
	old := w
	t.Cleanup(func() { w = old })
	var doc bytes.Buffer
	w = &out.Writer{Out: &doc, Err: io.Discard, Mode: out.JSON}
	if err := cmdAgent(root, []string{"template", "list"}); err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Templates []struct{ Kind string } `json:"templates"`
	}
	if err := json.Unmarshal(doc.Bytes(), &listed); err != nil || len(listed.Templates) != 1 ||
		listed.Templates[0].Kind != "triager" {
		t.Fatalf("`agent template list --json`: %v %q", err, doc.String())
	}
	w = old
	if err := cmdAgent(root, []string{"template", "remove", "triager"}); err != nil {
		t.Fatalf("`agent template remove` did not remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(templatesDir(root), "triager.json")); !os.IsNotExist(err) {
		t.Fatalf("the template is still there: %v", err)
	}
}

// The privilege table says listing a store's templates is a read and saving
// or removing one is a grant, in three-word rows the lookup never asked:
// it built "agent template" and fell back to "agent", so listing them took
// the manage-agents permission, and the rows that said otherwise said it to
// nobody.
func TestTheTemplateCommandsNeedWhatTheirRowsSay(t *testing.T) {
	for sub, want := range map[string]auth.Action{"list": auth.ActView, "save": auth.ActGrant,
		"remove": auth.ActGrant} {
		if n, _ := lookupNeed("agent", []string{"template", sub, "x"}); n.action != want {
			t.Errorf("`agent template %s` needs %s, and its row says %s", sub, n.action, want)
		}
	}
	// A flag in the third place is not a subcommand.
	if n, _ := lookupNeed("agent", []string{"template", "--json"}); n.action != auth.ActManageAgents {
		t.Errorf("`agent template --json` needs %s", n.action)
	}
}
