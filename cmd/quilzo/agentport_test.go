// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
)

// importAs runs quilzo agent import as dana, with the JSON report.
func importAs(t *testing.T, root string, args ...string) (report struct {
	Format string          `json:"format"`
	Agents []importedAgent `json:"agents"`
}) {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := agentImport(root, args); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	return report
}

func asDana(t *testing.T, root string) {
	t.Helper()
	toks := &auth.TokenStore{}
	secret, _, err := toks.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), toks); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { t.Cleanup(func() { flagToken = old }) }(flagToken)
	flagToken = secret
}

// A crew whose lead hands work to an agent declared after it in the file
// is declared whole, the delegate first; nothing is declared without
// --save; and what is declared already is left as it is.
func TestACrewIsImportedWholeAndOnlyWhenSaved(t *testing.T) {
	root, _ := identityStore(t)
	asDana(t, root)
	crew := filepath.Join("..", "..", "internal", "agentport", "testdata", "agents.yaml")

	got := importAs(t, root, crew)
	if got.Format != "crewai" || len(got.Agents) != 2 {
		t.Fatalf("%+v", got)
	}
	set, _ := loadAgents(root)
	if _, ok := set.Agents["lead"]; ok {
		t.Fatal("an import without --save declared an agent")
	}

	got = importAs(t, root, crew, "--save")
	for _, a := range got.Agents {
		if !a.Declared || a.Invalid != "" {
			t.Fatalf("%s: declared %v, %q", a.Manifest.Name, a.Declared, a.Invalid)
		}
	}
	set, _ = loadAgents(root)
	lead := set.Agents["lead"]
	if len(lead.Delegates) != 1 || lead.Delegates[0] != "researcher" || set.Agents["researcher"].Name == "" ||
		set.Identities["lead"].Sponsor != "dana" {
		t.Fatalf("lead %+v, identity %+v", lead, set.Identities["lead"])
	}
	if lead.Instructions == "" || !strings.Contains(lead.Instructions, "Your personal goal is:") {
		t.Fatalf("its instructions were not carried: %q", lead.Instructions)
	}

	got = importAs(t, root, crew, "--save")
	for _, a := range got.Agents {
		if a.Declared || !a.Exists {
			t.Fatalf("%s was declared again over itself", a.Manifest.Name)
		}
	}
}

// Written out, an import is a declaration quilzo agent declare takes as it
// is, with the documents it came with beside it, and it never writes over
// a file already there.
func TestAnImportWrittenOutIsADeclarationAndOverwritesNothing(t *testing.T) {
	root, _ := identityStore(t)
	asDana(t, root)
	dir := t.TempDir()
	bedrock := filepath.Join("..", "..", "internal", "agentport", "testdata", "bedrock_agent.json")
	got := importAs(t, root, bedrock, "-o", dir)
	if len(got.Agents) != 1 || len(got.Agents[0].Written) != 2 {
		t.Fatalf("%+v", got.Agents)
	}
	for _, f := range []string{"order-support.json", "orders.openapi.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := agentDeclareFile(root, []string{filepath.Join(dir, "order-support.json")}); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	if m := set.Agents["order-support"]; m.Model == "" || len(m.AskFirst) == 0 {
		t.Fatalf("declared from the file: %+v", m)
	}
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(true)
	w.Out = &bytes.Buffer{}
	if err := agentImport(root, []string{bedrock, "-o", dir}); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("written over: %v", err)
	}
}

// Exported, a declaration is printed as the file itself, and what the
// other platform cannot hold is said beside it, not in it.
func TestAnExportPrintsTheFileAndSaysWhatItLeaves(t *testing.T) {
	root, _ := identityStore(t)
	old := w
	t.Cleanup(func() { w = old })
	var file, said bytes.Buffer
	w = out.New(false)
	w.Out, w.Err = &file, &said
	if err := agentExport(root, []string{"tidy", "--to", "claude-subagent"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(file.String(), "---\nname: tidy\n") || strings.Contains(file.String(), "left out") {
		t.Fatalf("the file:\n%s", file.String())
	}
	if !strings.Contains(said.String(), "autonomy") {
		t.Fatalf("what it leaves was not said: %q", said.String())
	}
	dir := t.TempDir()
	if err := agentExport(root, []string{"tidy", "--to", "adk", "-o", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tidy.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := agentExport(root, []string{"tidy", "--to", "bedrock"}); err == nil {
		t.Fatal("exported to a format only read")
	}
}
