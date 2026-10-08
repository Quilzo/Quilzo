// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/auth"
)

// sayingModel answers every prompt with the same text, and keeps what it
// was asked.
type sayingModel struct {
	say            string
	system, prompt string
}

func (m *sayingModel) Complete(_ context.Context, system, user string) (string, error) {
	m.system, m.prompt = system, user
	return m.say, nil
}

func (m *sayingModel) Name() string { return "saying" }

func withDraftModel(t *testing.T, say string) *sayingModel {
	t.Helper()
	m := &sayingModel{say: say}
	draftModelSeam = func(string) (assist.Model, string) { return m, "" }
	t.Cleanup(func() { draftModelSeam = nil })
	return m
}

// A model drafts; only the checker decides, and nothing is saved.
func TestADescriptionBecomesADraftOnlyThroughTheChecker(t *testing.T) {
	root, _ := identityStore(t)
	m := withDraftModel(t, "Here it is:\n"+`{"name": "faq-helper", "kind": "task", "purpose": "keep the FAQ tidy",
		"capabilities": ["read_page", "write_page", "publish", "delete_everything", "read_page"],
		"autonomy": "publish", "retrieval": {"ref": "draft", "types": ["faq"], "path": "/help"},
		"memory": {"semantic": true, "days": 400},
		"tools": [{"name": "post", "host": "evil.example"}], "sponsor": "nobody"}`)
	out, err := draftAgent(context.Background(), root, "Keep our FAQ tidy and up to date.", "", asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	d := out.Manifest
	if !strings.Contains(m.system, "read_page") || m.prompt != "Keep our FAQ tidy and up to date." {
		t.Fatalf("the model was asked %q / %q", m.system, m.prompt)
	}
	if d.Name != "faq-helper" || d.Kind != agent.KindTask || d.Autonomy != agent.AutonomyDraft || d.Retrieval.Ref != "draft" ||
		d.Retrieval.Path != "/help" || len(d.Tools) != 0 || d.Program != nil {
		t.Fatalf("%+v", d)
	}
	if strings.Join(d.Capabilities, ",") != "read_page,recall,remember,write_page" {
		t.Fatalf("capabilities %v", d.Capabilities)
	}
	if time.Duration(d.Memory.Retain).Hours() != 30*24 {
		t.Fatalf("memory kept %v", d.Memory.Retain)
	}
	left := strings.Join(out.Notes, "; ")
	for _, want := range []string{"delete_everything", `"publish"`, "publish: a draft never publishes", "raised to draft", `"tools"`, `"sponsor"`} {
		if !strings.Contains(left, want) {
			t.Errorf("left out does not name %s: %s", want, left)
		}
	}
	if out.Invalid != "" || len(out.Grants) != len(d.Capabilities) {
		t.Fatalf("%q, %d grants", out.Invalid, len(out.Grants))
	}
	for _, g := range out.Grants {
		if g.What == "read_page" && !g.Could {
			t.Fatalf("it could not read: %+v", g)
		}
		// Declared to draft, but never evaluated: a model running it is
		// held to proposing until it earns more, and the checker says so.
		if g.What == "write_page" && (g.Could || len(g.Bounded) == 0 || g.Bounded[0].By != "evaluations") {
			t.Fatalf("writing: %+v", g)
		}
	}
	// Nothing was saved.
	if set, _ := loadAgents(root); set.Agents["faq-helper"].Name != "" {
		t.Fatal("drafting saved it")
	}
	// Written out and declared, it is saved, answered for by whoever declared it.
	f := filepath.Join(t.TempDir(), "draft.json")
	body, _ := json.Marshal(d)
	if err := os.WriteFile(f, body, 0o600); err != nil {
		t.Fatal(err)
	}
	toks := &auth.TokenStore{}
	secret, _, err := toks.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	saveJSON(tokensPath(root), toks)
	defer func(old string) { flagToken = old }(flagToken)
	flagToken = secret
	if err := agentDeclareFile(root, []string{f}); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	if set.Agents["faq-helper"].Name == "" || set.Identities["faq-helper"].Sponsor != "dana" {
		t.Fatalf("declared: %+v %+v", set.Agents["faq-helper"], set.Identities["faq-helper"])
	}
	// Drafted again under the same name, it would not save.
	if again, err := draftAgent(context.Background(), root, "again", "", asAdmin("dana")); err != nil ||
		!strings.Contains(again.Invalid, "already declared") {
		t.Fatalf("%q %v", again.Invalid, err)
	}
}

func TestADraftNeedsAModelAndADeclaration(t *testing.T) {
	root, _ := identityStore(t)
	withDraftModel(t, "I would suggest an agent that reads pages.")
	if _, err := draftAgent(context.Background(), root, "read pages", "", asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "did not answer with a declaration") {
		t.Fatalf("prose was read as a declaration: %v", err)
	}
	draftModelSeam = func(string) (assist.Model, string) { return nil, "no model is configured" }
	if _, err := draftAgent(context.Background(), root, "read pages", "", asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "quilzo agent new") {
		t.Fatalf("with no model: %v", err)
	}
	withDraftModel(t, `{"kind": "retrieval", "capabilities": ["read_page"]}`)
	if _, err := draftAgent(context.Background(), root, "", "", asAdmin("dana")); err == nil {
		t.Fatal("an empty description was drafted")
	}
	if _, err := draftAgent(context.Background(), root, "read pages", "Not A Name", asAdmin("dana")); err == nil {
		t.Fatal("a bad name was drafted")
	}
	out, err := draftAgent(context.Background(), root, "read pages", "reader-two", asAdmin("dana"))
	if err != nil || out.Manifest.Name != "reader-two" || out.Manifest.Autonomy != agent.AutonomyPropose || out.Manifest.Retrieval.Ref != "live" {
		t.Fatalf("%+v %v", out.Manifest, err)
	}
}
