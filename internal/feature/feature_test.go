// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/schema"
)

func sample(t *testing.T) *Package {
	t.Helper()
	p, err := Decode(bytes.NewReader(Example()))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var checks = Checks{
	Agent:     func(agent.Manifest) error { return nil },
	URL:       func(u string) error { return nil },
	EventType: func(t string) bool { return t == "page.published" },
}

func TestTheExampleIsAUsablePackage(t *testing.T) {
	p := sample(t)
	if err := p.Validate(checks); err != nil {
		t.Fatal(err)
	}
	if got := len(p.Refs()); got != p.Blocks() || got != 4 {
		t.Errorf("refs %d, blocks %d; want 4 each", got, p.Blocks())
	}
}

func TestAnUnknownKeyIsRefusedNotDropped(t *testing.T) {
	raw := bytes.Replace(Example(), []byte(`"format": 1,`), []byte(`"format": 1, "grants": ["admin"],`), 1)
	if _, err := Decode(bytes.NewReader(raw)); err == nil {
		t.Fatal("a package asking for something this program does not know was read without complaint")
	}
	if _, err := Decode(strings.NewReader(`{"format":1} {"format":1}`)); err == nil {
		t.Error("two JSON values were read as one package")
	}
}

func TestAPackageThatReferencesWhatItDoesNotDeclareIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*Package){
		"collection bound to an undeclared type": func(p *Package) { p.Collections[0].Type = "nothing" },
		"listing over an undeclared collection":  func(p *Package) { p.Listings[0].Collection = "elsewhere" },
		"block declared twice":                   func(p *Package) { p.Types = append(p.Types, p.Types[0]) },
		"bad name":                               func(p *Package) { p.Name = "Lab Samples" },
		"bad version":                            func(p *Package) { p.Version = "v1" },
		"no purpose":                             func(p *Package) { p.Purpose = " " },
		"wrong format":                           func(p *Package) { p.Format = 2 },
		"invalid type":                           func(p *Package) { p.Types[0].Fields[0].Kind = "regex" },
		"a form with no notice": func(p *Package) {
			p.Forms = []form.Form{{Name: "ask", Fields: []form.Field{{Name: "q", Label: "Q", Kind: form.Line}}}}
		},
		"a webhook for an event that never happens": func(p *Package) {
			p.Webhooks = []Webhook{{URL: "https://hooks.example/x", Types: []string{"nothing.happened"}}}
		},
		"an agent the installation refuses": func(p *Package) {
			p.Agents = []agent.Manifest{{Name: "keeper"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := sample(t)
			mutate(p)
			c := checks
			c.Agent = func(agent.Manifest) error { return errRefused }
			if err := p.Validate(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

var errRefused = errString("refused")

type errString string

func (e errString) Error() string { return string(e) }

func TestTheDigestIgnoresTheSignatureAndNothingElse(t *testing.T) {
	p := sample(t)
	d1, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = &Signature{KeyID: "k", Ed25519: "x"}
	d2, _ := p.Digest()
	if d1 != d2 {
		t.Error("signing changed the digest it signs")
	}
	p.Purpose += "."
	if d3, _ := p.Digest(); d3 == d1 {
		t.Error("a changed purpose kept its digest")
	}
	again := sample(t)
	if d4, _ := again.Digest(); d4 != d1 {
		t.Error("the same package read twice has two digests")
	}
}

func TestTheCardIsWorkedOutFromThePackage(t *testing.T) {
	p := sample(t)
	c := p.MakeCard()
	// holder_email is an email field: personal data, so two people approve.
	if c.Approvers != 2 || c.Risk != "medium" {
		t.Errorf("risk %s, approvers %d; a feature storing addresses needs two", c.Risk, c.Approvers)
	}
	if len(c.Stores) != 1 || c.Stores[0].Flag != "personal" {
		t.Errorf("stores %+v", c.Stores)
	}
	if len(c.Shows) != 1 || !strings.Contains(c.Shows[0].Text, "members") ||
		!strings.Contains(c.Shows[0].Text, "code, material, received") {
		t.Errorf("shows %+v", c.Shows)
	}

	// Take the address away and nothing on the card needs a second person.
	p.Types[0].Fields = p.Types[0].Fields[:3]
	p.Listings[0].Fields = nil
	if c := p.MakeCard(); c.Approvers != 1 || c.Risk != "low" || len(c.Because) != 0 {
		t.Errorf("an inventory of materials: risk %s, approvers %d, because %v", c.Risk, c.Approvers, c.Because)
	}

	// A diagnosis field is special-category data: high risk.
	p.Types[0].Fields = append(p.Types[0].Fields, schema.Field{Name: "diagnosis", Kind: schema.Text})
	if c := p.MakeCard(); c.Risk != "high" || c.Approvers != 2 {
		t.Errorf("health data: risk %s", c.Risk)
	}
}

func TestTheCardNamesWhatLeavesAndWhatActs(t *testing.T) {
	p := sample(t)
	p.Webhooks = []Webhook{{URL: "https://hooks.example/samples", Types: []string{"page.published"}}}
	p.Agents = []agent.Manifest{{
		Name: "orderer", Kind: "task", Purpose: "Reorder materials", Autonomy: agent.AutonomyPublish,
		Capabilities: []string{"records_list"},
		Tools:        []agent.Tool{{Name: "order", Host: "shop.example", Writes: true}},
	}}
	c := p.MakeCard()
	if c.Risk != "high" {
		t.Errorf("an agent that orders on its own is risk %s", c.Risk)
	}
	sends := ""
	for _, l := range c.Sends {
		sends += l.Text + "\n"
	}
	for _, want := range []string{"hooks.example", "shop.example", "changes things there"} {
		if !strings.Contains(sends, want) {
			t.Errorf("the card does not say it reaches %s:\n%s", want, sends)
		}
	}
	if len(c.Agents) != 1 || c.Agents[0].Flag != "acts" {
		t.Errorf("agents %+v", c.Agents)
	}
}

func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestThePlanRefusesWhatSomebodyElseMade(t *testing.T) {
	p := sample(t)
	typ := Ref{"type", "sample"}
	col := Ref{"collection", "samples"}
	page := Ref{"page", "samples"}

	// First install: everything is added.
	pl := p.MakePlan(State{}, nil)
	if len(pl.Conflicts) != 0 || len(pl.Steps) != 4 {
		t.Fatalf("first install %+v", pl)
	}
	for _, s := range pl.Steps {
		if s.Action != Add {
			t.Errorf("%s: %s", s.Ref, s.Action)
		}
	}

	// A page of the same name somebody wrote by hand is theirs.
	st := State{Current: map[Ref]json.RawMessage{page: raw(t, map[string]any{"title": "Mine"})}}
	if pl := p.MakePlan(st, nil); len(pl.Conflicts) != 1 || !strings.Contains(pl.Conflicts[0], "a person") {
		t.Errorf("conflicts %v", pl.Conflicts)
	}
	st.Owner = map[Ref]string{page: "other-feature"}
	if pl := p.MakePlan(st, nil); len(pl.Conflicts) != 1 || !strings.Contains(pl.Conflicts[0], "other-feature") {
		t.Errorf("conflicts %v", pl.Conflicts)
	}

	// An upgrade: what it owns and has not changed is kept, a changed type
	// is a change, and what it no longer declares is removed.
	st = State{
		Current: map[Ref]json.RawMessage{typ: raw(t, p.Types[0]), col: raw(t, p.Collections[0])},
		Owner:   map[Ref]string{typ: "lab-samples", col: "lab-samples"},
	}
	p.Types[0].Description = "changed"
	owned := []Ref{typ, col, {"form", "old_form"}}
	got := map[string]string{}
	for _, s := range p.MakePlan(st, owned).Steps {
		got[s.Ref.String()] = s.Action
	}
	want := map[string]string{"type sample": Change, "collection samples": Keep, "form old_form": Remove,
		"listing available_samples": Add, "page samples": Add}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
}
