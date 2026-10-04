// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuiltinsAreValidAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, pb := range Builtins() {
		if err := pb.Validate(); err != nil {
			t.Errorf("%s: %v", pb.Name, err)
		}
		if seen[pb.Name] || !pb.Builtin || pb.Why == "" {
			t.Errorf("%s: duplicate, unmarked or unexplained", pb.Name)
		}
		seen[pb.Name] = true
		// The ones that reach many people at once ship watching.
		for _, st := range pb.Stages {
			for _, s := range st.Do {
				wide := s.Action == "block-provider" || s.Action == "block-network" ||
					(s.Action == "shield-feature" && pb.On.Per != "source") ||
					(s.Action == "lockdown" && pb.On.Signal != "decoy")
				if wide && pb.Mode == "act" {
					t.Errorf("%s acts on %s from the start", pb.Name, s.Action)
				}
			}
		}
	}
}

func valid() Playbook {
	return Playbook{Name: "mine", Title: "Mine", Mode: "act",
		On:     Trigger{Signal: "chatbot-injection", Per: "source", Count: 2, Within: Duration(time.Minute)},
		Stages: []Stage{{Do: []Step{{Action: "block-source", Where: Site, For: Duration(time.Hour)}}}}}
}

func TestPlaybookValidation(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	step := func(s Step) func(*Playbook) { return func(p *Playbook) { p.Stages[0].Do[0] = s } }
	h := Duration(time.Hour)
	bad := map[string]func(*Playbook){
		"name":               func(p *Playbook) { p.Name = "Mine!" },
		"no title":           func(p *Playbook) { p.Title = " " },
		"long title":         func(p *Playbook) { p.Title = strings.Repeat("x", 121) },
		"mode":               func(p *Playbook) { p.Mode = "ask" },
		"signal":             func(p *Playbook) { p.On.Signal = "anything" },
		"per":                func(p *Playbook) { p.On.Per = "person" },
		"count zero":         func(p *Playbook) { p.On.Count = 0 },
		"count huge":         func(p *Playbook) { p.On.Count = 10001 },
		"within zero":        func(p *Playbook) { p.On.Within = 0 },
		"within two days":    func(p *Playbook) { p.On.Within = Duration(48 * time.Hour) },
		"no stages":          func(p *Playbook) { p.Stages = nil },
		"six stages":         func(p *Playbook) { p.Stages = make([]Stage, 6) },
		"hourly negative":    func(p *Playbook) { p.PerHour = -1 },
		"hourly huge":        func(p *Playbook) { p.PerHour = 1001 },
		"empty stage":        func(p *Playbook) { p.Stages[0].Do = nil },
		"nine steps":         func(p *Playbook) { p.Stages[0].Do = make([]Step, 9) },
		"unknown action":     step(Step{Action: "delete-page", For: h}),
		"no end":             step(Step{Action: "block-source", Where: Site}),
		"beyond a day":       step(Step{Action: "block-source", Where: Site, For: Duration(25 * time.Hour)}),
		"seconds":            step(Step{Action: "freeze", For: Duration(30 * time.Second)}),
		"notify with end":    step(Step{Action: "notify", For: h}),
		"block nowhere":      step(Step{Action: "block-source", For: h}),
		"freeze somewhere":   step(Step{Action: "freeze", Where: Site, For: h}),
		"freeze a feature":   step(Step{Action: "freeze", Feature: "forms", For: h}),
		"feature unknown":    step(Step{Action: "shield-feature", Feature: "signin", Level: Off, For: h}),
		"feature by name":    step(Step{Action: "shield-feature", Feature: "chatbot", Level: Off, For: h}),
		"feature no level":   step(Step{Action: "shield-feature", Feature: "forms", For: h}),
		"forms limited":      step(Step{Action: "shield-feature", Feature: "forms", Level: Limited, For: h}),
		"pause wrong signal": step(Step{Action: "pause-agent", For: h}),
		"subject wrong kind": func(p *Playbook) {
			p.On.Signal = "admin-hunt"
			step(Step{Action: "shield-feature", Feature: "subject", Level: Off, For: h})(p)
		},
		"block by subject": func(p *Playbook) { p.On.Per = "subject" },
		"limit form subject": func(p *Playbook) {
			p.On.Signal = "form-spam"
			step(Step{Action: "shield-feature", Feature: "subject", Level: Limited, For: h})(p)
		},
		"provider wide where": step(Step{Action: "block-provider", Where: "everywhere", For: h}),
	}
	for name, f := range bad {
		p := valid()
		p.Stages = []Stage{{Do: append([]Step(nil), p.Stages[0].Do...)}}
		f(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := map[string]func(*Playbook){
		"limit chatbot subject": func(p *Playbook) {
			p.On.Per = "subject"
			step(Step{Action: "shield-feature", Feature: "subject", Level: Limited, For: h})(p)
		},
		"form off": func(p *Playbook) {
			p.On.Signal, p.On.Per = "form-spam", "subject"
			step(Step{Action: "shield-feature", Feature: "subject", Level: Off, For: h})(p)
		},
		"pause":          func(p *Playbook) { p.On.Signal = "agent-hijacked"; step(Step{Action: "pause-agent", For: h})(p) },
		"provider":       func(p *Playbook) { p.On.Per = "provider" },
		"network":        step(Step{Action: "block-network", Where: All, For: h}),
		"one minute":     step(Step{Action: "lockdown", For: Duration(time.Minute)}),
		"a day":          step(Step{Action: "lockdown", For: Duration(24 * time.Hour)}),
		"every chatbot":  step(Step{Action: "shield-feature", Feature: "chatbots", Level: Limited, For: h}),
		"open case only": step(Step{Action: "open-case"}),
	}
	for name, f := range good {
		p := valid()
		p.Stages = []Stage{{Do: append([]Step(nil), p.Stages[0].Do...)}}
		f(&p)
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDurationsAreWrittenAsPeopleWriteThem(t *testing.T) {
	b, err := json.Marshal(valid())
	if err != nil || !strings.Contains(string(b), `"within":"1m0s"`) || !strings.Contains(string(b), `"for":"1h0m0s"`) {
		t.Fatalf("%s %v", b, err)
	}
	var p Playbook
	if err := json.Unmarshal([]byte(`{"on":{"within":"15m"}}`), &p); err != nil || time.Duration(p.On.Within) != 15*time.Minute {
		t.Fatalf("%v %v", p.On.Within, err)
	}
	for _, bad := range []string{`{"on":{"within":"soon"}}`, `{"on":{"within":900}}`} {
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
