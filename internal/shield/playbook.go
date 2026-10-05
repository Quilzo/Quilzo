// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Response playbooks: what the shield does, decided beforehand.
//
// A playbook says: when this signal comes from one source (or one provider,
// or anywhere) this many times within this long, do these things; and if
// it comes again after that, do the next stage. Every part is data from a
// fixed list, as automations and detections are, so a playbook is read
// and reviewed as a diff and can do nothing it does not list. There is no
// expression, no script, and no step that cannot be undone: the actions
// are the shield's own, each with an end.
//
// A model never runs one. Agents may propose a change to a playbook, as
// they propose everything; the playbook acts on signals the servers raise
// themselves, so nothing a model reads can trigger a block.
//
// Changing a playbook's mode, or its definition, is proposed by one
// administrator and approved by another, because a playbook acts without
// asking anybody: changing one is changing what Quilzo does on its own.

// Signals are what the servers raise, the moment they see it.
var Signals = map[string]string{
	"signin-failures":    "sign-ins failing again and again from one source",
	"admin-hunt":         "the public site asked for the admin's addresses",
	"conversation-guess": "wrong secrets on chatbot conversations' addresses",
	"chatbot-injection":  "prompt-injection phrases sent to a chatbot",
	"form-spam":          "a form refusing submissions as spam",
	"decoy":              "a decoy was touched: a decoy token was tried, or a decoy address asked for",
	"agent-hijacked":     "an agent followed an instruction planted in what it read",
}

// Trait is how far a signal can be trusted, in CrowdSec's terms: Confidence
// 0-3 is how seldom it is raised by somebody innocent; Spoofable 0-3 is how
// easily somebody can raise it in another's name. A block needs a signal
// nobody can raise for somebody else, and a block on the first sighting
// needs one that is seldom innocent.
type Trait struct {
	Confidence int
	Spoofable  int
}

// Traits are the signals' traits. Every source-keyed signal here is raised
// on a connection the server itself accepted, so it cannot be raised in
// another's name: Spoofable 0.
var Traits = map[string]Trait{
	// A secret shaped like a token that was never issued here: one is a
	// typo, five in an hour is somebody guessing.
	"signin-failures": {Confidence: 1},
	// Three distinct admin addresses is somebody looking; one is somebody
	// on the wrong host, which the trigger's Distinct is for.
	"admin-hunt": {Confidence: 2},
	// A conversation's address carries a secret nobody types by accident;
	// a stale or cut-off link is the innocent case.
	"conversation-guess": {Confidence: 2},
	// Phrase matching: people quote these things innocently too.
	"chatbot-injection": {Confidence: 1},
	"form-spam":         {Confidence: 2},
	// Nothing legitimate uses a decoy.
	"decoy": {Confidence: 3},
	// Measured by the evaluation's planted instruction.
	"agent-hijacked": {Confidence: 3},
}

// Per says what a trigger counts by.
var Per = map[string]string{
	"source":   "one source",
	"provider": "one provider's network",
	"subject":  "one chatbot, form or agent",
	"any":      "anywhere",
}

// Actions are what a playbook's steps may do.
var Actions = map[string]string{
	"block-source":   "refuse the source",
	"block-network":  "refuse the source's network (/24, or /48)",
	"block-provider": "refuse the source's provider",
	"shield-feature": "turn a feature down or off",
	"lockdown":       "admin sign-in by passkey or single sign-on only",
	"freeze":         "stop publishing",
	"pause-agent":    "stop the agent running",
	"notify":         "tell the security contact",
	"open-case":      "open a case for a person to follow",
}

// Duration is a duration written as "15m", "1h", "24h".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Trigger is when a playbook acts.
type Trigger struct {
	Signal string   `json:"signal"`
	Per    string   `json:"per"`
	Count  int      `json:"count"`
	Within Duration `json:"within"`
	// Distinct counts different subjects (admin addresses asked for,
	// chatbots tried) rather than every signal, so asking for one address
	// again and again is one.
	Distinct bool `json:"distinct,omitempty"`
}

// Step is one thing a stage does.
type Step struct {
	Action string `json:"action"`
	// Where a block applies: admin, site or all.
	Where string `json:"where,omitempty"`
	// Feature is what shield-feature turns down; "subject" is the signal's
	// own chatbot or form.
	Feature string   `json:"feature,omitempty"`
	Level   string   `json:"level,omitempty"`
	For     Duration `json:"for,omitempty"`
}

// Stage is what a playbook does the nth time its trigger is met for the
// same source (or provider, or subject) within a day.
type Stage struct {
	Do []Step `json:"do"`
}

// Playbook is one response, decided beforehand.
type Playbook struct {
	Name   string  `json:"name"`
	Title  string  `json:"title"`
	Why    string  `json:"why,omitempty"`
	Mode   string  `json:"mode"` // watch, act, off
	On     Trigger `json:"on"`
	Stages []Stage `json:"stages"`
	// PerHour bounds how many stages it runs an hour; past it, it watches
	// and says so, so a flood of spoofed signals cannot block everybody.
	PerHour int `json:"per_hour,omitempty"`
	// Builtin marks one that ships with Quilzo.
	Builtin bool `json:"builtin,omitempty"`
}

// Escalate is how long a source's stage is remembered.
const Escalate = 24 * time.Hour

// DefaultPerHour is a playbook's hourly limit when it names none.
const DefaultPerHour = 30

// Validate checks a playbook is something the shield can do, as it says.
func (p Playbook) Validate() error {
	if !reName.MatchString(p.Name) {
		return fmt.Errorf("%q is not a name", p.Name)
	}
	if strings.TrimSpace(p.Title) == "" || len(p.Title) > 120 {
		return errors.New("a playbook needs a title of at most 120 characters")
	}
	if p.Mode != "watch" && p.Mode != "act" && p.Mode != "off" {
		return errors.New("a playbook watches, acts, or is off")
	}
	if _, ok := Signals[p.On.Signal]; !ok {
		return fmt.Errorf("%q is not a signal", p.On.Signal)
	}
	if _, ok := Per[p.On.Per]; !ok {
		return fmt.Errorf("%q is not a way to count", p.On.Per)
	}
	if p.On.Count < 1 || p.On.Count > 10000 {
		return errors.New("a trigger counts 1 to 10000 signals")
	}
	if w := time.Duration(p.On.Within); w < time.Second || w > Escalate {
		return errors.New("a trigger counts within a second to a day")
	}
	if len(p.Stages) == 0 || len(p.Stages) > 5 {
		return errors.New("a playbook has one to five stages")
	}
	tr := Traits[p.On.Signal]
	for i, st := range p.Stages {
		for _, step := range st.Do {
			if !strings.HasPrefix(step.Action, "block-") {
				continue
			}
			if tr.Spoofable > 0 {
				return fmt.Errorf("stage %d: %s can be raised in somebody else's name, so it may notify or turn a feature down, never block", i+1, p.On.Signal)
			}
			if p.On.Count == 1 && tr.Confidence < 2 {
				return fmt.Errorf("stage %d: %s is raised by innocent people too; a block needs more than one", i+1, p.On.Signal)
			}
		}
	}
	if p.PerHour < 0 || p.PerHour > 1000 {
		return errors.New("at most 1000 stages an hour")
	}
	for i, s := range p.Stages {
		if len(s.Do) == 0 || len(s.Do) > 8 {
			return fmt.Errorf("stage %d has one to eight steps", i+1)
		}
		for _, st := range s.Do {
			if err := st.validate(p.On); err != nil {
				return fmt.Errorf("stage %d: %w", i+1, err)
			}
		}
	}
	return nil
}

func (s Step) validate(on Trigger) error {
	if _, ok := Actions[s.Action]; !ok {
		return fmt.Errorf("%q is not an action", s.Action)
	}
	timed := s.Action != "notify" && s.Action != "open-case"
	if timed && (time.Duration(s.For) < time.Minute || time.Duration(s.For) > MaxAuto) {
		return fmt.Errorf("%s lasts a minute to %s", s.Action, MaxAuto)
	}
	if !timed && s.For != 0 {
		return fmt.Errorf("%s has no duration", s.Action)
	}
	needsSource := s.Action == "block-source" || s.Action == "block-network" || s.Action == "block-provider"
	if needsSource {
		if on.Per == "subject" {
			return errors.New("a block needs a source, and this playbook counts by subject")
		}
		if s.Where != Admin && s.Where != Site && s.Where != All {
			return errors.New("a block is on the admin, the site, or both")
		}
	} else if s.Where != "" {
		return fmt.Errorf("%s does not take where", s.Action)
	}
	switch s.Action {
	case "shield-feature":
		f := s.Feature
		if f == "subject" {
			if on.Signal != "chatbot-injection" && on.Signal != "form-spam" {
				return errors.New("only a chatbot's or a form's signal has a subject to shield")
			}
		} else if _, ok := Features[f]; !ok || f == "chatbot" || f == "form" {
			return fmt.Errorf("%q is not a feature to shield", f)
		}
		if s.Level != Off && s.Level != Limited {
			return errors.New("a feature is turned off or limited")
		}
		if s.Level == Limited && !(f == "chatbots" || (f == "subject" && on.Signal == "chatbot-injection")) {
			return errors.New("only a chatbot can be limited to quoting pages")
		}
	case "pause-agent":
		if on.Signal != "agent-hijacked" {
			return errors.New("an agent is paused on an agent's signal")
		}
	default:
		if s.Feature != "" || s.Level != "" {
			return fmt.Errorf("%s does not take a feature", s.Action)
		}
	}
	return nil
}

// Builtins are the playbooks Quilzo ships. The ones that block a single
// source or touch nothing but an agent act; the ones that reach many
// people at once (a provider, the whole admin, every chatbot) watch until
// two administrators turn them on, with a dry run to show what they would
// have done.
func Builtins() []Playbook {
	h := func(d time.Duration) Duration { return Duration(d) }
	return []Playbook{
		{Name: "signin-attack", Title: "Repeated failed sign-ins from one source", Mode: "act", Builtin: true,
			Why: "Guessing tokens: five secrets never issued here within an hour, which is where ASVS asks for a reaction. A token mistyped once, or one that expired, is not counted. The throttle slows it; this stops it on the admin, for longer each time it comes back, and everywhere on the third.",
			On:  Trigger{Signal: "signin-failures", Per: "source", Count: 5, Within: h(time.Hour)},
			Stages: []Stage{
				{Do: []Step{{Action: "block-source", Where: Admin, For: h(time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: Admin, For: h(4 * time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: All, For: h(24 * time.Hour)}, {Action: "notify"}}},
			}},
		{Name: "signin-attack-spread", Title: "Failed sign-ins spread across one provider", Mode: "watch", Builtin: true,
			Why: "Credential stuffing from many addresses at one hosting provider, each staying under the per-source limit.",
			On:  Trigger{Signal: "signin-failures", Per: "provider", Count: 25, Within: h(time.Hour)},
			Stages: []Stage{
				{Do: []Step{{Action: "block-provider", Where: Admin, For: h(time.Hour)}, {Action: "notify"}}},
				{Do: []Step{{Action: "lockdown", For: h(6 * time.Hour)}, {Action: "open-case"}}},
			}},
		{Name: "admin-hunting", Title: "Looking for the admin on the public site", Mode: "act", Builtin: true,
			Why: "The admin is not on the public site; asking for three of its addresses is reconnaissance. Somebody typing the wrong host asks for one. Blocks stay on the site: the admin is only closed to somebody who also fails to sign in.",
			On:  Trigger{Signal: "admin-hunt", Per: "source", Count: 3, Within: h(10 * time.Minute), Distinct: true},
			Stages: []Stage{
				{Do: []Step{{Action: "block-source", Where: Site, For: h(time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: Site, For: h(4 * time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: Site, For: h(24 * time.Hour)}}},
			}},
		{Name: "conversation-guessing", Title: "Guessing chatbot conversations", Mode: "act", Builtin: true,
			Why: "Trying to read another visitor's conversation with the business. One wrong address is a stale link; three is guessing.",
			On:  Trigger{Signal: "conversation-guess", Per: "source", Count: 3, Within: h(time.Hour)},
			Stages: []Stage{
				{Do: []Step{{Action: "block-source", Where: Site, For: h(time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: Site, For: h(6 * time.Hour)}}},
			}},
		{Name: "chatbot-injection", Title: "Prompt injection against a chatbot", Mode: "act", Builtin: true,
			Why: "The chatbot cannot be widened by what a visitor writes; somebody trying again and again is still somebody to stop.",
			On:  Trigger{Signal: "chatbot-injection", Per: "source", Count: 3, Within: h(10 * time.Minute)},
			Stages: []Stage{
				{Do: []Step{{Action: "block-source", Where: Site, For: h(time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: Site, For: h(4 * time.Hour)}}},
				{Do: []Step{{Action: "block-source", Where: Site, For: h(24 * time.Hour)}}},
			}},
		{Name: "chatbot-flood", Title: "Injection attempts against a chatbot from everywhere", Mode: "watch", Builtin: true,
			Why: "Many sources at once: quoting pages only, with no model, takes away what they are after and the cost of it.",
			On:  Trigger{Signal: "chatbot-injection", Per: "subject", Count: 30, Within: h(10 * time.Minute)},
			Stages: []Stage{
				{Do: []Step{{Action: "shield-feature", Feature: "subject", Level: Limited, For: h(time.Hour)}, {Action: "notify"}}},
			}},
		{Name: "form-flood", Title: "A form flooded with spam", Mode: "watch", Builtin: true,
			Why: "Spam the form already refuses, in volume: closing the form for a while costs the attacker their script.",
			On:  Trigger{Signal: "form-spam", Per: "subject", Count: 100, Within: h(10 * time.Minute)},
			Stages: []Stage{
				{Do: []Step{{Action: "shield-feature", Feature: "subject", Level: Off, For: h(30 * time.Minute)}, {Action: "notify"}}},
			}},
		{Name: "decoy-touched", Title: "A decoy was touched", Mode: "act", Builtin: true,
			Why: "Nothing legitimate uses a decoy, so this is somebody with a stolen copy or somebody exploring: they are shut out everywhere, and a person is told where the leak was.",
			On:  Trigger{Signal: "decoy", Per: "source", Count: 1, Within: h(time.Hour)},
			Stages: []Stage{
				{Do: []Step{{Action: "block-source", Where: All, For: h(24 * time.Hour)}, {Action: "notify"}, {Action: "open-case"}}},
			}},
		{Name: "decoy-lockdown", Title: "A decoy was touched: lock the admin down", Mode: "watch", Builtin: true,
			Why: "Whoever has the decoy may have the real secrets kept beside it. Locking the admin to passkeys and single sign-on refuses every token made before, which stops integrations too; so it watches until two administrators decide it should act.",
			On:  Trigger{Signal: "decoy", Per: "any", Count: 1, Within: h(time.Hour)},
			Stages: []Stage{
				{Do: []Step{{Action: "lockdown", For: h(6 * time.Hour)}, {Action: "notify"}}},
				{Do: []Step{{Action: "lockdown", For: h(24 * time.Hour)}, {Action: "freeze", For: h(6 * time.Hour)}, {Action: "notify"}}},
			}},
		{Name: "agent-steered", Title: "An agent followed a planted instruction", Mode: "act", Builtin: true,
			Why: "Text it reads can steer it; it does not run until somebody narrows what it may do.",
			On:  Trigger{Signal: "agent-hijacked", Per: "subject", Count: 1, Within: h(time.Hour)},
			Stages: []Stage{
				{Do: []Step{{Action: "pause-agent", For: h(24 * time.Hour)}, {Action: "notify"}}},
			}},
	}
}
