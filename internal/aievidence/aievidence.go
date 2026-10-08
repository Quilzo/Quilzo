// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package aievidence is the evidence an organisation using AI is asked
// for, produced from what its agents, chatbots and models actually did.
//
// Three documents. The EU AI Act's duties for whoever puts an AI system to
// use (a deployer, Article 26 and Article 50, with Article 4 and 27 beside
// them). ISO/IEC 42001's Annex A, as a statement of applicability. And an
// AI bill of materials, CycloneDX 1.6: the models, the agents, the data
// they answer from and remember, and the services they reach.
//
// Each is read from the same state the posture checks read and from the
// signed log, so a line here is a count of things that happened or a fact
// about how the program is set up, never a promise beside them. What only
// the organisation can say (that workers were told, that an impact
// assessment was made, that the policy was reviewed) is marked as theirs,
// with what Quilzo contributes to it, rather than claimed.
package aievidence

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fleet"
	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/posture"
)

// Statuses.
const (
	// Shown is a duty or control the evidence here supports.
	Shown = "shown"
	// Partly is one it supports with gaps, which are named.
	Partly = "partly"
	// Yours is one only the organisation can show; Quilzo's part is named.
	Yours = "yours"
)

// Route is a model route.
type Route struct {
	Name, Model, Host string
	Personal, Local   bool
}

// Chatbot is a chatbot and what it answers from.
type Chatbot struct {
	Name                                          string
	Public, Disclosed, UseModel, KeepInstructions bool
	Documents                                     int
}

// Inputs are what the evidence is read from.
type Inputs struct {
	Name      string
	Version   string
	From, Now time.Time
	State     posture.State
	Findings  []posture.Finding
	Agents    map[string]agent.Manifest
	Sponsors  map[string]string
	Standing  map[string]bool
	Routes    []Route
	Direct    string
	Chatbots  []Chatbot
	Tools     []agent.Integration
	External  []fleet.External
	// Uses is, for each caller of the models (agent:NAME, chatbot:NAME),
	// the routes it used in the period.
	Uses map[string][]string
}

// Counts are what happened in the period, from the signed log.
type Counts struct {
	Runs, ModelRuns, Actions, Refused, Approved, Declined, Canceled int
	Paused, Flagged, Remembered, Confirmed, Forgotten, Masked       int
	GatewayCalls, AppCalls, Tasks, Receipts                         int
	First                                                           time.Time
}

// Count reads the period's events.
func Count(events []audit.Event, from, to time.Time) Counts {
	var c Counts
	for _, e := range events {
		at, err := time.Parse(time.RFC3339, e.At)
		if err != nil {
			continue
		}
		if c.First.IsZero() || at.Before(c.First) {
			c.First = at
		}
		if at.Before(from) || at.After(to) {
			continue
		}
		switch e.Action {
		case "agent.run":
			c.Runs++
			if e.Kind == audit.KindAI {
				c.ModelRuns++
			}
		case "agent.action":
			c.Actions++
			if e.Outcome == audit.Denied {
				c.Refused++
			}
		case "agent.approve":
			c.Approved++
		case "agent.decline":
			c.Declined++
		case "agent.canceled":
			c.Canceled++
		case "memory.remembered":
			c.Remembered++
		case "memory.confirmed":
			c.Confirmed++
		case "memory.forgotten", "memory.deleted":
			c.Forgotten++
		case "model.masked":
			c.Masked++
		case "mcp.gateway":
			c.GatewayCalls++
		case "mcp.call":
			c.AppCalls++
		case "a2a.task":
			c.Tasks++
		case "shield.responded":
			if strings.Contains(e.Detail["did"], "paus") {
				c.Paused++
			}
		case "shield.applied":
			if e.Detail["kind"] == "agent" && e.Outcome == audit.Success {
				c.Paused++
			}
		case "agentwatch.flagged":
			c.Flagged++
		}
	}
	return c
}

// Item is a duty or a control, with its evidence.
type Item struct {
	Ref      string   `json:"ref"`
	Title    string   `json:"title"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
	Yours    string   `json:"yours,omitempty"`
	Findings []string `json:"findings,omitempty"`
}

// facts are what several items read.
type facts struct {
	in                                  Inputs
	c                                   Counts
	agents, sponsored, evaluated, steer int
	unsponsored, unevaluated            []string
	disclosed, undisclosed              []string
	publicBots                          int
}

func gather(in Inputs) facts {
	f := facts{in: in, c: Count(in.State.Audit, in.From, in.Now)}
	evals := map[string]posture.AgentEvalFact{}
	for _, e := range in.State.AI.Evals {
		evals[e.Name] = e
	}
	names := sortedNames(in.Agents)
	f.agents = len(names)
	for _, n := range names {
		if in.Sponsors[n] != "" && in.Standing[n] {
			f.sponsored++
		} else {
			f.unsponsored = append(f.unsponsored, n)
		}
		if e, ok := evals[n]; ok && !e.At.IsZero() {
			f.evaluated++
			f.steer += e.Hijacked
		} else {
			f.unevaluated = append(f.unevaluated, n)
		}
	}
	for _, b := range in.Chatbots {
		if !b.Public {
			continue
		}
		f.publicBots++
		if b.Disclosed {
			f.disclosed = append(f.disclosed, b.Name)
		} else {
			f.undisclosed = append(f.undisclosed, b.Name)
		}
	}
	return f
}

// findingsFor are the open posture findings that bear on a requirement.
func findingsFor(in Inputs, framework, ref string) []string {
	var out []string
	for _, f := range in.Findings {
		for _, r := range frameworks.Refs(f.Rule, f.Controls) {
			if r.Framework == framework && (r.ID == ref || strings.HasPrefix(ref, r.ID+"(")) {
				out = append(out, f.Rule+": "+f.Detail)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// settle makes an item partly shown when a finding bears on it.
func settle(it Item, in Inputs, framework string) Item {
	it.Findings = findingsFor(in, framework, it.Ref)
	if len(it.Findings) > 0 && it.Status == Shown {
		it.Status = Partly
	}
	return it
}

func sortedNames(m map[string]agent.Manifest) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func list(names []string) string {
	if len(names) > 8 {
		return strings.Join(names[:8], ", ") + " and " + itoa(len(names)-8) + " more"
	}
	return strings.Join(names, ", ")
}

func itoa(n int) string { return strconv.Itoa(n) }
