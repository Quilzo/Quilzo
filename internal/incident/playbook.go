// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Playbooks: what to do, in what order, written down before it is needed.
//
// A playbook here does nothing. It is a list of steps a person carries
// out, in their own tools, and ticks off with their name. That is a
// decision and not a gap: a step that disables an account or isolates a
// laptop needs this program to hold a credential that can do those things
// to anybody, and the connectors are read-only so that it holds none.
//
// What it gives an incident is the part that goes wrong without it: the
// step nobody did because everybody thought somebody had, the step done
// out of order, and afterwards no record of who did which. So:
//
//   - A run is proposed, then approved, then worked. Whoever proposed it
//     does not also approve it, unless they are commanding the incident.
//   - A step waits for the steps it needs.
//   - Done means somebody says so by name, with what they saw where the
//     step asks for it. Skipped takes a reason. Both are in the record.
//   - A step that can be reversed says how, and undoing it is recorded
//     the same way.
//   - The steps are copied into the incident when the run starts. Editing
//     the playbook later does not rewrite what an incident was told to do.

// Step is one thing to do.
type Step struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Why is required. A step with no reason is the first one skipped
	// under pressure, and nobody can tell whether that mattered.
	Why string `json:"why"`
	// Needs are the steps that come first.
	Needs []string `json:"needs,omitempty"`
	// Evidence says finishing the step takes a note of what was seen.
	Evidence bool `json:"evidence,omitempty"`
	// Undo is how to reverse it, for a step that can be.
	Undo string `json:"undo,omitempty"`
}

// Playbook is a named list of steps.
type Playbook struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// For says what kind of incident it is for.
	For   string `json:"for"`
	Steps []Step `json:"steps"`
}

var playbookID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// MaxSteps bounds one playbook.
const MaxSteps = 60

// Validate refuses a playbook that cannot be worked.
func (p Playbook) Validate() error {
	if !playbookID.MatchString(p.ID) {
		return fmt.Errorf("%q is not a playbook identifier: lower-case "+
			"letters, digits and hyphens", p.ID)
	}
	if strings.TrimSpace(p.Title) == "" || strings.TrimSpace(p.For) == "" {
		return fmt.Errorf("%s needs a title and a line saying what it is for",
			p.ID)
	}
	if len(p.Steps) == 0 || len(p.Steps) > MaxSteps {
		return fmt.Errorf("%s has %d steps; between 1 and %d", p.ID,
			len(p.Steps), MaxSteps)
	}
	at := map[string]int{}
	for n, s := range p.Steps {
		if !playbookID.MatchString(s.ID) {
			return fmt.Errorf("%s: %q is not a step identifier", p.ID, s.ID)
		}
		if _, dup := at[s.ID]; dup {
			return fmt.Errorf("%s has two steps called %s", p.ID, s.ID)
		}
		at[s.ID] = n
		if strings.TrimSpace(s.Title) == "" {
			return fmt.Errorf("%s: step %s has no title", p.ID, s.ID)
		}
		if strings.TrimSpace(s.Why) == "" {
			return fmt.Errorf("%s: step %s does not say why. A step with "+
				"no reason is the first one skipped under pressure",
				p.ID, s.ID)
		}
		if len(s.Title) > 200 || len(s.Why) > 600 || len(s.Undo) > 600 {
			return fmt.Errorf("%s: step %s is too long to read in an "+
				"incident", p.ID, s.ID)
		}
	}
	for n, s := range p.Steps {
		for _, need := range s.Needs {
			m, ok := at[need]
			if !ok {
				return fmt.Errorf("%s: step %s needs %s, which is not a "+
					"step", p.ID, s.ID, need)
			}
			// Needs point backwards. It makes a cycle impossible and makes
			// the list read in the order it is worked.
			if m >= n {
				return fmt.Errorf("%s: step %s needs %s, which comes "+
					"after it. Put the steps in the order they are done",
					p.ID, s.ID, need)
			}
		}
	}
	return nil
}

// ReadPlaybook parses and validates one.
func ReadPlaybook(in []byte) (Playbook, error) {
	var p Playbook
	if len(in) > 256<<10 {
		return p, fmt.Errorf("a playbook of %d bytes", len(in))
	}
	if err := json.Unmarshal(in, &p); err != nil {
		return p, fmt.Errorf("this is not a playbook: %w", err)
	}
	return p, p.Validate()
}

//go:embed playbooks/*.json
var shipped embed.FS

// Shipped is the playbooks that come with the program, by identifier.
func Shipped() ([]Playbook, error) {
	entries, err := shipped.ReadDir("playbooks")
	if err != nil {
		return nil, err
	}
	var out []Playbook
	for _, e := range entries {
		b, err := shipped.ReadFile("playbooks/" + e.Name())
		if err != nil {
			return nil, err
		}
		p, err := ReadPlaybook(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if p.ID+".json" != e.Name() {
			return nil, fmt.Errorf("%s holds the playbook %s", e.Name(), p.ID)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

// StepState is where one step of a run has got to.
type StepState string

const (
	Todo    StepState = "todo"
	Done    StepState = "done"
	Skipped StepState = "skipped"
	// Undone is done and then reversed. It can be done again.
	Undone StepState = "undone"
)

// RunStep is a step as one incident was given it, and what became of it.
type RunStep struct {
	Step
	State StepState `json:"state"`
	By    string    `json:"by,omitempty"`
	At    time.Time `json:"at,omitzero"`
	Note  string    `json:"note,omitempty"`
}

// Run is a playbook applied to one incident.
type Run struct {
	// ID is the playbook's, which is also the run's: a playbook runs once
	// per incident.
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Proposed Moment    `json:"proposed"`
	Approved *Moment   `json:"approved,omitempty"`
	Steps    []RunStep `json:"steps"`
}

// Left is how many steps are neither done nor skipped.
func (r Run) Left() int {
	n := 0
	for _, s := range r.Steps {
		if s.State == Todo || s.State == Undone {
			n++
		}
	}
	return n
}

// Waiting reports the steps a step is still waiting for.
func (r Run) Waiting(step string) []string {
	settled := map[string]bool{}
	for _, s := range r.Steps {
		settled[s.ID] = s.State == Done || s.State == Skipped
	}
	var out []string
	for _, s := range r.Steps {
		if s.ID != step {
			continue
		}
		for _, n := range s.Needs {
			if !settled[n] {
				out = append(out, n)
			}
		}
	}
	return out
}

// MaxRuns bounds how many playbooks one incident runs.
const MaxRuns = 10

func (i *Incident) run(id string) *Run {
	for n := range i.Runs {
		if i.Runs[n].ID == id {
			return &i.Runs[n]
		}
	}
	return nil
}

// Propose attaches a playbook. Nothing in it can be worked until it is
// approved.
func (i *Incident) Propose(p Playbook, by, why string, at time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if i.run(p.ID) != nil {
		return fmt.Errorf("%s is already part of this", p.ID)
	}
	if len(i.Runs) >= MaxRuns {
		return fmt.Errorf("this already runs %d playbooks", MaxRuns)
	}
	if strings.TrimSpace(why) == "" {
		return fmt.Errorf("say why this playbook fits. The one that " +
			"nearly fits is how the wrong steps get done carefully")
	}
	r := Run{ID: p.ID, Title: p.Title, Proposed: Moment{At: at.UTC(),
		By: by, Why: strings.TrimSpace(why)}}
	for _, s := range p.Steps {
		r.Steps = append(r.Steps, RunStep{Step: s, State: Todo})
	}
	i.Runs = append(i.Runs, r)
	i.note(by, "proposed playbook "+p.ID+": "+strings.TrimSpace(why), at)
	return nil
}

// Approve lets a proposed run be worked.
//
// By somebody other than whoever proposed it, or by the commander. Two
// people, or the one person whose job is to decide: a list of actions one
// person both wrote down and agreed to has been agreed to by nobody.
func (i *Incident) Approve(id, by string, at time.Time) error {
	r := i.run(id)
	if r == nil {
		return fmt.Errorf("%s is not part of this", id)
	}
	if r.Approved != nil {
		return fmt.Errorf("%s was approved by %s", id, r.Approved.By)
	}
	commanding := strings.EqualFold(strings.TrimSpace(i.Filled[Commander]), by)
	if !commanding && strings.EqualFold(r.Proposed.By, by) {
		return fmt.Errorf("%s proposed this. It is approved by somebody "+
			"else, or by whoever is commanding the incident", by)
	}
	r.Approved = &Moment{At: at.UTC(), By: by, Why: "approved"}
	i.note(by, "approved playbook "+id, at)
	return nil
}

// Withdraw takes back a proposal nobody approved. An approved run is not
// withdrawn: its steps are skipped, each with a reason.
func (i *Incident) Withdraw(id, by, why string, at time.Time) error {
	for n, r := range i.Runs {
		if r.ID != id {
			continue
		}
		if r.Approved != nil {
			return fmt.Errorf("%s was approved. Skip the steps that do "+
				"not apply, each with its reason", id)
		}
		if strings.TrimSpace(why) == "" {
			return fmt.Errorf("say why it does not fit after all")
		}
		i.Runs = append(i.Runs[:n:n], i.Runs[n+1:]...)
		i.note(by, "withdrew playbook "+id+": "+strings.TrimSpace(why), at)
		return nil
	}
	return fmt.Errorf("%s is not part of this", id)
}

// Work records what became of one step: done, skip or undo.
func (i *Incident) Work(id, step, outcome, by, note string,
	at time.Time) error {

	r := i.run(id)
	if r == nil {
		return fmt.Errorf("%s is not part of this", id)
	}
	if r.Approved == nil {
		return fmt.Errorf("%s has not been approved. A list of actions "+
			"somebody proposed is not yet a list anybody agreed to", id)
	}
	var s *RunStep
	for n := range r.Steps {
		if r.Steps[n].ID == step {
			s = &r.Steps[n]
		}
	}
	if s == nil {
		return fmt.Errorf("%s has no step %s", id, step)
	}
	note = strings.TrimSpace(note)
	switch outcome {
	case "done":
		if s.State == Done || s.State == Skipped {
			return fmt.Errorf("%s is already %s, by %s", step, s.State, s.By)
		}
		if w := r.Waiting(step); len(w) > 0 {
			return fmt.Errorf("%s waits for %s", step, strings.Join(w, ", "))
		}
		if s.Evidence && note == "" {
			return fmt.Errorf("%s asks what was seen. \"Done\" with "+
				"nothing beside it is what gets written when it was not",
				step)
		}
		s.State = Done
		i.note(by, fmt.Sprintf("did %s/%s: %s", id, step, orDash(note)), at)
	case "skip":
		if s.State == Done || s.State == Skipped {
			return fmt.Errorf("%s is already %s, by %s", step, s.State, s.By)
		}
		if note == "" {
			return fmt.Errorf("skipping %s takes a reason", step)
		}
		s.State = Skipped
		i.note(by, fmt.Sprintf("skipped %s/%s: %s", id, step, note), at)
	case "undo":
		if s.State != Done {
			return fmt.Errorf("%s has not been done", step)
		}
		if strings.TrimSpace(s.Undo) == "" {
			return fmt.Errorf("%s does not say how it is reversed, so "+
				"recording it as reversed would record a guess", step)
		}
		if note == "" {
			return fmt.Errorf("undoing %s takes a reason", step)
		}
		s.State = Undone
		i.note(by, fmt.Sprintf("undid %s/%s: %s", id, step, note), at)
	default:
		return fmt.Errorf("a step is done, skipped or undone")
	}
	s.By, s.At, s.Note = by, at.UTC(), note
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// StepsLeft names every step of every approved run that is neither done
// nor skipped, and every run nobody approved.
func (i *Incident) StepsLeft() []string {
	var out []string
	for _, r := range i.Runs {
		if r.Approved == nil {
			out = append(out, r.ID+" (proposed, never approved)")
			continue
		}
		for _, s := range r.Steps {
			if s.State == Todo || s.State == Undone {
				out = append(out, r.ID+"/"+s.ID)
			}
		}
	}
	return out
}
