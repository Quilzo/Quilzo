// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package automate runs rules of the form "when this happens, if this is
// true, do these things": the response half of the security operations,
// as Sentinel's automation rules, Splunk's and Google's playbooks and Tines'
// stories do it.
//
// # A rule is data, and so is everything it can do
//
// When is one kind of event — a sign-in, a finding, a device, a person.
// If is a list of comparisons, every one of which must hold, over the
// fields that kind of event carries; there is no expression language, for
// the reason detections have none (internal/detect): a rule is reviewed as
// data with a diff and cannot run anything but what it lists. Then is an
// ordered list of steps, each an action from a fixed catalogue with
// parameters from fixed choices. No part of any request is built from text
// in the event: an action acts on the event's subject, by an identifier
// matched against a pattern before it is used (see internal/action).
//
// # Three modes, because acting is the thing to be careful with
//
//   - watch: the rule runs and records what it would have done, and does
//     nothing. A new rule starts here, so it can be judged against real
//     traffic before it touches anybody.
//   - ask: it records what it would do and waits for a person to approve.
//   - act: it does it, then and there.
//
// An hourly limit per rule stops one noisy source from suspending
// everybody: past it, the rule falls back to watching and says so.
//
// # Real time
//
// Handle runs synchronously, in whatever request raised the event. A
// sign-in is judged while it is being made, so "step up" means that sign-in
// does not get a session until the person proves it is them.
package automate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Event is something that happened, as automation sees it.
type Event struct {
	Kind string `json:"kind"`
	// Subject is who or what it is about: a person's sign-in name, a
	// machine, a finding's entity.
	Subject string `json:"subject"`
	At      time.Time
	// Fields are what the event says, by the names Kinds lists.
	Fields map[string]string `json:"fields,omitempty"`
	// Summary is the event in a sentence, for the history.
	Summary string `json:"summary"`
}

// Kinds are the events there are and the fields each carries, which is
// everything a condition may test.
var Kinds = map[string][]string{
	"signin":  {"signal", "risk", "score", "how", "role", "country", "from", "to", "km", "kmh", "history", "network", "asn", "provider", "anon", "device", "source"},
	"finding": {"source", "severity", "kind", "title", "issuer"},
	"device":  {"control", "severity", "os", "support", "owner"},
	"person":  {"band", "department", "reason"},
	"signal": {"type", "severity", "source", "issuer", "current_level", "previous_level", "change_type",
		"credential_type", "current_status", "principal", "initiator", "reason"},
}

// KindNames are the kinds in words.
var KindNames = map[string]string{
	"signin": "Somebody signs in", "finding": "A finding is raised",
	"device": "A machine fails a control", "person": "Something is said about a person",
	"signal": "Another system reports something",
}

// Ops are the comparisons a condition may make.
var Ops = map[string]string{
	"is": "is", "is-not": "is not", "one-of": "is one of", "not-one-of": "is not one of",
	"at-least": "is at least", "at-most": "is at most", "contains": "contains",
}

// OpOrder is Ops in the order a person reads them, "is" first.
var OpOrder = []string{"is", "is-not", "one-of", "not-one-of", "at-least", "at-most", "contains"}

// Condition is one comparison.
type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// Holds reports whether the comparison is true of the event.
func (c Condition) Holds(ev Event) bool {
	got := ev.Fields[c.Field]
	// A sign-in carries every signal it raised, comma-separated: "signal
	// is new-country" holds when new-country is among them.
	if c.Field == "signal" && strings.Contains(got, ",") {
		in := map[string]bool{}
		for _, s := range strings.Split(got, ",") {
			in[strings.ToLower(strings.TrimSpace(s))] = true
		}
		any := func(list string) bool {
			for _, v := range strings.Split(list, ",") {
				if in[strings.ToLower(strings.TrimSpace(v))] {
					return true
				}
			}
			return false
		}
		switch c.Op {
		case "is", "one-of":
			return any(c.Value)
		case "is-not", "not-one-of":
			return !any(c.Value)
		}
	}
	switch c.Op {
	case "is":
		return strings.EqualFold(got, c.Value)
	case "is-not":
		return !strings.EqualFold(got, c.Value)
	case "one-of", "not-one-of":
		in := false
		for _, v := range strings.Split(c.Value, ",") {
			if strings.EqualFold(strings.TrimSpace(v), got) {
				in = true
			}
		}
		return in == (c.Op == "one-of")
	case "contains":
		return strings.Contains(strings.ToLower(got), strings.ToLower(c.Value))
	case "at-least", "at-most":
		g, gerr := rank(c.Field, got)
		w, werr := rank(c.Field, c.Value)
		if gerr != nil || werr != nil {
			return false
		}
		if c.Op == "at-least" {
			return g >= w
		}
		return g <= w
	}
	return false
}

// severities rank in order, so "at least high" means high or critical.
var severities = map[string]float64{"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func rank(field, v string) (float64, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if field == "severity" || field == "band" || field == "risk" || field == "current_level" || field == "previous_level" {
		if n, ok := severities[v]; ok {
			return n, nil
		}
		return 0, fmt.Errorf("%q is not a severity", v)
	}
	return strconv.ParseFloat(v, 64)
}

// Step is one thing a rule does.
type Step struct {
	Action string            `json:"action"`
	With   map[string]string `json:"with,omitempty"`
}

// Rule is one automation.
type Rule struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	Mode    string      `json:"mode"` // watch, ask, act
	When    string      `json:"when"`
	If      []Condition `json:"if,omitempty"`
	Then    []Step      `json:"then"`
	PerHour int         `json:"per_hour,omitempty"`
	Note    string      `json:"note,omitempty"`
	By      string      `json:"by,omitempty"`
	At      time.Time   `json:"at"`
}

// Modes, in words.
var Modes = map[string]string{
	"watch": "Watch: record what it would do", "ask": "Ask: wait for approval", "act": "Act: do it at once",
}

// DefaultPerHour is the limit a rule has when it names none.
const DefaultPerHour = 20

// Param is one choice an action takes.
type Param struct {
	Name    string
	Choices []string
}

// Action is one thing a rule can do.
type Action struct {
	ID    string
	Name  string
	Does  string
	Undo  string
	Kinds []string
	// Params are its choices; With may name only these, with these values.
	Params []Param
	// Inline is done by the request a sign-in came from (stepping it up),
	// not by Run; for any other event Run does it.
	Inline bool
	// Access marks an action on somebody's access — their sessions, their
	// accounts — which only an administrator of the whole site may set a
	// rule to take, or approve.
	Access bool
	// Run does it, saying what happened.
	Run func(ev Event, with map[string]string) (string, error)
}

func (a Action) applies(kind string) bool {
	for _, k := range a.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Validate refuses a rule that could not be what it says.
func (r Rule) Validate(actions map[string]Action) error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("a rule needs a name somebody can read")
	}
	// Bounded, so a rules file stays a thing a person reads.
	switch {
	case len(r.Name) > 120:
		return errors.New("a name is a line: 120 characters at most")
	case len(r.Note) > 1000:
		return errors.New("a note is a paragraph: 1000 characters at most")
	case len(r.If) > 10 || len(r.Then) > 10:
		return errors.New("a rule has at most ten conditions and ten steps; split it")
	}
	for _, c := range r.If {
		if len(c.Value) > 500 {
			return fmt.Errorf("the value for %s is longer than 500 characters", c.Field)
		}
	}
	if _, ok := Modes[r.Mode]; !ok {
		return fmt.Errorf("mode %q is not watch, ask or act", r.Mode)
	}
	fields, ok := Kinds[r.When]
	if !ok {
		return fmt.Errorf("%q is not something that happens; try signin, finding, device, person or signal", r.When)
	}
	for _, c := range r.If {
		known := false
		for _, f := range fields {
			known = known || f == c.Field
		}
		if !known {
			return fmt.Errorf("a %s has no field %q; it has %s", r.When, c.Field, strings.Join(fields, ", "))
		}
		if _, ok := Ops[c.Op]; !ok {
			return fmt.Errorf("%q is not a comparison", c.Op)
		}
		if c.Op == "at-least" || c.Op == "at-most" {
			if _, err := rank(c.Field, c.Value); err != nil {
				return fmt.Errorf("%s %s needs a number or a severity: %w", c.Field, Ops[c.Op], err)
			}
		}
	}
	if len(r.Then) == 0 {
		return errors.New("a rule needs at least one thing to do")
	}
	for _, s := range r.Then {
		a, ok := actions[s.Action]
		if !ok {
			return fmt.Errorf("%q is not an action this program has", s.Action)
		}
		if !a.applies(r.When) {
			return fmt.Errorf("%s cannot be done when %s", a.Name, strings.ToLower(KindNames[r.When]))
		}
		for k, v := range s.With {
			okParam := false
			for _, p := range a.Params {
				if p.Name != k {
					continue
				}
				for _, c := range p.Choices {
					okParam = okParam || c == v
				}
			}
			if !okParam {
				return fmt.Errorf("%s does not take %s=%s", a.Name, k, v)
			}
		}
	}
	if r.PerHour < 0 {
		return errors.New("the hourly limit cannot be negative")
	}
	return nil
}

// Matches reports whether the rule is for this event.
func (r Rule) Matches(ev Event) bool {
	if !r.Enabled || r.When != ev.Kind {
		return false
	}
	for _, c := range r.If {
		if !c.Holds(ev) {
			return false
		}
	}
	return true
}

// StepRun is what one step did.
type StepRun struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	// With is the parameters it was decided with, so approving it later
	// does what was shown, whatever the rule says by then.
	With map[string]string `json:"with,omitempty"`
	OK   bool              `json:"ok"`
	Said string            `json:"said"`
	// Pending is a step decided and not yet done.
	Pending bool `json:"pending,omitempty"`
}

// Run is one rule firing.
type Run struct {
	ID    string    `json:"id"`
	Rule  string    `json:"rule"`
	Name  string    `json:"name"`
	Mode  string    `json:"mode"`
	At    time.Time `json:"at"`
	Event Event     `json:"event"`
	Steps []StepRun `json:"steps"`
	// State: done, watched, waiting, approved, declined, limited.
	State string `json:"state"`
	By    string `json:"by,omitempty"`
}

// Access reports whether any of the run's steps acts on somebody's access.
func (r Run) Access(actions map[string]Action) bool {
	for _, s := range r.Steps {
		if actions[s.Action].Access {
			return true
		}
	}
	return false
}

// Access reports whether the rule acts on somebody's access when it fires
// in a mode that does anything.
func (r Rule) Access(actions map[string]Action) bool {
	if r.Mode == "watch" {
		return false
	}
	for _, s := range r.Then {
		if actions[s.Action].Access {
			return true
		}
	}
	return false
}

// Outcome is what Handle tells the request the event came from.
type Outcome struct {
	StepUp  bool
	Reasons []string
	Runs    []Run
}

// Engine runs rules against events and keeps what it did.
//
// Its file is written by more than one process — the admin, as sign-ins
// arrive, and the command line, when the tools are read — so every change
// is made under a lock file as well as a mutex, and nothing slow is done
// while either is held: rules are matched and their runs recorded under
// the lock, the actions run after it is released, and what they said is
// written back under it again. A slow mail server cannot hold a sign-in.
type Engine struct {
	Path    string // rules and runs, as one JSON file
	Actions map[string]Action
	Now     func() time.Time
	// Async runs actions in the background, for a server answering a
	// request; a command line run does them before it returns.
	Async bool
	// Done, when set, is told when a background run has finished, for
	// tests.
	Done func(Run)
	mu   sync.Mutex
}

type state struct {
	Rules []Rule `json:"rules"`
	Runs  []Run  `json:"runs"`
}

// MaxRuns bounds the history.
const MaxRuns = 2000

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) load() (*state, error) {
	st := &state{}
	b, err := os.ReadFile(e.Path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", e.Path, err)
	}
	return st, nil
}

func (e *Engine) save(st *state) error {
	if len(st.Runs) > MaxRuns {
		st.Runs = st.Runs[len(st.Runs)-MaxRuns:]
	}
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	return atomicfile.Write(e.Path, b, 0o600)
}

// lockWait is how long a change waits for another process's; lockStale is
// how old a lock file must be to be taken as abandoned by a process that
// died holding it.
const (
	lockWait  = 5 * time.Second
	lockStale = time.Minute
)

// change runs fn on the state under both locks, and saves when it says to.
func (e *Engine) change(fn func(*state) (bool, error)) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	unlock, err := lockFile(e.Path+".lock", lockWait, lockStale)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := e.load()
	if err != nil {
		return err
	}
	dirty, err := fn(st)
	if err != nil || !dirty {
		return err
	}
	return e.save(st)
}

// lockFile takes a lock file, waiting a little for another holder and
// taking over one left by a process that died.
func lockFile(path string, wait, stale time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > stale {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s is held by another process", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Rules lists them.
func (e *Engine) Rules() ([]Rule, error) {
	var out []Rule
	err := e.change(func(st *state) (bool, error) {
		out = st.Rules
		return false, nil
	})
	return out, err
}

// Runs lists the history, newest first.
func (e *Engine) Runs() ([]Run, error) {
	var out []Run
	err := e.change(func(st *state) (bool, error) {
		out = append([]Run(nil), st.Runs...)
		return false, nil
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, err
}

// Save adds a rule, or replaces the one with its ID. Two rules may not
// share a name: they would read as one in the history.
func (e *Engine) Save(r Rule, by string) (Rule, error) {
	if err := r.Validate(e.Actions); err != nil {
		return r, err
	}
	err := e.change(func(st *state) (bool, error) {
		r.By, r.At = by, e.now()
		if r.ID == "" {
			r.ID = newID()
		}
		for _, x := range st.Rules {
			if x.ID != r.ID && strings.EqualFold(strings.TrimSpace(x.Name), strings.TrimSpace(r.Name)) {
				return false, fmt.Errorf("a rule called %q already exists", r.Name)
			}
		}
		replaced := false
		for i := range st.Rules {
			if st.Rules[i].ID == r.ID {
				st.Rules[i], replaced = r, true
			}
		}
		if !replaced {
			st.Rules = append(st.Rules, r)
		}
		return true, nil
	})
	return r, err
}

// Remove deletes a rule; its history stays.
func (e *Engine) Remove(id string) error {
	return e.change(func(st *state) (bool, error) {
		kept := st.Rules[:0]
		for _, r := range st.Rules {
			if r.ID != id {
				kept = append(kept, r)
			}
		}
		if len(kept) == len(st.Rules) {
			return false, errors.New("no such rule")
		}
		st.Rules = kept
		return true, nil
	})
}

// Handle runs every rule that matches the event, now. What stops a sign-in
// is decided before it returns; what acts elsewhere runs after the runs are
// recorded, in the background when Async is set.
func (e *Engine) Handle(ev Event) (Outcome, error) {
	if ev.At.IsZero() {
		ev.At = e.now()
	}
	var out Outcome
	err := e.change(func(st *state) (bool, error) {
		for _, r := range st.Rules {
			if !r.Matches(ev) {
				continue
			}
			run := Run{ID: newID(), Rule: r.ID, Name: r.Name, Mode: r.Mode, At: e.now(), Event: ev}
			limit := r.PerHour
			if limit == 0 {
				limit = DefaultPerHour
			}
			mode := r.Mode
			recent := 0
			for _, past := range st.Runs {
				if past.Rule == r.ID && e.now().Sub(past.At) < time.Hour && past.State != "watched" && past.State != "limited" {
					recent++
				}
			}
			if mode != "watch" && recent >= limit {
				mode, run.State = "watch", "limited"
			}
			for _, s := range r.Then {
				a := e.Actions[s.Action]
				sr := StepRun{Action: s.Action, Name: a.Name, With: s.With}
				switch {
				case mode == "watch":
					sr.Said = "would have: " + a.Does
				case mode == "ask":
					sr.Said = "waiting for approval: " + a.Does
				case a.Inline && ev.Kind == "signin":
					// What happened to this sign-in, not what the action
					// does in general; and when several rules hold the same
					// one, the history names the rule that held it first.
					sr.OK, sr.Said = true, "held this sign-in until it is confirmed"
					if len(out.Reasons) > 0 {
						sr.Said = "already held by " + out.Reasons[0]
					}
					out.StepUp = true
					out.Reasons = append(out.Reasons, r.Name)
				case a.Run == nil:
					sr.Said = "nothing to do this with here"
				default:
					sr.Pending, sr.Said = true, "doing it"
				}
				run.Steps = append(run.Steps, sr)
			}
			if run.State == "" {
				run.State = map[string]string{"watch": "watched", "ask": "waiting", "act": "done"}[mode]
			}
			st.Runs = append(st.Runs, run)
			out.Runs = append(out.Runs, run)
		}
		return len(out.Runs) > 0, nil
	})
	if err != nil {
		return Outcome{}, err
	}
	for i := range out.Runs {
		if pending(out.Runs[i]) {
			if e.Async {
				// Its own copy of the steps: the caller reads the ones
				// returned while the background writes these.
				r := out.Runs[i]
				r.Steps = append([]StepRun(nil), r.Steps...)
				go e.perform(r)
			} else {
				out.Runs[i] = e.perform(out.Runs[i])
			}
		}
	}
	return out, nil
}

func pending(r Run) bool {
	for _, s := range r.Steps {
		if s.Pending {
			return true
		}
	}
	return false
}

// perform does a run's pending steps, outside every lock, and writes what
// each said back to the run. A step that panics is a failed step, not a
// stopped program.
func (e *Engine) perform(run Run) Run {
	for i := range run.Steps {
		sr := &run.Steps[i]
		if !sr.Pending {
			continue
		}
		sr.Pending = false
		a, ok := e.Actions[sr.Action]
		if !ok || a.Run == nil {
			sr.Said = "this action no longer exists"
			continue
		}
		said, err := safeRun(a, run.Event, sr.With)
		sr.OK, sr.Said = err == nil, said
		if err != nil {
			sr.Said = err.Error()
		}
	}
	_ = e.change(func(st *state) (bool, error) {
		for i := range st.Runs {
			if st.Runs[i].ID == run.ID {
				st.Runs[i].Steps = run.Steps
				st.Runs[i].State = run.State
				return true, nil
			}
		}
		return false, nil
	})
	if e.Done != nil {
		e.Done(run)
	}
	return run
}

func safeRun(a Action, ev Event, with map[string]string) (said string, err error) {
	defer func() {
		if p := recover(); p != nil {
			said, err = "", fmt.Errorf("%s failed: %v", a.Name, p)
		}
	}()
	return a.Run(ev, with)
}

// Decide approves or declines a waiting run; approving does its steps,
// with the parameters they were decided with. An inline step cannot be
// approved afterwards — the sign-in it would have stopped is long gone —
// so it is reported as not done.
func (e *Engine) Decide(id string, approve bool, by string) (Run, error) {
	var run Run
	err := e.change(func(st *state) (bool, error) {
		for i := range st.Runs {
			r := &st.Runs[i]
			if r.ID != id {
				continue
			}
			if r.State != "waiting" {
				return false, fmt.Errorf("this run is %s, not waiting", r.State)
			}
			r.By = by
			if !approve {
				r.State = "declined"
				for j := range r.Steps {
					r.Steps[j].Said = "declined by " + by
				}
				run = *r
				return true, nil
			}
			r.State = "approved"
			for j := range r.Steps {
				sr := &r.Steps[j]
				a, ok := e.Actions[sr.Action]
				switch {
				case !ok:
					sr.Said = "this action no longer exists"
				case a.Inline && r.Event.Kind == "signin":
					sr.Said = "not done: it acts on the sign-in as it happens, which has passed"
				default:
					sr.Pending, sr.Said = true, "doing it"
				}
			}
			run = *r
			return true, nil
		}
		return false, errors.New("no such run")
	})
	if err != nil || run.State != "approved" {
		return run, err
	}
	// Approval is a person waiting on the answer, so it is done now.
	return e.perform(run), nil
}
