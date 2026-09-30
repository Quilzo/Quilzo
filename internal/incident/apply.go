// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// An incident kept between runs, and the one way anything changes it.
//
// The command line and the screen both go through Apply, so there is one
// list of what can be done to an incident and one place each thing is
// checked. A screen with its own idea of what closing means is how a case
// ends up closed over an obligation the command line would have refused.

// idShape is what an incident's identifier looks like. It becomes a file
// name, so it is checked wherever one arrives from outside.
var idShape = regexp.MustCompile(`^inc-[0-9]{8}-[0-9a-f]{6}$`)

// ValidID reports whether s can name an incident.
func ValidID(s string) bool { return idShape.MatchString(s) }

// NewID names an incident declared at a moment. suffix is six hex digits
// the caller draws at random: the day makes it readable and the rest makes
// two declared in the same minute different.
func NewID(at time.Time, suffix string) (string, error) {
	id := "inc-" + at.UTC().Format("20060102") + "-" + strings.ToLower(suffix)
	if !ValidID(id) {
		return "", fmt.Errorf("%q is not an incident identifier", id)
	}
	return id, nil
}

// Scopes is every sector or jurisdiction the obligations table knows, in
// order, for a form that offers them.
func Scopes() []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range Obligations {
		if !seen[o.Scope] {
			seen[o.Scope] = true
			out = append(out, o.Scope)
		}
	}
	sort.Strings(out)
	return out
}

// Restore puts back what a stored incident does not carry: the order of
// its record, which is the order it was written in, and the maps an empty
// one leaves out.
func (i *Incident) Restore() {
	for n := range i.Log {
		i.Log[n].seq = uint64(n + 1)
	}
	i.seq = uint64(len(i.Log))
	if i.Moments == nil {
		i.Moments = map[Trigger]Moment{}
	}
	if i.Filled == nil {
		i.Filled = map[Role]string{}
	}
	if i.Discharged == nil {
		i.Discharged = map[string]Moment{}
	}
}

// MaxLinked bounds how many findings one incident gathers. Past this it is
// not an incident, it is a second queue.
const MaxLinked = 500

// Link attaches a finding. The finding is named, not copied: what it says
// was written by whoever could reach a log, and it stays where that is
// known about it.
func (i *Incident) Link(finding, by string, at time.Time) error {
	finding = strings.TrimSpace(finding)
	if finding == "" {
		return fmt.Errorf("which finding")
	}
	for _, f := range i.Findings {
		if f == finding {
			return fmt.Errorf("%s is already part of this", finding)
		}
	}
	if len(i.Findings) >= MaxLinked {
		return fmt.Errorf("this already gathers %d findings", MaxLinked)
	}
	i.Findings = append(i.Findings, finding)
	i.note(by, "linked finding "+finding, at)
	return nil
}

// Unlink detaches a finding, and says so in the record.
func (i *Incident) Unlink(finding, by string, at time.Time) error {
	for n, f := range i.Findings {
		if f == finding {
			i.Findings = append(i.Findings[:n:n], i.Findings[n+1:]...)
			i.note(by, "unlinked finding "+finding, at)
			return nil
		}
	}
	return fmt.Errorf("%s is not part of this", finding)
}

// Action is one thing somebody does to an incident.
type Action struct {
	// Do is what: note, assign, decide, discharge, waive, link, unlink,
	// watch, reopen or close.
	Do string `json:"do"`
	// Text is the words that go with it: the note, the reason, the cause.
	Text    string  `json:"text,omitempty"`
	Role    Role    `json:"role,omitempty"`
	Who     string  `json:"who,omitempty"`
	Trigger Trigger `json:"trigger,omitempty"`
	Regime  string  `json:"regime,omitempty"`
	Finding string  `json:"finding,omitempty"`
	// Actions is what changes as a result, for closing.
	Actions []string `json:"actions,omitempty"`
}

// Decides reports whether an action is one of the judgements that start,
// settle or end something — the ones that are a person's and never a
// model's.
func (a Action) Decides() bool {
	switch a.Do {
	case "decide", "discharge", "waive", "close":
		return true
	}
	return false
}

// MaxText bounds what somebody writes into the record in one go.
const MaxText = 4000

// Apply does one thing to an incident.
func (i *Incident) Apply(a Action, by string, at time.Time) error {
	by = strings.TrimSpace(by)
	if by == "" {
		return fmt.Errorf("somebody does this")
	}
	if len(a.Text) > MaxText {
		return fmt.Errorf("that is %d characters; the record takes %d at "+
			"a time", len(a.Text), MaxText)
	}
	if i.State == Closed && a.Do != "note" {
		return fmt.Errorf("this is closed. What happened afterwards can " +
			"be noted; the rest of the record stands as it was")
	}
	switch a.Do {
	case "note":
		return i.Note(by, a.Text, at)
	case "assign":
		return i.Assign(a.Role, a.Who, at)
	case "decide":
		return i.Decide(a.Trigger, by, a.Text, at)
	case "discharge":
		return i.Discharge(a.Regime, by, a.Text, at)
	case "waive":
		return i.Waive(a.Regime, by, a.Text, at)
	case "link":
		return i.Link(a.Finding, by, at)
	case "unlink":
		return i.Unlink(a.Finding, by, at)
	case "watch":
		if strings.TrimSpace(a.Text) == "" {
			return fmt.Errorf("say what makes this look fixed")
		}
		return i.Watch(by, a.Text, at)
	case "reopen":
		if i.State != Watching {
			return fmt.Errorf("this is not being watched")
		}
		if strings.TrimSpace(a.Text) == "" {
			return fmt.Errorf("say what came back")
		}
		i.State = Open
		i.note(by, "reopened: "+strings.TrimSpace(a.Text), at)
		return nil
	case "close":
		var actions []string
		for _, x := range a.Actions {
			if x = strings.TrimSpace(x); x != "" {
				actions = append(actions, x)
			}
		}
		return i.Close(by, a.Text, actions, at)
	}
	return fmt.Errorf("%q is not something done to an incident", a.Do)
}

// Next is the duty that matters soonest: the latest one overdue, else the
// nearest deadline still running. Nothing when no clock is running.
func (i *Incident) Next(now time.Time) (Duty, bool) {
	var best Duty
	found := false
	for _, d := range i.Duties(now) {
		if !d.Started || d.Done || d.Waived || d.Within == 0 {
			continue
		}
		if !found || d.Left < best.Left {
			best, found = d, true
		}
	}
	return best, found
}
