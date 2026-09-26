// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package work tracks what a team is doing, with four states and no way to
// add a fifth.
//
// # Why four
//
// Every Jira administrator has had the conversation about how many statuses
// is too many. The advice is to stay under seven; the reality is workflows
// reading "in dev → dev done → ready for test → in test → ...", several
// different statuses that all mean To Do, and several more that all mean
// Done, and a transition menu with thirteen options in it. Atlassian's own
// community has a thread titled Worst Jira Admin Contest: Multiple Green
// Statuses. The usual diagnosis is that people are not thinking clearly.
//
// That diagnosis is wrong, and it is why the problem never goes away. Look
// at what the extra statuses are: "dev done" and "ready for test" are the
// same moment described from two sides. "In review", "awaiting QA",
// "blocked", "ready for deploy" are not states of the work at all. They are
// statements about who it is waiting on. Teams add statuses because a
// status field is the only place to put that, and one field is being asked
// to carry two independent facts — what state the work is in, and who is
// holding it up. Proliferation is the field splitting under the load.
//
// So this splits it deliberately. Four states, fixed, and an orthogonal
// Waiting that names a subject. "In review" becomes Doing, waiting on alan
// for a review. "Awaiting security sign-off" becomes Doing, waiting on the
// security team. The dozen statuses collapse into one dimension, and that
// dimension is a reference rather than a string — so "what is alan holding
// up" is a question with an answer, which is something no amount of Jira
// status design can give you, because a status is a word.
//
// The other direction fails too. Linear fixes the state model and adds no
// escape hatch, which works for most teams and leaves the rest modelling
// their process in issue titles. The escape hatch here is Waiting and the
// definition of done, both of which are structured, rather than a new word
// in a dropdown.
//
// # Why Done needs a definition
//
// Multiple green statuses exist for a reason: "done" means different things
// to different people, and a team that cannot say which one it means invents
// a status per meaning. Here the meaning is attached to the kind of work as
// a short list of requirements, once, rather than retyped as statuses. An
// item moves to Done when its list is satisfied — or with a requirement
// explicitly excused by somebody, which is recorded, because the difference
// between "we did it" and "we decided not to" is the only thing anybody
// wants to know a quarter later.
package work

import (
	"fmt"
	"strings"
	"time"
)

// State is what state the work is in. There are four and there is no way to
// add a fifth; see the package comment for why that is a feature.
type State string

const (
	// Todo: nobody has started.
	Todo State = "todo"
	// Doing: somebody has. This covers everything a team would otherwise
	// spell as in progress, in review, in test, awaiting deploy — those are
	// not states, they are what the work is waiting on.
	Doing State = "doing"
	// Done: the definition of done for this kind of work is satisfied.
	Done State = "done"
	// Dropped: it will not be done, and somebody said why.
	Dropped State = "dropped"
)

// States in the order a board shows them.
var States = []State{Todo, Doing, Done, Dropped}

// Known reports whether a state is one of the four.
func (s State) Known() bool {
	for _, c := range States {
		if c == s {
			return true
		}
	}
	return false
}

// Open reports whether the work is still live.
func (s State) Open() bool { return s == Todo || s == Doing }

// rank orders the states so forward and backward can be told apart.
func (s State) rank() int {
	switch s {
	case Todo:
		return 0
	case Doing:
		return 1
	case Done, Dropped:
		return 2
	}
	return -1
}

// Backward reports whether moving between two states loses ground.
//
// Worth naming because it is the move that needs a reason. An item that has
// been Done and is not any more is the single most informative event on a
// board, and in most trackers it is indistinguishable from any other
// transition — which is why teams invent a Reopened status to make it
// visible, and then have two statuses meaning Todo.
func (s State) Backward(to State) bool { return to.rank() < s.rank() }

// WaitKind is what sort of thing is being waited on.
type WaitKind string

const (
	// OnPerson: a named person has to do something.
	OnPerson WaitKind = "person"
	// OnTeam: a group has to, and nobody in particular owns it, which is
	// worth distinguishing because it is the kind that stalls.
	OnTeam WaitKind = "team"
	// OnThing: something outside this team — a vendor, a release, an
	// external dependency.
	OnThing WaitKind = "thing"
	// OnTime: a date has to arrive. The only kind nobody can be chased
	// about, and the only one that is not a risk.
	OnTime WaitKind = "time"
)

// Waiting is what is holding an item up.
//
// Orthogonal to State on purpose. An item can be Doing and waiting, which
// is the ordinary case and the one that every status-based tracker has to
// invent a word for.
type Waiting struct {
	Kind  WaitKind  `json:"kind"`
	On    string    `json:"on"`
	For   string    `json:"for"`
	Since time.Time `json:"since"`
	// Until is when a time-based wait ends. Only meaningful for OnTime.
	Until time.Time `json:"until,omitzero"`
}

// Validate refuses a wait nobody could act on.
func (w Waiting) Validate() error {
	switch w.Kind {
	case OnPerson, OnTeam, OnThing:
		if strings.TrimSpace(w.On) == "" {
			return fmt.Errorf("waiting on a %s means naming which one; "+
				"otherwise this is the word \"blocked\" again and nobody "+
				"can be asked about it", w.Kind)
		}
	case OnTime:
		if w.Until.IsZero() {
			return fmt.Errorf("waiting for a date means naming the date")
		}
	default:
		return fmt.Errorf("%q is not something to wait on; the kinds are "+
			"person, team, thing and time", w.Kind)
	}
	if strings.TrimSpace(w.For) == "" {
		return fmt.Errorf("say what is being waited for. \"waiting on " +
			"alan\" is a note to self; \"waiting on alan for a review\" is " +
			"something alan can act on")
	}
	return nil
}

// Held reports how long this has been waiting.
func (w Waiting) Held(at time.Time) time.Duration { return at.Sub(w.Since) }

// Chaseable reports whether there is somebody to ask.
//
// A wait on a date is not a risk and a wait on a team is the worst kind,
// because everybody assumes somebody else has it.
func (w Waiting) Chaseable() bool { return w.Kind != OnTime }

// OriginKind is where a piece of work came from.
type OriginKind string

const (
	// FromCall: somebody said it out loud, and internal/errand carries the
	// sentence.
	FromCall OriginKind = "call"
	// FromFinding: it came off the register in internal/finding.
	FromFinding OriginKind = "finding"
	// FromPerson: somebody typed it.
	FromPerson OriginKind = "person"
	// FromImport: it came from another tracker.
	FromImport OriginKind = "import"
)

// Origin is where an item came from.
//
// Required. An item with no origin is an item nobody can ask about, and
// every backlog that has become a graveyard is full of them.
type Origin struct {
	Kind OriginKind `json:"kind"`
	Ref  string     `json:"ref"`
	// Said is the sentence, for work that came out of a call.
	Said string    `json:"said,omitempty"`
	Who  string    `json:"who,omitempty"`
	At   time.Time `json:"at"`
}

// Validate refuses an origin that says nothing.
func (o Origin) Validate() error {
	switch o.Kind {
	case FromCall, FromFinding, FromPerson, FromImport:
	default:
		return fmt.Errorf("%q is not somewhere work comes from", o.Kind)
	}
	if strings.TrimSpace(o.Ref) == "" && strings.TrimSpace(o.Who) == "" {
		return fmt.Errorf("an origin names either what it came from or who " +
			"asked for it. Work whose origin is nobody is what a backlog " +
			"turns into")
	}
	return nil
}

// Move is one state change.
type Move struct {
	From State     `json:"from"`
	To   State     `json:"to"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	Why  string    `json:"why,omitempty"`
}

// Kind is a sort of work, and what finishing it means.
type Kind struct {
	Name string `json:"name"`
	// Requires is the definition of done: short, and written once for the
	// kind rather than retyped as a status per meaning.
	Requires []string `json:"requires,omitempty"`
}

// MaxRequires caps a definition of done.
//
// A definition of done with fifteen lines is a process document, and it
// will be excused into meaninglessness within a quarter. If finishing this
// kind of work genuinely takes fifteen checks, it is more than one kind of
// work.
const MaxRequires = 7

// Validate refuses a kind nobody could satisfy.
func (k Kind) Validate() error {
	if strings.TrimSpace(k.Name) == "" {
		return fmt.Errorf("a kind of work needs a name")
	}
	if len(k.Requires) > MaxRequires {
		return fmt.Errorf("%d requirements is a process document, not a "+
			"definition of done. The cap is %d; past that this is more "+
			"than one kind of work", len(k.Requires), MaxRequires)
	}
	seen := map[string]bool{}
	for _, r := range k.Requires {
		r = strings.TrimSpace(r)
		if r == "" {
			return fmt.Errorf("an empty requirement is one nobody can meet")
		}
		if seen[strings.ToLower(r)] {
			return fmt.Errorf("%q is in the definition of done twice", r)
		}
		seen[strings.ToLower(r)] = true
	}
	return nil
}
