// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package incident runs the response to something going wrong, and keeps
// the several clocks that start when it does.
//
// # Every deadline runs from a decision, not from an investigation
//
// That is the whole of the regulatory problem and it is not obvious. GDPR
// Article 33's seventy-two hours run from awareness that a breach has
// likely occurred. DORA's four hours run from classifying an incident as
// major. The SEC's four business days run from determining that an incident
// is material. NIS2's twenty-four hours run from awareness of a significant
// incident. None of them run from the end of the investigation, and every
// one of them starts at a moment somebody decided something.
//
// So the moment is recorded as a decision, with who made it and why, and
// each regime's clock hangs off its own moment. One incident therefore has
// several clocks that start at different times, which is the situation
// every team is actually in and almost no tool represents.
//
// The failure this is built against is subtler than missing a deadline. A
// team that never formally determined materiality believes no clock is
// running, and is right, and is also three weeks into an incident that a
// regulator will say was plainly material on day one. So Duties reports the
// obligations whose clock has not started *and names the decision that would
// start it* — because "nothing is due" and "nobody has made the call that
// makes something due" look identical on a dashboard and are not the same
// situation at all.
//
// # A page nobody answered is the failure
//
// Escalation that does not escalate is the other ordinary disaster. A page
// goes out, nobody acknowledges, and the system considers itself to have
// notified somebody. It has not: it has sent a message. Acknowledgement
// here is a person saying they have it, escalation continues until one
// does, and an unacknowledged page is reported as what it is rather than
// counted as a notification.
package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Grade is how bad this is, which decides how much of the organisation
// wakes up.
type Grade string

const (
	// Sev1: service is down or data is leaving. Everybody.
	Sev1 Grade = "sev1"
	// Sev2: serious and contained, or serious and not yet understood.
	Sev2 Grade = "sev2"
	// Sev3: degraded, working around it.
	Sev3 Grade = "sev3"
	// Sev4: worth recording, not worth waking anybody.
	Sev4 Grade = "sev4"
)

// Grades in order of severity.
var Grades = []Grade{Sev1, Sev2, Sev3, Sev4}

// Known reports whether a grade is one of the four.
func (g Grade) Known() bool {
	for _, c := range Grades {
		if c == g {
			return true
		}
	}
	return false
}

// Wakes reports whether this grade pages people out of hours.
func (g Grade) Wakes() bool { return g == Sev1 || g == Sev2 }

// Role is a job during an incident.
//
// Three, from incident command practice, and the split is the point: the
// person deciding what to do cannot also be the person writing down what
// happened and talking to everybody who wants an update, and every incident
// where one person did all three is an incident with no record of itself.
type Role string

const (
	// Commander decides. One, and never more than one.
	Commander Role = "commander"
	// Comms talks to everybody outside the response, so the commander does
	// not spend the incident answering the same question.
	Comms Role = "comms"
	// Scribe writes down what happened as it happens, because afterwards
	// nobody remembers the order.
	Scribe Role = "scribe"
)

// Roles in the order they are filled.
var Roles = []Role{Commander, Comms, Scribe}

// Trigger is a decision that starts a clock.
type Trigger string

const (
	// Aware: somebody concluded a breach has likely occurred. GDPR's
	// seventy-two hours run from here, and NIS2's twenty-four.
	Aware Trigger = "aware"
	// Major: the incident was classified major under DORA.
	Major Trigger = "major"
	// Material: the incident was determined material for disclosure.
	Material Trigger = "material"
	// Personal: personal data was confirmed involved.
	Personal Trigger = "personal"
	// Health: protected health information was confirmed involved.
	Health Trigger = "health"
)

// Triggers is every decision that starts something.
var Triggers = []Trigger{Aware, Major, Material, Personal, Health}

// Means says what making this decision commits to, so somebody can see
// what they are about to start before they start it.
func (t Trigger) Means() string {
	switch t {
	case Aware:
		return "somebody concluded a breach has likely occurred. Not that " +
			"it is confirmed and not that it is understood — the standard " +
			"is likelihood, and waiting for certainty is how the seventy-" +
			"two hours are spent"
	case Major:
		return "the incident meets the classification thresholds for a " +
			"major one. Four hours from here, which is the shortest clock " +
			"in the set"
	case Material:
		return "a reasonable investor would consider this important. The " +
			"determination itself is required to be made without " +
			"unreasonable delay, so not making it is not a way of avoiding " +
			"it"
	case Personal:
		return "personal data was involved, confirmed rather than assumed"
	case Health:
		return "protected health information was involved"
	}
	return string(t)
}

// Moment is a decision and when it was made.
type Moment struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
	// Why is required. A clock that started for no recorded reason is one
	// nobody can defend the start of afterwards, and the start is the
	// thing a regulator asks about.
	Why string `json:"why"`
}

// Entry is one line of the incident's record.
type Entry struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	What string    `json:"what"`
	seq  uint64
}

// Order is where an entry sits in the incident's own sequence.
func (e Entry) Order() uint64 { return e.seq }

// State is where an incident has got to.
type State string

const (
	// Open: being worked on.
	Open State = "open"
	// Watching: believed fixed, not yet trusted.
	Watching State = "watching"
	// Closed: done, with a cause and the obligations accounted for.
	Closed State = "closed"
)

// Incident is one thing going wrong, and everything that follows from it.
type Incident struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Grade    Grade     `json:"grade"`
	State    State     `json:"state"`
	Declared time.Time `json:"declared"`
	By       string    `json:"by"`

	// Moments are the decisions that start clocks, by trigger.
	Moments map[Trigger]Moment `json:"moments,omitempty"`
	// Filled is who holds each role.
	Filled map[Role]string `json:"filled,omitempty"`
	// Regimes are the jurisdictions and sectors this organisation is in,
	// which decides which duties apply at all.
	Regimes []string `json:"regimes,omitempty"`

	Pages []Page  `json:"pages,omitempty"`
	Log   []Entry `json:"log,omitempty"`

	// Cause and Actions are required to close.
	Cause   string   `json:"cause,omitempty"`
	Actions []string `json:"actions,omitempty"`
	// Discharged records each duty that was met or explicitly ruled out.
	Discharged map[string]Moment `json:"discharged,omitempty"`

	seq uint64
}

// Declare opens an incident.
func Declare(id, title string, g Grade, by string,
	at time.Time, regimes ...string) (*Incident, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("an incident needs an identifier and a title")
	}
	if !g.Known() {
		return nil, fmt.Errorf("%q is not a grade; they are %s", g,
			gradeList())
	}
	if strings.TrimSpace(by) == "" {
		return nil, fmt.Errorf("somebody declares an incident")
	}
	i := &Incident{
		ID: id, Title: strings.TrimSpace(title), Grade: g, State: Open,
		Declared: at.UTC(), By: strings.TrimSpace(by),
		Moments: map[Trigger]Moment{}, Filled: map[Role]string{},
		Discharged: map[string]Moment{},
	}
	for _, r := range regimes {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			i.Regimes = append(i.Regimes, r)
		}
	}
	sort.Strings(i.Regimes)
	i.note(by, fmt.Sprintf("declared %s", g), at)
	return i, nil
}

func gradeList() string {
	out := make([]string, 0, len(Grades))
	for _, g := range Grades {
		out = append(out, string(g))
	}
	return strings.Join(out, ", ")
}

func (i *Incident) next() uint64 { i.seq++; return i.seq }

func (i *Incident) note(by, what string, at time.Time) {
	i.Log = append(i.Log, Entry{
		At: at.UTC(), By: strings.TrimSpace(by), What: what, seq: i.next(),
	})
}

// Note records something that happened.
func (i *Incident) Note(by, what string, at time.Time) error {
	if strings.TrimSpace(what) == "" || strings.TrimSpace(by) == "" {
		return fmt.Errorf("an entry is somebody saying something")
	}
	i.note(by, strings.TrimSpace(what), at)
	return nil
}

// Assign fills a role.
//
// One commander. A second is not a redundancy, it is two people giving
// different instructions to the same responders, which is the failure mode
// incident command exists to prevent.
func (i *Incident) Assign(r Role, who string, at time.Time) error {
	known := false
	for _, c := range Roles {
		if c == r {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%q is not a role; they are commander, comms "+
			"and scribe", r)
	}
	who = strings.TrimSpace(who)
	if who == "" {
		return fmt.Errorf("a role is somebody's")
	}
	if r != Commander {
		for other, holder := range i.Filled {
			if other != r && strings.EqualFold(holder, who) &&
				other == Commander {
				return fmt.Errorf(
					"%s is already the commander. The person deciding what "+
						"to do cannot also be the one writing down what "+
						"happened and answering everybody who wants an "+
						"update — an incident where one person did all "+
						"three has no record of itself", who)
			}
		}
	}
	i.Filled[r] = who
	i.note(who, "took "+string(r), at)
	return nil
}

// Unfilled is the roles nobody holds.
func (i *Incident) Unfilled() []Role {
	var out []Role
	for _, r := range Roles {
		if strings.TrimSpace(i.Filled[r]) == "" {
			out = append(out, r)
		}
	}
	return out
}

// Decide records a trigger: the moment a clock starts.
func (i *Incident) Decide(t Trigger, by, why string, at time.Time) error {
	known := false
	for _, c := range Triggers {
		if c == t {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%q is not a decision that starts anything", t)
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("somebody makes this call")
	}
	if strings.TrimSpace(why) == "" {
		return fmt.Errorf(
			"recording %q needs a reason. The start of the clock is the "+
				"thing a regulator asks about, and \"it says here it was "+
				"tuesday\" is not an answer somebody can defend", t)
	}
	if existing, ok := i.Moments[t]; ok {
		return fmt.Errorf(
			"%s was already recorded at %s by %s. Moving the start of a "+
				"clock afterwards is the one edit that cannot be innocent",
			t, existing.At.Format(time.RFC3339), existing.By)
	}
	i.Moments[t] = Moment{At: at.UTC(), By: strings.TrimSpace(by),
		Why: strings.TrimSpace(why)}
	i.note(by, fmt.Sprintf("decided: %s — %s", t, why), at)
	return nil
}

// Started reports whether a trigger's clock is running.
func (i *Incident) Started(t Trigger) (Moment, bool) {
	m, ok := i.Moments[t]
	return m, ok
}

// Watch marks an incident as believed fixed but not yet trusted.
func (i *Incident) Watch(by, why string, at time.Time) error {
	if i.State == Closed {
		return fmt.Errorf("this is closed")
	}
	i.State = Watching
	i.note(by, "watching: "+strings.TrimSpace(why), at)
	return nil
}

// Close finishes an incident.
//
// Refuses while anything is outstanding, and says what. The list is the
// point: an incident closed with a duty neither met nor ruled out is an
// obligation that has quietly become nobody's.
func (i *Incident) Close(by, cause string, actions []string,
	at time.Time) error {
	if strings.TrimSpace(cause) == "" {
		return fmt.Errorf(
			"closing needs a cause. Not a timeline and not a fix — what " +
				"was actually wrong, in a sentence somebody who was not " +
				"here can read")
	}
	if len(actions) == 0 {
		return fmt.Errorf(
			"closing needs at least one action. An incident that produced " +
				"nothing to change is either a false alarm, which is worth " +
				"saying, or a lesson nobody wrote down")
	}
	var owed []string
	for _, d := range i.Duties(at) {
		if d.Done || d.Waived {
			continue
		}
		owed = append(owed, d.Regime+" — "+d.What)
	}
	if len(owed) > 0 {
		return fmt.Errorf(
			"%d obligation(s) are neither discharged nor ruled out: %s. "+
				"An incident closed over one of these is an obligation "+
				"that has quietly become nobody's", len(owed),
			strings.Join(owed, "; "))
	}
	i.State = Closed
	i.Cause = strings.TrimSpace(cause)
	i.Actions = actions
	i.note(by, "closed: "+i.Cause, at)
	return nil
}

// Timeline is the record, in the incident's own order.
//
// By sequence rather than by timestamp, because during an incident three
// people write to it from three machines whose clocks disagree by seconds,
// and a record that reorders itself is not a record.
func (i *Incident) Timeline() []Entry {
	out := append([]Entry(nil), i.Log...)
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].seq < out[b].seq
	})
	return out
}
