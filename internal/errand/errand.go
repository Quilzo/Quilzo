// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package errand carries out what somebody agreed to do in a call.
//
// internal/scribe produces action items, and every one of them points at a
// span of transcript — a person, a timestamp, and the words they used.
// This is what happens next: the assistant does the thing, or proposes to.
//
// # What this adds that the manifest does not
//
// internal/agent is the chokepoint. It decides what an agent may call at
// all, it bounds the run, and an agent that has been entirely talked round
// by something it read can still only do what its manifest declared. That
// is the security property and it is not this package's.
//
// Three things it cannot know, which are this package's:
//
//  1. Provenance. An agent's manifest says it may create a task. It does
//     not say whether this particular task came from anything. An errand
//     without words behind it cannot be made here, and a receipt names the
//     sentence somebody actually said — so "why is there a ticket assigned
//     to me" has an answer that is not "the AI decided".
//
//  2. Audience. The manifest says an agent may send mail. It does not know
//     that the contents came from a call with four people in it, and that
//     the address it is about to send to belongs to a fifth. An errand
//     carries the roster of the call it came from, and anything that would
//     reach further is refused until a person agrees — with the refusal
//     naming exactly who would newly learn. This is the ordinary shape of
//     an agent leaking something: not a break-in, a helpful forward.
//
//  3. Who agrees. The person who made the commitment is the person who
//     confirms it. If the minutes say grace will write the migration, it
//     is grace's to confirm and not the meeting organiser's. Every product
//     that puts a single approve button in front of whoever opened the
//     summary has quietly moved the decision to the wrong person.
//
// # And the part that does not work
//
// An errand's words can be erased — somebody withdraws consent after the
// fact, and internal/scribe takes their contribution out. An errand
// resting on those words is then an instruction with nothing behind it.
// It is reported as orphaned rather than carried, and rather than silently
// dropped, because a task that was on somebody's list and has vanished is
// a thing they should be told about.
package errand

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/scribe"
)

// Provenance is the words an errand rests on.
type Provenance struct {
	Speaker string        `json:"speaker"`
	Seat    int           `json:"seat"`
	At      time.Duration `json:"at"`
	Words   string        `json:"words"`
}

// Gone reports whether the words have been erased.
func (p Provenance) Gone() bool { return strings.TrimSpace(p.Words) == "" }

// State is where an errand has got to.
type State string

const (
	// Proposed: it exists and nobody has agreed to it.
	Proposed State = "proposed"
	// Accepted: the person who made the commitment confirmed it.
	Accepted State = "accepted"
	// Declined: they said no, which is a normal outcome and not a failure.
	Declined State = "declined"
	// Carried: it was done.
	Carried State = "carried"
	// Failed: it was attempted and did not work.
	Failed State = "failed"
	// Orphaned: the words it rested on were erased.
	Orphaned State = "orphaned"
)

// Errand is one thing to do, and the sentence it came from.
type Errand struct {
	ID    string `json:"id"`
	Call  string `json:"call"`
	Epoch uint64 `json:"epoch"`

	// Owner is who agreed to do it, and therefore who confirms it.
	Owner string `json:"owner"`
	// Want is what the minutes say, in the minutes' words.
	Want string `json:"want"`
	// Op is the capability this would call, from the manifest's closed set.
	Op    string            `json:"op,omitempty"`
	Input map[string]string `json:"input,omitempty"`

	From Provenance `json:"from"`
	// Heard is everybody who was in the call when the words were said.
	//
	// The audience boundary. It is fixed at the moment of speaking rather
	// than read from the call later, because the roster changes and the
	// question is who heard it, not who is there now.
	Heard []string `json:"heard"`

	State State     `json:"state"`
	Made  time.Time `json:"made"`

	By   string    `json:"by,omitempty"`
	When time.Time `json:"when,omitzero"`
	Note string    `json:"note,omitempty"`
}

// NewID makes an identifier for an errand.
func NewID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FromMinutes builds an errand from an action item.
//
// heard is the roster of the call. It is required, and there is no
// convenience overload without it: an errand whose audience is unknown is
// one where the widening check cannot run, and a check that is optional is
// a check that is off.
func FromMinutes(m scribe.Minutes, line int, heard []string,
	at time.Time) (Errand, error) {
	if line < 0 || line >= len(m.Lines) {
		return Errand{}, fmt.Errorf("there is no line %d", line)
	}
	l := m.Lines[line]
	if l.Kind != scribe.Action {
		return Errand{}, fmt.Errorf(
			"line %d is a %s. Only something somebody agreed to do becomes "+
				"an errand; a decision is not a task and a question is the "+
				"opposite of one", line, l.Kind)
	}
	if strings.TrimSpace(l.Owner) == "" {
		return Errand{}, fmt.Errorf("that action has no owner, so there is " +
			"nobody whose agreement would count")
	}
	if len(heard) == 0 {
		return Errand{}, fmt.Errorf("an errand needs the roster of the " +
			"call it came from; without it there is nothing to compare an " +
			"audience against and the widening check cannot run")
	}
	quotes := m.Quote(line)
	if len(quotes) == 0 {
		return Errand{}, fmt.Errorf("that line points at nothing")
	}
	// The first live span is the provenance. Scribe already refuses to
	// anchor an action to a quarantined span, and this refuses again rather
	// than trusting that it did: the two packages can be used apart.
	var src scribe.Span
	found := false
	for _, q := range quotes {
		if q.Quarantined {
			return Errand{}, fmt.Errorf(
				"that action rests on something that reads as an "+
					"instruction to a machine (%s at %s). It can be quoted "+
					"and it cannot be why somebody now has work",
				q.Name, plainClock(q.From))
		}
		if !q.Erased && !found {
			src, found = q, true
		}
	}
	if !found {
		return Errand{}, fmt.Errorf(
			"the words behind that action have been erased")
	}
	id, err := NewID()
	if err != nil {
		return Errand{}, err
	}
	return Errand{
		ID: id, Call: m.Call, Epoch: m.Epoch,
		Owner: l.Owner, Want: l.Text,
		From: Provenance{Speaker: src.Name, Seat: src.Seat, At: src.From,
			Words: src.Text},
		Heard: normalise(heard),
		State: Proposed, Made: at.UTC(),
	}, nil
}

func normalise(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func plainClock(d time.Duration) string {
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}

// Accept is the owner confirming.
//
// Only the owner. A moderator, a meeting organiser and an administrator
// are all the wrong person: the record says this one agreed to do it, and
// an approval by anybody else turns a commitment somebody made into a task
// somebody was given.
func (e *Errand) Accept(by string, at time.Time) error {
	if !strings.EqualFold(strings.TrimSpace(by), e.Owner) {
		return fmt.Errorf("%s agreed to this, so it is %s who confirms it. "+
			"%s cannot, and an approve button that did not care which of "+
			"them pressed it would have moved the decision to whoever "+
			"opened the summary", e.Owner, e.Owner, by)
	}
	switch e.State {
	case Proposed, Declined:
	default:
		return fmt.Errorf("this errand is already %s", e.State)
	}
	e.State, e.By, e.When = Accepted, e.Owner, at.UTC()
	return nil
}

// Decline is the owner saying no. A normal outcome.
func (e *Errand) Decline(by, why string, at time.Time) error {
	if !strings.EqualFold(strings.TrimSpace(by), e.Owner) {
		return fmt.Errorf("only %s can decline their own commitment",
			e.Owner)
	}
	e.State, e.By, e.When = Declined, by, at.UTC()
	e.Note = strings.TrimSpace(why)
	return nil
}

// Reach is who an operation's result would get to.
type Reach struct {
	// To is the people it would reach, by name or address.
	To []string `json:"to,omitempty"`
	// Public means anybody, which is always wider than a call.
	Public bool `json:"public,omitempty"`
}

// Widens is who would learn something they were not in the room for.
//
// Empty means the result stays inside the call, which is the only case
// that needs no decision from anybody.
func (e Errand) Widens(r Reach) []string {
	if r.Public {
		return []string{"anybody"}
	}
	heard := map[string]bool{}
	for _, h := range e.Heard {
		heard[h] = true
	}
	var out []string
	for _, t := range normalise(r.To) {
		if !heard[t] {
			out = append(out, t)
		}
	}
	return out
}

// Orphaned reports whether the words are gone.
func (e Errand) Orphaned() bool {
	return e.State == Orphaned || e.From.Gone()
}

// Orphan marks an errand whose provenance has been erased.
//
// Something already carried out stays carried out. The words behind it are
// gone and the thing still happened, and rewriting the record to say
// otherwise would be a worse lie than the gap.
func (e *Errand) Orphan(at time.Time) {
	e.From.Words = ""
	if e.State != Carried {
		e.State, e.When = Orphaned, at.UTC()
	}
}

// Lost says what an erasure did to an errand, for somebody being told
// about it.
func (e Errand) Lost() string {
	if !e.From.Gone() {
		return ""
	}
	if e.State == Carried {
		return "it was already done, and there is now nothing on record " +
			"saying why"
	}
	return "there is nothing behind it any more"
}
