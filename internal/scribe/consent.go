// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package scribe

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Rule is how many people have to agree before a conversation may be
// recorded.
type Rule string

const (
	// AllParty: everybody in the call. Thirteen US states, and the
	// practical answer under the GDPR for a recording of colleagues.
	AllParty Rule = "all-party"
	// OneParty: one participant's agreement covers the call. The federal
	// US default and most states.
	OneParty Rule = "one-party"
	// Unstated: nobody said where somebody is. Treated as all-party,
	// because the failure mode of guessing wrong is a criminal statute.
	Unstated Rule = "unstated"
)

// Strict reports whether a rule needs everybody.
func (r Rule) Strict() bool { return r != OneParty }

// Place is somewhere a participant might be, and what it requires.
//
// This is a starting table and not legal advice, which the package says
// where a deployment will read it. The edges of this list are genuinely
// contested — several of these states reached all-party through case law
// rather than statute, and one or two more are argued either way — so
// anything not named here is Unstated and therefore treated as all-party.
// Failing closed is the only defensible default when the downside is a
// wiretap charge.
type Place struct {
	Name string `json:"name"`
	Rule Rule   `json:"rule"`
	Note string `json:"note,omitempty"`
}

// Places is the table.
var Places = []Place{
	{Name: "california", Rule: AllParty},
	{Name: "connecticut", Rule: AllParty},
	{Name: "delaware", Rule: AllParty},
	{Name: "florida", Rule: AllParty},
	{Name: "illinois", Rule: AllParty},
	{Name: "maryland", Rule: AllParty},
	{Name: "massachusetts", Rule: AllParty},
	{Name: "montana", Rule: AllParty},
	{Name: "nevada", Rule: AllParty},
	{Name: "new hampshire", Rule: AllParty},
	{Name: "oregon", Rule: AllParty},
	{Name: "pennsylvania", Rule: AllParty},
	{Name: "washington", Rule: AllParty},
	{Name: "michigan", Rule: AllParty,
		Note: "argued both ways; listed strict because the cost of being " +
			"wrong falls on the participant and not on this table"},
	{Name: "eu", Rule: AllParty,
		Note: "not a wiretap rule. Recording colleagues needs a lawful " +
			"basis, and consent between an employer and an employee is " +
			"weak because of the power imbalance, so in practice this " +
			"behaves as all-party and the basis should be written down"},
	{Name: "uk", Rule: AllParty, Note: "as the EU, post-Brexit"},
	{Name: "new york", Rule: OneParty},
	{Name: "texas", Rule: OneParty},
	{Name: "us-federal", Rule: OneParty,
		Note: "the floor. A state may be stricter and several are"},
}

// Lookup finds a place, or reports that it is unstated.
func Lookup(name string) Place {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range Places {
		if p.Name == n {
			return p
		}
	}
	return Place{Name: n, Rule: Unstated,
		Note: "not in the table, so treated as needing everybody"}
}

// Consent is one participant's answer.
type Consent struct {
	Seat  int       `json:"seat"`
	Name  string    `json:"name"`
	Where string    `json:"where"`
	Given bool      `json:"given"`
	At    time.Time `json:"at"`
	// Withdrawn is when they changed their mind, which they may do at any
	// point and without giving a reason.
	Withdrawn time.Time `json:"withdrawn,omitzero"`
}

// Live reports whether this consent currently holds.
func (c Consent) Live() bool { return c.Given && c.Withdrawn.IsZero() }

// Record is the consent state of one call.
type Record struct {
	Call  string    `json:"call"`
	Asked []Consent `json:"asked"`
}

// Ask records somebody's answer.
func (r *Record) Ask(seat int, name, where string, given bool,
	at time.Time) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("an answer needs to be somebody's")
	}
	for i := range r.Asked {
		if r.Asked[i].Seat != seat {
			continue
		}
		if r.Asked[i].Live() && !given {
			return r.Withdraw(seat, at)
		}
		r.Asked[i].Given = given
		r.Asked[i].Where = strings.ToLower(strings.TrimSpace(where))
		r.Asked[i].At = at.UTC()
		r.Asked[i].Withdrawn = time.Time{}
		return nil
	}
	r.Asked = append(r.Asked, Consent{
		Seat: seat, Name: name,
		Where: strings.ToLower(strings.TrimSpace(where)),
		Given: given, At: at.UTC(),
	})
	return nil
}

// Withdraw takes consent back.
//
// No reason required and no confirmation asked for. A withdrawal that has
// to be justified is not a withdrawal.
func (r *Record) Withdraw(seat int, at time.Time) error {
	for i := range r.Asked {
		if r.Asked[i].Seat == seat {
			if !r.Asked[i].Live() {
				return nil
			}
			r.Asked[i].Withdrawn = at.UTC()
			return nil
		}
	}
	return fmt.Errorf("nobody at seat %d has been asked", seat)
}

// Governing is the rule that applies to this call, and where it came from.
//
// The strictest place anybody is in. This is the trap enterprise teams fall
// into: the meeting is run from a one-party state, everybody assumes that
// settles it, and one participant dialling in from California makes the
// whole call all-party. It is not a rule about the host, it is a rule about
// the conversation.
func (r *Record) Governing(seats []int) (Rule, string) {
	strictest, from := OneParty, "us-federal"
	for _, s := range seats {
		where := ""
		for _, c := range r.Asked {
			if c.Seat == s {
				where = c.Where
			}
		}
		p := Lookup(where)
		if p.Rule.Strict() && strictest == OneParty {
			strictest, from = AllParty, p.Name
			if p.Rule == Unstated {
				strictest = AllParty
				from = "somebody who has not said where they are"
			}
		}
	}
	if strictest == OneParty {
		return OneParty, "nobody in this call is somewhere that needs " +
			"everybody to agree"
	}
	return AllParty, fmt.Sprintf(
		"the strictest place anybody is in governs the whole call, and "+
			"that is %s", from)
}

// Missing is everybody who has not agreed, which is what an interface
// should show instead of a refusal with no names in it.
func (r *Record) Missing(seats []int) []string {
	var out []string
	for _, s := range seats {
		live := false
		name := fmt.Sprintf("seat %d", s)
		for _, c := range r.Asked {
			if c.Seat == s {
				name = c.Name
				live = c.Live()
			}
		}
		if !live {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// MayRun reports whether a scribe may run over these participants.
//
// The refusal names the people, because "consent required" with nobody
// named is a message that gets clicked past.
func (r *Record) MayRun(seats []int) (bool, string) {
	rule, why := r.Governing(seats)
	if rule == OneParty {
		for _, c := range r.Asked {
			if c.Live() {
				return true, fmt.Sprintf("%s, and %s agreed", why, c.Name)
			}
		}
		return false, "nobody has agreed, and somebody in the call has to"
	}
	missing := r.Missing(seats)
	if len(missing) == 0 {
		return true, fmt.Sprintf("%s, and everybody agreed", why)
	}
	return false, fmt.Sprintf("%s. Waiting on %s", why,
		strings.Join(missing, ", "))
}

// Arrived is what happens when somebody new joins mid-call.
//
// It returns whether the scribe has to stop. This is the behaviour the
// lawsuits are about: a person who was not there when consent was taken
// has not consented, and carrying on because it would be awkward to stop
// is the decision being litigated.
func (r *Record) Arrived(seats []int) (pause bool, why string) {
	ok, why := r.MayRun(seats)
	return !ok, why
}
