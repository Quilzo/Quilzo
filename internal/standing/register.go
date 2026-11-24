// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package standing

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// Register is every situational role in this program.
//
// One list rather than a declaration per package, for the same reason the
// privilege table in the command layer is one list: the question worth
// answering is "what can anybody do here", and an answer assembled from
// nine files is one nobody assembles.
//
// It said "every" while holding only the roles of the call demonstrations
// and the room, and left out the ones a deployment hands out every day: a
// share link, a handoff conversation's secret, an enrolment link and an
// agent run's starter. Those are here. The call demonstrations and the room
// have left Quilzo, and their roles went with them.
func Register() []Situational {
	return []Situational{
		{
			// Kept by `quilzo share` in the command layer; there is no
			// package of its own.
			Package: "share", Name: "link holder",
			What: "somebody outside, a client most often, sent a link to a draft",
			Held: "by having the link, which only somebody who may publish " +
				"the page makes",
			Ends: "when the link expires, thirty days at most, or is revoked",
			Powers: []Power{
				{Name: "view", Why: "it shows one page as it stood when it " +
					"was shared and nothing else: later edits do not reach " +
					"it, it changes nothing in the store, and the site serves " +
					"it marked not to be indexed, stored or referred onward"},
			},
		},
		{
			Package: "handoff", Name: "visitor",
			What: "a visitor whose conversation with a site's assistant was " +
				"handed to a person",
			Held: "by holding the secret in the conversation's address, given " +
				"to them when they chose to talk to a person",
			Ends: "when the conversation is deleted, a set time after it last moved",
			Powers: []Power{
				{Name: "read", Why: "the replies in their own conversation " +
					"and no other; the store keeps only a digest of the " +
					"secret, so the address is the only way in"},
				{Name: "say", Why: "adds a message to that one " +
					"conversation, within its limits on length and number"},
				{Name: "end", Why: "closes that one conversation; what was " +
					"said is kept until it expires, and nothing else changes"},
			},
		},
		{
			Package: "enrol", Name: "link holder",
			What: "a person sent a link to add their first passkey",
			Held: "by having the link, which only somebody who may grant " +
				"access makes, for one person the policy already names",
			Ends: "when it is used, revoked, or a day after it was made",
			Powers: []Power{
				{Name: "add-passkey", Outside: true, Needs: auth.ActGrant,
					Why: "the passkey outlives the link and signs in as the " +
						"person it names, with every grant they hold. That is " +
						"a standing act, and the authority it rests on is the " +
						"grant of whoever made the link, checked when they " +
						"made it: the link carries that decision, once, to " +
						"one person"},
			},
		},
		{
			// Kept by the agent runs in the command layer, over the records
			// internal/agent defines.
			Package: "agent", Name: "run starter",
			What: "the person who started an agent run",
			Held: "by having started it, which takes the run-agents " +
				"permission on that agent",
			Ends: "when the run's record goes; stopping it, when the run ends",
			Powers: []Power{
				{Name: "follow", Why: "reads what their own run is doing and " +
					"did, as a task over the agent-to-agent interface; " +
					"somebody else's run reads as no run at all"},
				{Name: "cancel", Why: "stops their own run, which ends what " +
					"it had yet to do and undoes nothing it did. What the " +
					"run may do is already narrowed by the starter's own " +
					"credential, and a step that pays, publishes, deletes " +
					"or sends waits for somebody other than the starter " +
					"whenever there is such a person"},
			},
		},
	}
}

// Find looks a situational role up.
func Find(pkg, name string) (Situational, bool) {
	for _, s := range Register() {
		if strings.EqualFold(s.Package, pkg) &&
			strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return Situational{}, false
}

// Packages is every package that confers situational authority.
func Packages() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Register() {
		if !seen[s.Package] {
			seen[s.Package] = true
			out = append(out, s.Package)
		}
	}
	sort.Strings(out)
	return out
}

// Escalations is every power that reaches outside its situation.
//
// The list worth reviewing. Each of these is a standing act somebody can
// reach by being in the right place at the right time, and each one either
// has a floor under it or is a way to acquire authority nobody granted.
func Escalations() []Situational {
	var out []Situational
	for _, s := range Register() {
		if !s.Contained() {
			out = append(out, s)
		}
	}
	return out
}

// Shape is what the register looks like, for somebody deciding whether
// this program's authority is reviewable.
type Shape struct {
	Roles     int `json:"roles"`
	Packages  int `json:"packages"`
	Powers    int `json:"powers"`
	Contained int `json:"contained"`
	Reaching  int `json:"reaching"`
}

// Look measures the register.
func Look() Shape {
	s := Shape{Packages: len(Packages())}
	for _, r := range Register() {
		s.Roles++
		s.Powers += len(r.Powers)
		if r.Contained() {
			s.Contained++
		} else {
			s.Reaching++
		}
	}
	return s
}

// Why describes the register in a sentence.
//
// The verbs agree with the counts. They were written for a register where
// several roles were contained and several reached outside, and once a
// single role reached outside the sentence read "1 confer something",
// which is how a figure nobody looked at reads.
func (s Shape) Why() string {
	are, confer := "are", "confer"
	if s.Contained == 1 {
		are = "is"
	}
	if s.Reaching == 1 {
		confer = "confers"
	}
	return fmt.Sprintf(
		"%d situational role(s) across %d package(s), conferring %d "+
			"power(s). %d %s contained and %d %s something that "+
			"survives the situation and therefore rests on a standing "+
			"grant", s.Roles, s.Packages, s.Powers, s.Contained, are,
		s.Reaching, confer)
}

// Check validates the whole register.
//
// Run as a test. The failure this exists to prevent is a ninth model
// appearing quietly in the tenth package, so the register being complete
// matters more than any single entry in it being right.
func Check() error {
	seen := map[string]bool{}
	for _, s := range Register() {
		if err := s.Validate(); err != nil {
			return err
		}
		key := s.Package + "/" + s.Name
		if seen[key] {
			return fmt.Errorf("%s is registered twice", key)
		}
		seen[key] = true
	}
	return nil
}
