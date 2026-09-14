// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package gate is the list of checks that stand between a draft and the
// public, in one place so that every surface runs the same ones.
//
// # The bug this exists for
//
// There are four ways to publish here — the command line, the browser, the
// agent interface, and a message in a chat room — and they ran four different
// sets of checks. Not a subset each: a different set each, with gates the
// command line had and the browser did not, and one gate the browser had and
// the command line did not.
//
//	                     CLI   browser   MCP   chat
//	classification        yes    no       no    no
//	image rights          yes    no       no    no
//	arrangement           yes    no       no    no
//	claims                yes    no       no    no
//	references            yes    yes      no    no
//	already expired       no     yes      no    no
//	broken menu links     no     yes      no    no
//
// The demo ships a shop whose own instructions say "take guarantee_terms off
// the brass pen and publishing stops". It stops on the command line:
//
//	$ quilzo publish
//	  products/6f8e5666… (description): "Guaranteed" — a guarantee is a
//	  promise somebody has to honour, so the terms have to be written down
//	  1 claim(s) this business would have to stand behind and nothing
//	  here substantiates.                                         exit 3
//
// and it did not stop in the browser, which published the same draft with the
// same unsubstantiated claim and an image whose licence was running out.
//
// That is worse than not having the gate. A control that holds on one surface
// and not on another is a control somebody has already relied on, and the
// surface that skips it is usually the one most people use.
//
// # Why a list and not a call in each place
//
// The same reason cmd/quilzo keeps a privilege table rather than a check at
// the top of each command, and its comment says it: "A call has to be
// remembered; a table is a list somebody has to add a row to." Four publish
// paths each remembering seven checks is four chances to forget, and forgetting
// is silent — a publish that skipped a gate looks exactly like a publish that
// passed one.
package gate

import "fmt"

// A Finding is one thing wrong, named so it can be fixed.
//
// Page may be empty: some checks are about the set being published rather than
// about a page in it — a menu entry pointing at nothing belongs to the menu.
type Finding struct {
	Page   string
	Detail string
}

func (f Finding) String() string {
	if f.Page == "" {
		return f.Detail
	}
	return f.Page + ": " + f.Detail
}

// A Check is one gate.
type Check struct {
	// Name is what it is called in an audit record and in a log line. Stable,
	// short, and the same on every surface, because "which check refused" is a
	// question asked across surfaces.
	Name string
	// Refusal is the sentence somebody reads, given how many findings there
	// were. It has to say what to do about it: a refusal that only says no
	// teaches people to look for the flag that turns it off.
	Refusal func(n int) string
	// Run answers what is wrong. Blocking refuses the publish; advisory is
	// printed and let through.
	//
	// An error is a refusal and not an absence. "The claim check could not
	// run" must never reach somebody as "there are no claims to answer for",
	// which is the failure mode of every check that returns nil on error.
	Run func() (blocking, advisory []Finding, err error)
}

// A Report is a check that refused, and what it found.
type Report struct {
	Check    Check
	Findings []Finding
}

// Error is the refusal as an error, naming the check and what it found.
func (r *Report) Error() string {
	msg := r.Check.Refusal(len(r.Findings))
	for _, f := range r.Findings {
		msg += "\n  " + f.String()
	}
	return msg
}

// A Set is the gates, in the order they are asked.
//
// The order is the order somebody should fix things in, which is why it is a
// slice and not a map: content first, so that a draft which is going to be
// refused anyway is refused before two colleagues are asked to approve it.
type Set []Check

// Run asks every gate and stops at the first refusal.
//
// Stopping rather than collecting: a screen that lists eight unrelated
// refusals at once is one nobody reads to the end of, and the first one is the
// one to fix. Advisory findings from the checks that did pass are returned
// either way, because they are the half worth having — a licence expiring in
// six weeks can be renewed and one that expired last month cannot.
func (s Set) Run() (refused *Report, advisory []Finding, err error) {
	for _, c := range s {
		blocking, advice, cerr := c.Run()
		advisory = append(advisory, advice...)
		if cerr != nil {
			return nil, advisory, fmt.Errorf(
				"the %s check could not run, so publishing would claim a "+
					"check that did not happen: %w", c.Name, cerr)
		}
		if len(blocking) > 0 {
			return &Report{Check: c, Findings: blocking}, advisory, nil
		}
	}
	return nil, advisory, nil
}

// Names is what this set checks, for a test that asks whether two surfaces
// agree.
func (s Set) Names() []string {
	out := make([]string, 0, len(s))
	for _, c := range s {
		out = append(out, c.Name)
	}
	return out
}
