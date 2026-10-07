// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"strings"
)

// The exfiltration breaker.
//
// Three things together are what makes an agent able to leak: it holds
// something private, it has read something somebody else wrote, and it can
// send something outside. Each alone is ordinary. Together, the words
// somebody else wrote can tell it to take what is private and send it, and
// no classifier reliably tells those words apart from honest content:
// the design patterns that hold up (dual LLM, plan-then-execute, CaMeL) all
// work by never letting the three meet without a gate.
//
// So this is the gate. The taint already says the second (Session.Tainted);
// this records the first, which is reading what is not published; and the
// third is a call to a tool, whose host is outside by definition, or a
// program's connection through its proxy. When a call would complete the
// three, the run stops and a person sees exactly what it read, what is
// private about it, and where the call would go, and decides. A program
// cannot be held, so for a program the call is refused, with that reason.
//
// What it does not do: inspect what is in the call. That would be the
// classifier this exists not to depend on. It is deliberately coarse, and a
// run that should send private material out on purpose is approved once,
// by a person who has seen the reason.

// MaxPrivate bounds the private things a run names, as MaxSources does.
const MaxPrivate = 16

// notePrivate records that the run read something that is not public. The
// caller holds the lock.
func (s *Session) notePrivate(what string) {
	for _, p := range s.private {
		if p == what {
			return
		}
	}
	if len(s.private) < MaxPrivate {
		s.private = append(s.private, what)
		return
	}
	s.privateMore++
}

// HoldsPrivate records that the run now holds something private that is
// not a draft: what an agent remembers about somebody, say.
func (s *Session) HoldsPrivate(what string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notePrivate(what)
}

// Private is what this run has read that is not published.
func (s *Session) Private() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.private...)
}

// RecallPrivate restores what a run being continued had read in private.
func (s *Session) RecallPrivate(private []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range private {
		s.notePrivate(p)
	}
}

// Inherit starts a delegate holding what its supervisor holds: handing work
// on must not be the way private material and somebody else's words reach
// a tool without the gate.
func (s *Session) Inherit(parent *Session) {
	parent.mu.Lock()
	tainted, private, sources := parent.tainted, append([]string(nil), parent.private...), parent.sourcesLocked()
	parent.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if tainted {
		s.tainted = true
		for _, src := range sources {
			s.note(src.Kind, src.Name, src.Where)
		}
	}
	for _, p := range private {
		s.notePrivate(p)
	}
}

// Breaks says whether an action would send something out of a run that
// holds private material and has read somebody else's words, and why.
func (s *Session) Breaks(a Action) (string, bool) {
	if strings.TrimSpace(a.Tool) == "" {
		return "", false
	}
	return s.breaksTo(s.HostFor(a.Tool), a.Tool)
}

// BreaksTo is Breaks for a connection to a host, as a program's proxy asks.
func (s *Session) BreaksTo(host string) (string, bool) { return s.breaksTo(host, "") }

func (s *Session) breaksTo(host, tool string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tainted || len(s.private) == 0 {
		return "", false
	}
	private := strings.Join(s.private, ", ")
	if s.privateMore > 0 {
		private += fmt.Sprintf(" and %d more", s.privateMore)
	}
	to := host
	if tool != "" {
		to = tool + " at " + host
	}
	why := fmt.Sprintf("this run has read what is not published (%s) and content somebody else may have written", private)
	if p := Provenance(s.sourcesLocked(), s.omitted); p != "" {
		why += " (" + p + ")"
	}
	why += ", and this would send to " + to + ". A person decides whether what it holds may leave"
	return why, true
}
