// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
		if to, sends := HandSends(a); sends {
			return s.breaksTo(to, "")
		}
		return "", false
	}
	return s.breaksTo(s.HostFor(a.Tool), a.Tool)
}

// HandSends says where an action of the agent's hands would carry words
// the model chose out to another system: an address its browser opens or
// it reads on the web, text it types into a page or an app, a file it puts
// into a page, a query it asks a search provider (browserSends, webSends).
// The breaker's own reading, said once for whatever else holds such an
// action: a run nobody started holds it for a person as it holds a tool's
// write (cmd/quilzo agentsends.go), and a second list there would be one
// a new hand could be added to this one and missing from. A command that
// reaches the network is the workspace's to say (internal/shell).
func HandSends(a Action) (string, bool) {
	if strings.TrimSpace(a.Tool) != "" || a.Delegate != "" {
		return "", false
	}
	if to, sends := browserSends(a); sends {
		return to, true
	}
	return webSends(a)
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

// MaxMemory bounds the memory a receipt names, each way.
const MaxMemory = 64

// UsedMemory records memory the run recalled, or kept, by id.
func (s *Session) UsedMemory(recalled bool, ids ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := &s.remembered
	if recalled {
		list = &s.recalled
	}
	for _, id := range ids {
		if len(*list) < MaxMemory && !contains(*list, id) {
			*list = append(*list, id)
		}
	}
}

// FromMemory is a run that recalled what somebody else's run kept.
const FromMemory SourceKind = "memory"

// ReadMemory records that the run recalled an entry somebody else's run
// kept, by its id: a procedure is about nobody and so recalled into
// everybody's runs, and in any run but its author's it is somebody else's
// words. The run is tainted from here, as reading them anywhere else would
// taint it, so the breaker and the hold on what it learns apply.
func (s *Session) ReadMemory(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tainted = true
	s.note(FromMemory, id, "")
}

// MemoryUsed is the memory the run recalled and kept.
func (s *Session) MemoryUsed() (recalled, remembered []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.recalled...), append([]string(nil), s.remembered...)
}

// OnlyPublished reports a run that has read, and read only what is
// published: no draft, no tool's answer, no other agent's, and nothing it
// read and could not name.
func (s *Session) OnlyPublished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tainted || s.omitted > 0 || isUnpublished(s.manifest.Retrieval.Ref) {
		return false
	}
	for _, src := range s.sourcesLocked() {
		if src.Kind != FromPage && src.Kind != FromSet {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
