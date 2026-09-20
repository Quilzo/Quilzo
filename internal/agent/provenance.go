// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"sort"
	"strings"
)

// What the taint came from.
//
// # Why a boolean was not enough
//
// The taint rule is the load-bearing part of this design: anything an agent
// produced after reading content somebody else may have written needs a person
// before it goes live. The person is the control.
//
// They were handed one bit. The receipt said tainted: true and nothing else,
// so an editor asked to approve an agent's draft knew that it had read
// something untrusted and not what — and the only honest way to review that is
// to re-read the whole site. Which nobody does. A control that is too
// expensive to exercise is a control that gets exercised by clicking approve.
//
// So the sources are recorded as they are read. "This agent read /pricing and
// /faq, and called crm at api.example.com" is a review somebody can actually
// do in a minute, and it is the difference between the approval meaning
// something and being a formality.
//
// This is the provenance half of the design the rest of this package follows.
// CaMeL's argument is not only that policy is enforced outside the model; it
// is that the enforcement needs to know where each value came from. The taint
// bit is that idea with the provenance thrown away.
//
// # Why not per-value
//
// Because this program does not have a value graph. CaMeL tracks provenance
// through an interpreter it controls; here the model's output is a string and
// what produced it is the sequence of reads that preceded it. Recording that
// sequence is honest about what is known — these are the sources this run
// touched — and does not claim the stronger property, which would be that a
// particular sentence came from a particular page.

// SourceKind is what a piece of untrusted input was.
type SourceKind string

const (
	// FromPage is one named page read out of the store.
	FromPage SourceKind = "page"
	// FromSet is a listing or a search over a ref, where the pages that
	// contributed are not individually known.
	FromSet SourceKind = "set"
	// FromTool is a result off a third-party host.
	FromTool SourceKind = "tool"
	// FromDelegate is everything a delegated run read, folded upward.
	FromDelegate SourceKind = "delegate"
)

// Source is one thing a run read.
type Source struct {
	Kind SourceKind `json:"kind"`
	// Name is the page, the ref, the tool or the delegate.
	Name string `json:"name"`
	// Where is the host a tool reached, empty for anything in this store.
	Where string `json:"where,omitempty"`
}

func (s Source) String() string {
	switch s.Kind {
	case FromTool:
		if s.Where != "" {
			return s.Name + " at " + s.Where
		}
		return s.Name
	case FromSet:
		return "a listing of " + s.Name
	case FromDelegate:
		return "delegated to " + s.Name
	}
	return s.Name
}

// MaxSources bounds what one run records.
//
// A run that read four hundred pages has a provenance list nobody will read,
// and putting it in an audit detail turns one record into a document. The
// bound is generous enough that an ordinary run is recorded in full and small
// enough that the record stays a record; past it the count is kept and the
// names are not, which is the honest summary rather than a truncated list
// somebody might mistake for the whole.
const MaxSources = 64

// note records one source, if it is new and there is room.
//
// The caller holds the lock.
func (s *Session) note(kind SourceKind, name, where string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	s.reads++
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	key := string(kind) + "\x00" + name + "\x00" + where
	if s.seen[key] {
		// The same page read twice is one source. Counting it again would
		// make the receipt say "and 6 more" about a run that touched three
		// things repeatedly, which is a sentence that sends a reviewer
		// looking for six pages that do not exist.
		return
	}
	s.seen[key] = true
	if len(s.sources) >= MaxSources {
		// Counted and not named, so the receipt can say how many distinct
		// sources there were once it has stopped saying which.
		s.omitted++
		return
	}
	s.sources = append(s.sources, Source{Kind: kind, Name: name, Where: where})
}

// Sources is everything this run read, in a stable order.
//
// Sorted rather than in the order they were read. The order of reads is a
// property of what the model chose to do and changes between runs of the same
// agent on the same content; a reviewer comparing two runs, or a test
// comparing a run to an expectation, needs the same list to look the same.
func (s *Session) Sources() []Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sourcesLocked()
}

// sourcesLocked is Sources for a caller that already holds the lock.
func (s *Session) sourcesLocked() []Source {
	out := append([]Source(nil), s.sources...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Where < out[j].Where
	})
	return out
}

// Reads is how many times this run read something untrusted.
//
// Events, not sources: a page read four times is four reads and one source.
// Kept apart because they answer different questions — how much untrusted
// input the run took in, and what a reviewer has to go and look at.
func (s *Session) Reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// Omitted is how many distinct sources were past MaxSources and so are
// counted rather than named.
func (s *Session) Omitted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.omitted
}

// Provenance is the sources written out for a person.
//
// The form a receipt and a refusal both use, so the sentence an operator reads
// in the terminal is the sentence in the audit record.
//
// omitted is how many distinct sources did not fit, not how many reads
// happened. Those are different numbers and using the second here said "and 6
// more" about a run that read three things repeatedly, which sends a reviewer
// looking for six pages that do not exist.
func Provenance(sources []Source, omitted int) string {
	if len(sources) == 0 {
		if omitted > 0 {
			return fmt.Sprintf("%d untrusted source(s)", omitted)
		}
		return ""
	}
	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		parts = append(parts, s.String())
	}
	out := strings.Join(parts, ", ")
	if omitted > 0 {
		out += fmt.Sprintf(", and %d more", omitted)
	}
	return out
}
