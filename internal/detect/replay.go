// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Replaying what has already gone wrong.
//
// A rule's fixtures are what its author thought of. A corpus is what
// happened: the events people closed as false positives, and the ones that
// turned out to be real. Replaying every rule over it on every change is
// what stops a false positive somebody spent an afternoon on from coming
// back the next time the rule is widened — which, without this, it does,
// because nothing about a rule's text remembers why it was narrowed.
//
// # The corpus is the estate's memory, so it is labelled by verdict
//
// An event closed as a false positive is added expecting nothing to fire.
// An event closed as real is added expecting its rule. An event closed as
// benign — true, and expected — is added expecting its rule too: the rule
// was right, and what quietens it is a suppression, not a change that would
// also blind it to the same thing done by somebody else.
//
// # Pending: known to be wrong, and not yet fixed
//
// A false positive learned today fails the replay today, because the rule
// still fires on it. Failing the build for that would make adding to the
// corpus something people avoid. So a new entry is pending: reported every
// run as a rule known to be wrong here, without failing, until the rule
// stops firing on it — at which point the mark comes off and it is a guard
// for good.

// Labelled is one event and what should happen to it.
type Labelled struct {
	Name  string          `json:"name"`
	Event telemetry.Event `json:"event"`
	// Expect are the rules that must fire on it. Empty means none may.
	Expect []string `json:"expect,omitempty"`
	// From is where it came from, for whoever reads the corpus next.
	From string `json:"from,omitempty"`
	// Pending marks a false positive the rule is known still to raise.
	Pending bool `json:"pending,omitempty"`
}

// Validate refuses an entry nobody could act on.
func (l Labelled) Validate() error {
	if strings.TrimSpace(l.Name) == "" {
		return fmt.Errorf("a corpus entry needs a name: it is what the " +
			"failure says when a rule stops agreeing with it")
	}
	if strings.TrimSpace(l.Event.Source) == "" {
		return fmt.Errorf("%s has no source, and a rule only reads the "+
			"sources it names", l.Name)
	}
	if l.Pending && len(l.Expect) > 0 {
		return fmt.Errorf("%s is pending and expects a rule to fire; "+
			"pending is for a false positive not yet fixed", l.Name)
	}
	return nil
}

// Outcome is how one rule did over the corpus.
type Outcome struct {
	Rule string `json:"rule"`
	// Caught fired where expected; Missed did not; Wrong fired where
	// nothing should have. Known are the pending ones it still fires on,
	// and Mended the pending ones it no longer does.
	Caught int      `json:"caught"`
	Missed []string `json:"missed,omitempty"`
	Wrong  []string `json:"wrong,omitempty"`
	Known  []string `json:"known,omitempty"`
	Mended []string `json:"mended,omitempty"`
}

// OK reports whether the rule agrees with every settled entry.
func (o Outcome) OK() bool { return len(o.Missed) == 0 && len(o.Wrong) == 0 }

// Replay runs every rule over the corpus.
//
// An entry expecting a rule that does not exist is an error, not a miss: a
// corpus naming a rule somebody renamed would otherwise report it as
// missed for ever, or — worse — stop checking it at all.
func Replay(rules []Rule, corpus []Labelled) ([]Outcome, error) {
	known := map[string]bool{}
	for _, r := range rules {
		known[r.ID] = true
	}
	for _, l := range corpus {
		if err := l.Validate(); err != nil {
			return nil, err
		}
		for _, id := range l.Expect {
			if !known[id] {
				return nil, fmt.Errorf("%s expects %s, and there is no rule "+
					"called that. If it was renamed, the corpus has to be "+
					"told", l.Name, id)
			}
		}
	}
	out := make([]Outcome, 0, len(rules))
	for _, r := range rules {
		o := Outcome{Rule: r.ID}
		for _, l := range corpus {
			fired := r.Matches(l.Event)
			expected := false
			for _, id := range l.Expect {
				expected = expected || id == r.ID
			}
			switch {
			case expected && fired:
				o.Caught++
			case expected && !fired:
				o.Missed = append(o.Missed, l.Name)
			case fired && l.Pending:
				o.Known = append(o.Known, l.Name)
			case fired:
				o.Wrong = append(o.Wrong, l.Name)
			case l.Pending && pendingFor(l, r):
				o.Mended = append(o.Mended, l.Name)
			}
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, nil
}

// pendingFor reports whether a pending entry was learned from this rule,
// which its From line records; an entry from another rule not firing here
// is not something this rule mended.
func pendingFor(l Labelled, r Rule) bool {
	return strings.Contains(l.From, r.ID)
}
