// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package appsec

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Separating what this change introduced from what the codebase already
// carried, and refusing to close a secret because the line went away.

// Triage is a run compared against a baseline.
type Triage struct {
	// Introduced are alerts the baseline did not carry. The only ones a
	// gate anybody sustains can block on.
	Introduced []Alert `json:"introduced,omitempty"`
	// Carried are alerts that were already there.
	Carried []Alert `json:"carried,omitempty"`
	// Cleared are fingerprints the baseline had and this run does not.
	Cleared []string `json:"cleared,omitempty"`
	// Vanished are secrets that are no longer in the working tree and have
	// not been rotated.
	//
	// Not cleared. The commit is still in the history and, if the branch was
	// ever pushed, on a server and in every clone. Every scanner reports
	// these as fixed.
	Vanished []string `json:"vanished,omitempty"`
	// Churned counts alerts whose identity depends on a path, which a
	// rename would break.
	Churned int `json:"churned"`
}

// Clean reports whether this change introduced nothing.
func (t Triage) Clean() bool { return len(t.Introduced) == 0 }

// Why explains a triage in one line, leading with what is new.
func (t Triage) Why() string {
	switch {
	case len(t.Vanished) > 0:
		return fmt.Sprintf(
			"%d secret(s) are gone from the working tree and nobody has "+
				"recorded a rotation. The commit is still in the history, "+
				"and every scanner reports this as fixed", len(t.Vanished))
	case len(t.Introduced) > 0:
		return fmt.Sprintf(
			"%d new, %d already there. A gate on the second number is one "+
				"that gets switched off; a gate on the first is one a team "+
				"lives with", len(t.Introduced), len(t.Carried))
	case len(t.Cleared) > 0:
		return fmt.Sprintf("nothing new, and %d fewer than before",
			len(t.Cleared))
	default:
		return fmt.Sprintf("nothing new; %d already there",
			len(t.Carried))
	}
}

// Rotated is the set of secret fingerprints somebody has replaced.
type Rotated map[string]Rotation

// From builds it from a list of rotations, newest wins.
func From(in []Rotation) Rotated {
	out := Rotated{}
	for _, r := range in {
		if existing, ok := out[r.Secret]; ok && existing.At.After(r.At) {
			continue
		}
		out[r.Secret] = r
	}
	return out
}

// Compare works out what a run introduced and what went away.
//
// Three inputs because the question needs three, and collapsing them is how
// a secret gets closed by somebody deleting a line.
//
//	run        what the scanner just found
//	accepted   the debt this organisation decided to stop reporting
//	previous   what the last run found, which is not the same thing
//
// New is measured against the accepted debt, because that is what a gate is
// for. Gone is measured against the previous run, because that is the only
// thing that knows a secret used to be there — and a secret is never in the
// accepted debt, since accepting one is deciding not to rotate a credential
// that is in the history.
func Compare(run, accepted, previous []Alert, rotated Rotated,
	at time.Time) Triage {

	var t Triage
	base := Of(accepted, at)
	was := map[string]Alert{}
	for _, a := range previous {
		was[a.Fingerprint()] = a
	}

	seen := map[string]bool{}
	for _, a := range run {
		f := a.Fingerprint()
		seen[f] = true
		if !a.Stable() {
			t.Churned++
		}
		if base.Has(a) {
			t.Carried = append(t.Carried, a)
			continue
		}
		t.Introduced = append(t.Introduced, a)
	}

	// What the last run had and this one does not.
	gone := map[string]Alert{}
	for f, a := range was {
		if !seen[f] {
			gone[f] = a
		}
	}
	// And anything in the accepted debt that has stopped appearing, which
	// the previous run may not have covered.
	for _, f := range base.Keys() {
		if seen[f] {
			continue
		}
		if _, known := gone[f]; !known {
			gone[f] = Alert{}
		}
	}
	for f, a := range gone {
		if a.Kind != Secret {
			t.Cleared = append(t.Cleared, f)
			continue
		}
		// A secret never simply goes away. Deleting the line changed the
		// working tree; the commit is still in the history. Only a recorded
		// rotation closes it.
		if _, done := rotated[f]; done {
			t.Cleared = append(t.Cleared, f)
			continue
		}
		t.Vanished = append(t.Vanished, f)
	}

	sort.Slice(t.Introduced, func(i, j int) bool {
		if t.Introduced[i].Severity != t.Introduced[j].Severity {
			return t.Introduced[i].Severity > t.Introduced[j].Severity
		}
		return t.Introduced[i].Fingerprint() < t.Introduced[j].Fingerprint()
	})
	sort.Strings(t.Cleared)
	sort.Strings(t.Vanished)
	return t
}

// Group is one rule, and everywhere it fired.
//
// The queue groups by rule and enclosing symbol rather than listing every
// occurrence, for the reason internal/vuln groups by advisory: four hundred
// alerts for one bad pattern in one helper is one piece of work, and a list
// that spends four hundred rows on it pushes the next rule off the page.
type Group struct {
	Tool string  `json:"tool"`
	Rule string  `json:"rule"`
	Kind Kind    `json:"kind"`
	At   []Alert `json:"at"`
}

// Worst is the highest-severity alert in the group.
func (g Group) Worst() Alert { return g.At[0] }

// Count is how many places this rule fired.
func (g Group) Count() int { return len(g.At) }

// Where names the first few places, and says how many more.
func (g Group) Where(limit int) string {
	var out []string
	for i, a := range g.At {
		if i >= limit {
			return fmt.Sprintf("%s and %d more", strings.Join(out, ", "),
				len(g.At)-limit)
		}
		where := a.Path
		if a.Line > 0 {
			where = fmt.Sprintf("%s:%d", a.Path, a.Line)
		}
		out = append(out, where)
	}
	return strings.Join(out, ", ")
}

// Groups folds alerts into one entry per rule, worst first.
func Groups(in []Alert) []Group {
	at := map[string]int{}
	var out []Group
	for _, a := range in {
		key := a.Tool + "\x00" + a.Rule
		if i, seen := at[key]; seen {
			out[i].At = append(out[i].At, a)
			continue
		}
		at[key] = len(out)
		out = append(out, Group{Tool: a.Tool, Rule: a.Rule, Kind: a.Kind,
			At: []Alert{a}})
	}
	for i := range out {
		sort.SliceStable(out[i].At, func(x, y int) bool {
			return out[i].At[x].Severity > out[i].At[y].Severity
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Worst().Severity != out[j].Worst().Severity {
			return out[i].Worst().Severity > out[j].Worst().Severity
		}
		if out[i].Count() != out[j].Count() {
			return out[i].Count() > out[j].Count()
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// Findings turns a triage into the register.
func Findings(t Triage, previous []Alert, now time.Time) []finding.Finding {
	was := map[string]Alert{}
	for _, a := range previous {
		was[a.Fingerprint()] = a
	}
	var out []finding.Finding
	add := func(id string, kind finding.Kind, sev telemetry.Severity,
		title, what string) {

		f := finding.Finding{
			Kind: kind, Title: title, Source: "appsec",
			Entity:   telemetry.ID{Issuer: "code", Value: id},
			Severity: sev, State: finding.Open, Seen: 1,
			First: now, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "appsec", What: what,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}

	// The secrets first, because they are the only kind here where the
	// severity is a fact rather than an inference.
	for _, f := range t.Vanished {
		a := was[f]
		add(f, finding.FromCode, telemetry.SeverityCritical,
			fmt.Sprintf("a credential %s found is gone from the tree and "+
				"has not been rotated", a.Tool),
			"the commit is still in the history and, if the branch was ever "+
				"pushed, on a server, in every clone and in the CI cache. "+
				"Removing the line changed the working tree and nothing "+
				"else; the only fix is rotation")
	}
	for _, g := range Groups(t.Introduced) {
		a := g.Worst()
		sev := a.Severity
		if g.Kind == Secret {
			// A verified secret is a fact. An unverified one is a string
			// that looks like a credential, which is still worth someone
			// looking at today rather than in the backlog.
			sev = telemetry.SeverityHigh
			if a.Verified {
				sev = telemetry.SeverityCritical
			}
		}
		kind := finding.FromCode
		if g.Kind == Dependency {
			kind = finding.FromVulnerability
		}
		where := g.Where(3)
		add(a.Fingerprint(), kind, sev,
			fmt.Sprintf("%s: %s, in %d place(s)", a.Tool, a.Rule, g.Count()),
			fmt.Sprintf("%s. %s", messageOf(a), where))
	}
	if t.Churned > 0 {
		add("churn", finding.FromCode, telemetry.SeverityLow,
			fmt.Sprintf("%d alert(s) are identified by their path", t.Churned),
			"the tool gave no fingerprint and no enclosing symbol, so a "+
				"rename or a move will close these and open them again as "+
				"new. Every age and every trend over them is measuring "+
				"whitespace")
	}
	return finding.Rank(out, now)
}

func messageOf(a Alert) string {
	if m := strings.TrimSpace(a.Message); m != "" {
		return m
	}
	return a.Rule
}

// Gate is the answer to whether a change may merge.
//
// On what it introduced and never on what the codebase carries. A gate on
// total debt means nothing merges and is switched off within a month.
type Gate struct {
	// Blocked are the new alerts at or above the threshold.
	Blocked []Alert `json:"blocked,omitempty"`
	// Secrets are new secrets, which block at any severity.
	Secrets []Alert `json:"secrets,omitempty"`
	// Carried is how many the codebase already had, reported so that a
	// clean gate does not read as a clean codebase.
	Carried int `json:"carried"`
}

// Passes reports whether the change may merge.
func (g Gate) Passes() bool {
	return len(g.Blocked) == 0 && len(g.Secrets) == 0
}

// Why explains a gate in one line.
func (g Gate) Why(at telemetry.Severity) string {
	switch {
	case len(g.Secrets) > 0:
		return fmt.Sprintf(
			"%d new secret(s). A credential in a commit is in the history "+
				"whatever happens next, so this one blocks at any severity",
			len(g.Secrets))
	case len(g.Blocked) > 0:
		return fmt.Sprintf(
			"%d new alert(s) at %v or above. The %d the codebase already "+
				"carried are not counted here: a gate on those is one that "+
				"gets switched off", len(g.Blocked), at, g.Carried)
	default:
		return fmt.Sprintf(
			"nothing new at %v or above. The codebase carries %d, which "+
				"this does not gate on and does not pretend is zero",
			at, g.Carried)
	}
}

// Check decides whether a change may merge.
func Check(t Triage, at telemetry.Severity) Gate {
	g := Gate{Carried: len(t.Carried)}
	for _, a := range t.Introduced {
		if a.Kind == Secret {
			g.Secrets = append(g.Secrets, a)
			continue
		}
		if a.Severity >= at {
			g.Blocked = append(g.Blocked, a)
		}
	}
	return g
}
