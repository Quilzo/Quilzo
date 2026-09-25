// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package finding is the one thing a security team actually works on.
//
// # Why one type and not five
//
// A detection fired. A dependency has a CVE. A control failed its check. A
// questionnaire answer is missing. A vendor's certification lapsed. Five
// products sell these as five things, with five queues, five owners and five
// definitions of "closed" — and a small team then spends its attention on the
// seams rather than on the work.
//
// They are one thing: something is wrong, somebody owns it, here is the
// evidence, and it ends in fixed, accepted or no-longer-true. The kind is a
// field. Everything else — triage, ownership, ageing, ranking, the audit
// trail — is written once.
//
// # Ranking, not thresholds
//
// Risk-based alerting is usually sold as "score events, alert above 100". The
// first real evaluation of it (Uetz et al., submitted to USENIX Security '27,
// arXiv:2609.02465) found the threshold form is not where the benefit is:
// reformulated as continuous prioritisation across eight datasets it scored
// mean AUROC 0.92 against 0.72 for ranking by severity alone, and the authors
// note prior claims for RBA were "mostly guesswork based on anecdotal
// evidence".
//
// So there is no threshold here. Rank() orders what exists and the team works
// down the list. A threshold has to be tuned, drifts as content is added, and
// converts "what should I look at" into "what did we decide the number was" —
// and Splunk's own guidance to keep the threshold fixed and tune the scores
// instead pushes all that pressure onto a much larger, more fragile surface.
//
// # Age is evidence, not decoration
//
// A finding open for ninety days is a different object from the same finding
// opened this morning, and the difference is not that it became more severe.
// It is that somebody decided not to act, repeatedly, without recording why.
// Rank puts weight on age for that reason, and Accept exists so the decision
// can be recorded instead.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Kind is what produced a finding. The field that replaces five queues.
type Kind string

const (
	// FromDetection is a rule that matched telemetry.
	FromDetection Kind = "detection"
	// FromVulnerability is a known weakness in something installed.
	FromVulnerability Kind = "vulnerability"
	// FromControl is a configuration check that failed.
	FromControl Kind = "control"
	// FromQuestionnaire is an unanswered or failing assurance question.
	FromQuestionnaire Kind = "questionnaire"
	// FromVendor is something wrong with a third party you rely on.
	FromVendor Kind = "vendor"
)

// Kinds lists them, for a caller validating input.
func Kinds() []Kind {
	return []Kind{FromDetection, FromVulnerability, FromControl,
		FromQuestionnaire, FromVendor}
}

func (k Kind) known() bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// State is where a finding is in its life.
type State string

const (
	// Open is nobody has looked yet.
	Open State = "open"
	// Triaged is somebody looked and it is real.
	Triaged State = "triaged"
	// Accepted is somebody decided not to fix it, on the record.
	//
	// Not the same as closed, and deliberately harder to reach: an accepted
	// finding keeps its evidence, keeps its owner, and expires. A risk
	// accepted once and never revisited is the commonest way a register
	// becomes fiction.
	Accepted State = "accepted"
	// Fixed is the underlying thing changed.
	Fixed State = "fixed"
	// Stale is it stopped being reported and nobody said why.
	//
	// Distinct from Fixed on purpose. A scanner that stops mentioning a
	// vulnerability may mean it was patched, or that the scanner broke, or
	// that the asset dropped out of inventory. Recording the second as the
	// first is how a register reports progress it did not make.
	Stale State = "stale"
)

// Evidence is one thing that supports a finding.
//
// Kept on the finding rather than fetched later. What a scanner said in March
// is not recoverable from the scanner in September, and an accepted risk
// whose justification cannot be reconstructed is an audit failure regardless
// of whether the decision was right.
type Evidence struct {
	At time.Time `json:"at"`
	// What is the claim, in one line.
	What string `json:"what"`
	// Source is what produced it: a rule id, a scanner, a connector.
	Source string `json:"source"`
	// Ref points into the tamper-evident record where one exists — an audit
	// entry hash, an object id. Empty when the evidence is only prose.
	Ref string `json:"ref,omitempty"`
	// Tainted marks evidence derived from attacker-controlled input.
	//
	// Log text is written by whoever can reach the log, which on an
	// authentication source includes whoever is attacking it. A finding
	// resting on tainted evidence may be entirely real and still must not be
	// actioned without a person: the measured attack success rate against
	// models reading telemetry is 83-88%, and the residual after the best
	// known layered defences is 8-12%.
	Tainted bool `json:"tainted,omitempty"`
}

// Finding is something wrong that somebody owns.
type Finding struct {
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	Title string `json:"title"`

	// Source is the rule, scanner or connector that raised it.
	Source string `json:"source"`
	// Entity is what it is about, issuer-qualified so that the same account
	// seen through two platforms is one entity and not two findings.
	Entity telemetry.ID `json:"entity"`

	Severity telemetry.Severity `json:"severity"`
	State    State              `json:"state"`

	// Owner is the person accountable. Empty is a finding nobody is doing
	// anything about, which is a fact worth being able to sort by.
	Owner string `json:"owner,omitempty"`

	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	// Seen is how many times this has been observed.
	//
	// One finding with a count, not five hundred findings. Deduplication is
	// the difference between a register somebody reads and a queue nobody
	// does — and the count is itself evidence: the same misconfiguration
	// reported daily for a month is a different conversation from one seen
	// once.
	Seen int `json:"seen"`

	Evidence []Evidence `json:"evidence,omitempty"`

	// Because is why it was accepted, and Until when that expires.
	Because string    `json:"because,omitempty"`
	Until   time.Time `json:"until,omitempty"`

	// Technique are ATT&CK ids, for navigation. Never summed into a score;
	// see internal/detect for why a coverage figure would be dishonest.
	Technique []string `json:"technique,omitempty"`
}

// Key is the identity a finding is deduplicated on.
//
// Derived rather than assigned, so the same underlying problem reported by
// two runs of the same scanner is one finding. Kind, source and entity: the
// title is deliberately excluded because scanners reword their messages
// between versions, and a register that split a finding in half because a
// vendor improved their phrasing would double-count every upgrade.
func Key(kind Kind, source string, entity telemetry.ID) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		string(kind), strings.ToLower(strings.TrimSpace(source)),
		strings.ToLower(strings.TrimSpace(entity.Issuer)),
		strings.ToLower(strings.TrimSpace(entity.Value)),
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// Validate refuses a finding that cannot be worked on.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.ID) == "" {
		return fmt.Errorf("a finding needs an id")
	}
	if !f.Kind.known() {
		return fmt.Errorf("%s is not a kind of finding", f.Kind)
	}
	if strings.TrimSpace(f.Title) == "" {
		return fmt.Errorf("%s has no title, so a queue of them is unreadable",
			f.ID)
	}
	if strings.TrimSpace(f.Source) == "" {
		return fmt.Errorf(
			"%s names no source. A finding nobody can trace to what raised "+
				"it cannot be verified, re-run, or switched off when it is "+
				"wrong", f.ID)
	}
	if f.First.IsZero() || f.Last.IsZero() {
		return fmt.Errorf("%s has no age, and age is most of its weight", f.ID)
	}
	if f.State == Accepted {
		if strings.TrimSpace(f.Because) == "" {
			return fmt.Errorf(
				"%s is accepted with no reason. An accepted risk whose "+
					"justification nobody wrote down is indistinguishable "+
					"from one nobody noticed", f.ID)
		}
		if f.Until.IsZero() {
			return fmt.Errorf(
				"%s is accepted for ever. A risk accepted once and never "+
					"revisited is the commonest way a register becomes "+
					"fiction; acceptance has to expire", f.ID)
		}
	}
	return nil
}

// Tainted reports whether any evidence came from attacker-controlled input.
func (f Finding) Tainted() bool {
	for _, e := range f.Evidence {
		if e.Tainted {
			return true
		}
	}
	return false
}

// NeedsAPerson reports whether this may not be actioned automatically.
//
// The same rule internal/agent applies to content, for the same reason and
// with better evidence: an attacker who can write a log line can write a
// prompt, and a finding whose evidence is that log line is a finding an
// attacker had a hand in composing. It may be entirely correct. It still gets
// a human before anything acts on it.
func (f Finding) NeedsAPerson() string {
	if !f.Tainted() {
		return ""
	}
	var from []string
	for _, e := range f.Evidence {
		if e.Tainted {
			from = append(from, e.Source)
		}
	}
	sort.Strings(from)
	return fmt.Sprintf(
		"evidence for %s came from %s, which is written by whoever can reach "+
			"it — including whoever is being detected. A person decides.",
		f.ID, strings.Join(dedupe(from), ", "))
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Age is how long this has been open at a given moment.
func (f Finding) Age(now time.Time) time.Duration { return now.Sub(f.First) }

// Expired reports whether an acceptance has run out.
func (f Finding) Expired(now time.Time) bool {
	return f.State == Accepted && !f.Until.IsZero() && now.After(f.Until)
}

// Weight is how far up the list this belongs. Higher is more urgent.
//
// Not a threshold and not a percentage. It orders a list, and the only claim
// made for it is that the thing at the top is worth looking at before the
// thing below it. Every term is stated here rather than tuned in a file,
// because a weight somebody can change without reading this is a weight
// nobody can explain afterwards.
func (f Finding) Weight(now time.Time) float64 {
	if f.State == Fixed || f.State == Stale {
		return 0
	}
	// Severity is the base and is deliberately not the whole answer: ranking
	// by severity alone is the baseline the RBA evaluation beat, 0.72 to
	// 0.92.
	w := float64(f.Severity) * 10

	// Age, capped. An old finding is evidence of a decision not made, and
	// beyond a month the signal stops growing — something ignored for a year
	// is not twelve times the problem of something ignored for a month, it is
	// the same problem with a worse story.
	days := f.Age(now).Hours() / 24
	if days > 30 {
		days = 30
	}
	if days > 0 {
		w += days
	}

	// Recurrence, sub-linearly. The tenth sighting says much less than the
	// second, and without saturation a noisy source dominates the list
	// purely by being noisy — which is the failure mode that makes people
	// turn ranking off.
	if f.Seen > 1 {
		w += 10 * float64(f.Seen) / float64(f.Seen+9)
	}

	// Nobody owns it. Not a severity judgement: an unowned finding is one
	// that will still be here next month whatever its severity, so it needs
	// to surface while somebody can still pick it up.
	if strings.TrimSpace(f.Owner) == "" {
		w += 5
	}

	// An acceptance that has run out is worse than an open finding, because
	// it is an open finding that the register is reporting as handled.
	if f.Expired(now) {
		w += 25
	}
	return w
}

// Rank orders findings, most urgent first.
func Rank(in []Finding, now time.Time) []Finding {
	out := append([]Finding(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		wi, wj := out[i].Weight(now), out[j].Weight(now)
		if wi != wj {
			return wi > wj
		}
		// A stable order for equal weights, so the list reads the same twice
		// running and a team working down it does not see it reshuffle.
		return out[i].ID < out[j].ID
	})
	return out
}

// Why explains a weight in the terms it was computed from.
func (f Finding) Why(now time.Time) string {
	parts := []string{fmt.Sprintf("severity %d", f.Severity)}
	if d := int(f.Age(now).Hours() / 24); d > 0 {
		parts = append(parts, fmt.Sprintf("open %d day(s)", d))
	}
	if f.Seen > 1 {
		parts = append(parts, fmt.Sprintf("seen %d times", f.Seen))
	}
	if strings.TrimSpace(f.Owner) == "" {
		parts = append(parts, "unowned")
	}
	if f.Expired(now) {
		parts = append(parts, "acceptance expired")
	}
	return strings.Join(parts, ", ")
}

// Register holds findings and deduplicates them.
type Register struct {
	byKey map[string]*Finding
}

// NewRegister starts an empty one.
func NewRegister() *Register { return &Register{byKey: map[string]*Finding{}} }

// Record adds a finding or folds it into the one already there.
//
// Returns the finding as it now stands, and whether it was new. Folding
// rather than appending is what keeps a register readable: the same failing
// control reported hourly is one row with a count, not seven hundred rows.
func (r *Register) Record(f Finding, at time.Time) (*Finding, bool) {
	key := Key(f.Kind, f.Source, f.Entity)
	if f.ID == "" {
		f.ID = key
	}
	if f.First.IsZero() {
		f.First = at
	}
	f.Last = at
	if f.Seen == 0 {
		f.Seen = 1
	}

	existing, seen := r.byKey[key]
	if !seen {
		copied := f
		r.byKey[key] = &copied
		return &copied, true
	}

	existing.Last = at
	existing.Seen++
	existing.Evidence = append(existing.Evidence, f.Evidence...)
	// Severity can rise and does not fall on its own. A control that failed
	// worse today is worse; one that reported lower today may simply have
	// been scanned differently, and quietly downgrading it would let a
	// flapping scanner talk a finding down.
	if f.Severity > existing.Severity {
		existing.Severity = f.Severity
	}
	// Re-opening. Something reported again is not fixed, whatever anybody
	// ticked — and saying so is the whole reason to keep one row.
	if existing.State == Fixed || existing.State == Stale {
		existing.State = Open
	}
	return existing, false
}

// All returns every finding, ranked.
func (r *Register) All(now time.Time) []Finding {
	out := make([]Finding, 0, len(r.byKey))
	for _, f := range r.byKey {
		out = append(out, *f)
	}
	return Rank(out, now)
}

// Len is how many findings the register holds.
func (r *Register) Len() int { return len(r.byKey) }
