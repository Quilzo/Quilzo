// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package review

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/workforce"
)

// Closing a review, and the measure that says whether one happened.
//
// An item is not closed by the reviewer deciding. A keep closes on the
// decision; a revoke closes when the account is gone from a later import, and
// a reduce when the privilege is. The connector closes the review, which is
// the half of this control that fails and the half no product measures.

// Shape is what a campaign's decisions looked like.
//
// Reported as a property of the evidence rather than as an accusation, the
// way internal/assurance reports a control that has never failed. An auditor
// sampling a review asks these questions; the version where they ask first is
// the expensive one.
type Shape struct {
	Decisions int `json:"decisions"`
	// Kept, Revoked and Reduced are the split.
	Kept    int `json:"kept"`
	Revoked int `json:"revoked"`
	Reduced int `json:"reduced"`
	// Median is the middle decision's duration, and Hasty how many were
	// under the floor below which somebody cannot have read the row.
	Median time.Duration `json:"median"`
	Hasty  int           `json:"hasty"`
	// Span is from the first decision to the last. A campaign decided in
	// one unbroken run is a rubber stamp whatever each decision took.
	Span time.Duration `json:"span"`
	// Reviewers is how many people decided anything.
	Reviewers int `json:"reviewers"`
}

// RubberStamped reports whether the shape is one nobody can defend.
//
// Everything kept, decided faster than a person can read, in one sitting.
// Any one of those alone is defensible — a small team, a reviewer who knows
// the answers, an hour set aside. All three together is a held-down key.
func (s Shape) RubberStamped() bool {
	if s.Decisions < 10 {
		// Too few to have a shape. Five decisions in a minute is five
		// decisions in a minute.
		return false
	}
	return s.Revoked+s.Reduced == 0 && s.Median < MinThought &&
		s.Span < MaxSitting
}

// Why explains a shape in one line.
func (s Shape) Why() string {
	switch {
	case s.Decisions == 0:
		return "nothing has been decided"
	case s.RubberStamped():
		return fmt.Sprintf(
			"%d decisions, every one of them keep, a median of %s each, all "+
				"within %s. That is what a held-down key looks like, and it "+
				"is what an auditor samples for", s.Decisions,
			s.Median.Round(time.Millisecond), s.Span.Round(time.Second))
	case s.Hasty > s.Decisions/2:
		return fmt.Sprintf(
			"%d of %d decisions took under %s, which is less than it takes "+
				"to read the row", s.Hasty, s.Decisions, MinThought)
	case s.Revoked+s.Reduced == 0 && s.Decisions >= 10:
		return fmt.Sprintf(
			"%d decisions and not one change. A review that never removes "+
				"anything is either an estate with no drift or a review "+
				"that is not looking", s.Decisions)
	default:
		return fmt.Sprintf("%d decisions by %d reviewer(s): %d kept, %d "+
			"revoked, %d reduced", s.Decisions, s.Reviewers, s.Kept,
			s.Revoked, s.Reduced)
	}
}

// Measure works out the shape of a campaign's decisions.
func Measure(in []Decision) Shape {
	var s Shape
	if len(in) == 0 {
		return s
	}
	var took []time.Duration
	var first, last time.Time
	who := map[string]bool{}
	for _, d := range Latest(in) {
		s.Decisions++
		who[d.By] = true
		switch d.Verdict {
		case Keep:
			s.Kept++
		case Revoke:
			s.Revoked++
		case Reduce:
			s.Reduced++
		}
		if d.Took > 0 {
			took = append(took, d.Took)
			if d.Took < MinThought {
				s.Hasty++
			}
		}
		if first.IsZero() || d.At.Before(first) {
			first = d.At
		}
		if d.At.After(last) {
			last = d.At
		}
	}
	s.Reviewers = len(who)
	s.Span = last.Sub(first)
	if len(took) > 0 {
		sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
		s.Median = took[len(took)/2]
	}
	return s
}

// Standing is where one item stands.
type Standing string

const (
	// Undecided is nobody has looked at it.
	Undecided Standing = "undecided"
	// Settled is it was kept, which needs nothing further.
	Settled Standing = "settled"
	// Committed is a change was decided and the deadline has not passed.
	Committed Standing = "committed"
	// Unremediated is a change was decided, the deadline has passed, and
	// the access is still there.
	//
	// The finding this package exists for. Every product reports the
	// campaign as complete at this point.
	Unremediated Standing = "unremediated"
	// Done is a change was decided and the access is gone.
	Done Standing = "done"
)

// Outcome is one item with everything known about it.
type Outcome struct {
	Item     Item      `json:"item"`
	Decision *Decision `json:"decision,omitempty"`
	Standing Standing  `json:"standing"`
	// Still says the access is present in the later import.
	Still bool `json:"still,omitempty"`
}

// Close works out where a campaign stands, against a later import.
//
// The import is what closes it. A revoke is not done because somebody said
// so; it is done because the account is absent from what the system reported
// afterwards, which is the only evidence an auditor will accept and the one
// nobody gathers.
func Close(c Campaign, items []Item, decisions []Decision,
	after []workforce.Identity, now time.Time) []Outcome {

	byKey := Latest(decisions)
	present := map[string]workforce.Identity{}
	for _, id := range after {
		present[strings.ToLower(id.ID.String())] = id
	}
	// Whether a later import happened at all. Without one, a change cannot
	// be reported as unremediated — it can only be reported as unverified,
	// and calling those the same would accuse a team of not acting when
	// nobody has looked.
	verified := len(after) > 0

	var out []Outcome
	for _, item := range sortedItems(items, now) {
		o := Outcome{Item: item, Standing: Undecided}
		d, decided := byKey[item.Key()]
		if decided {
			copied := d
			o.Decision = &copied
		}
		switch {
		case !decided:
		case !d.Verdict.Changes():
			o.Standing = Settled
		default:
			id, still := present[strings.ToLower(item.Account.String())]
			o.Still = still
			switch {
			case !verified:
				o.Standing = Committed
			case d.Verdict == Revoke && !still:
				o.Standing = Done
			case d.Verdict == Reduce && still && !id.Live():
				// Reduced and the account is disabled, which is more than
				// was asked for and is not a failure.
				o.Standing = Done
			case now.Before(c.Remediate):
				o.Standing = Committed
			default:
				o.Standing = Unremediated
			}
		}
		out = append(out, o)
	}
	return out
}

// Report is what a campaign adds up to.
type Report struct {
	Campaign     string `json:"campaign"`
	Shape        Shape  `json:"shape"`
	Items        int    `json:"items"`
	Undecided    int    `json:"undecided"`
	Unremediated int    `json:"unremediated"`
	Committed    int    `json:"committed"`
	Done         int    `json:"done"`
	// Dormant is how many accounts nobody had used in ninety days.
	Dormant int `json:"dormant"`
	// Missing names issuers the campaign covers that no item came from.
	Missing []string `json:"missing,omitempty"`
	// Verified says a later import was supplied at all.
	//
	// A fact about the input rather than about the outcomes. A campaign
	// where every decision was keep has nothing to verify and has still
	// been checked against what the system reports.
	Verified bool `json:"verified"`
}

// Why explains a report in one line, leading with the half that fails.
func (r Report) Why() string {
	switch {
	case len(r.Missing) > 0:
		// Names the systems, not the campaign. "The campaign covers
		// q3-access" is a sentence about the wrong noun, and a report whose
		// first line does not parse is one nobody reads the second line of.
		return fmt.Sprintf(
			"nothing was reviewed from %s, which this campaign covers. A "+
				"review of whatever happened to be exported is narrower "+
				"than it claims", strings.Join(r.Missing, ", "))
	case r.Unremediated > 0:
		return fmt.Sprintf(
			"%d access(es) were decided for removal, the date has passed, "+
				"and they are still there. Every product reports this "+
				"campaign as complete", r.Unremediated)
	case r.Undecided > 0:
		return fmt.Sprintf("%d of %d item(s) undecided", r.Undecided,
			r.Items)
	case !r.Verified && r.Shape.Revoked+r.Shape.Reduced > 0:
		return "every item decided, and no later import has been " +
			"supplied. A revocation is done when the account is gone from " +
			"what the system reports, not when somebody says so"
	case r.Shape.Revoked+r.Shape.Reduced == 0:
		return fmt.Sprintf(
			"every one of %d item(s) decided and nothing to remove",
			r.Items)
	default:
		return fmt.Sprintf("every item decided and %d change(s) verified "+
			"gone", r.Done)
	}
}

// Summarise adds up a campaign.
//
// The later import is passed rather than inferred from the outcomes: a
// campaign where every decision was keep has nothing to verify, and deriving
// "verified" from the outcomes made it report that no import had been
// supplied when one had.
func Summarise(c Campaign, items []Item, decisions []Decision,
	outcomes []Outcome, after []workforce.Identity, now time.Time) Report {

	r := Report{Campaign: c.ID, Shape: Measure(decisions),
		Items: len(items), Verified: len(after) > 0}
	for _, o := range outcomes {
		switch o.Standing {
		case Undecided:
			r.Undecided++
		case Unremediated:
			r.Unremediated++
		case Committed:
			r.Committed++
		case Done:
			r.Done++
		}
		if o.Item.Dormant(now, 90*24*time.Hour) {
			r.Dormant++
		}
	}
	saw := map[string]bool{}
	for _, item := range items {
		saw[strings.ToLower(item.Account.Issuer)] = true
	}
	for _, s := range c.Scope {
		if !saw[strings.ToLower(s)] {
			r.Missing = append(r.Missing, s)
		}
	}
	sort.Strings(r.Missing)
	return r
}

// Findings turns a campaign's state into the register.
func Findings(c Campaign, r Report, outcomes []Outcome,
	now time.Time) []finding.Finding {

	var out []finding.Finding
	add := func(entity telemetry.ID, sev telemetry.Severity,
		title, what string) {

		f := finding.Finding{
			Kind: finding.FromControl, Title: title, Source: "review",
			Entity: entity, Severity: sev, State: finding.Open, Seen: 1,
			Owner: c.By, First: c.Opened, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "review", What: what,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}
	campaign := telemetry.ID{Issuer: "review", Value: c.ID}

	for _, o := range outcomes {
		if o.Standing != Unremediated {
			continue
		}
		add(o.Item.Account, telemetry.SeverityHigh,
			fmt.Sprintf("%s was decided for %s on %s and is still there",
				o.Item.Account.String(), o.Decision.Verdict,
				o.Decision.At.Format("2006-01-02")),
			fmt.Sprintf(
				"the campaign asked for this by %s. The control is review "+
					"and remediate, and this is the half that fails: every "+
					"product reports the campaign as complete at this point",
				c.Remediate.Format("2006-01-02")))
	}
	if len(r.Missing) > 0 {
		add(campaign, telemetry.SeverityHigh,
			fmt.Sprintf("%s covers %s and reviewed nothing from there",
				c.ID, strings.Join(r.Missing, ", ")),
			"a review of whatever happened to be exported is silently "+
				"narrower than it claims, and nothing afterwards can tell")
	}
	if r.Shape.RubberStamped() {
		add(campaign, telemetry.SeverityMedium,
			fmt.Sprintf("%s has the shape of a rubber stamp", c.ID),
			r.Shape.Why())
	}
	if r.Undecided > 0 && now.After(c.Due) {
		add(campaign, telemetry.SeverityMedium,
			fmt.Sprintf("%s has %d item(s) undecided past its date", c.ID,
				r.Undecided),
			fmt.Sprintf("the decisions were due %s",
				c.Due.Format("2006-01-02")))
	}
	if !r.Verified && r.Shape.Revoked+r.Shape.Reduced > 0 &&
		now.After(c.Remediate) {
		add(campaign, telemetry.SeverityMedium,
			fmt.Sprintf("%s has %d change(s) nobody has verified", c.ID,
				r.Shape.Revoked+r.Shape.Reduced),
			"a revocation is done when the account is gone from what the "+
				"system reports afterwards, and no later import has been "+
				"supplied")
	}
	return finding.Rank(out, now)
}

// From builds the items for a campaign out of a workforce import.
//
// What the reviewer is shown, in the order that makes the easy decisions
// easy: dormant accounts first, then privileged ones. An account nobody has
// touched in ninety days is a decision that makes itself, and putting it
// forty rows down is how it gets kept.
func From(c Campaign, in []workforce.Identity, now time.Time) []Item {
	var out []Item
	for _, id := range in {
		if id.Subject == workforce.ADevice || !c.Covers(id.ID) {
			continue
		}
		item := Item{Campaign: c.ID, Account: id.ID, Seen: id.Seen}
		if name := strings.TrimSpace(id.Name); name != "" {
			item.Person = name
		} else if id.Email != "" {
			item.Person = id.Email
		}
		if role := id.Attributes["role"]; role != "" {
			item.Role = role
		}
		if strings.EqualFold(id.Attributes["privileged"], "true") ||
			strings.EqualFold(id.Attributes["admin"], "true") {
			item.Privileged = true
		}
		out = append(out, item)
	}
	return sortedItems(out, now)
}
