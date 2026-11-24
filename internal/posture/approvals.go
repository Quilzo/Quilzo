// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"fmt"
	"strings"
	"time"
)

// The security record's approvals, as the posture sees them.
//
// A decision made alone carries a review by somebody else, due within the
// separation policy's days; a review that has not come by then is a
// decision nobody checked, and it is reported until it does. An approval
// that has lapsed is a decision nobody holds any more: the risk is no longer
// accepted, the exception no longer granted, by anybody, until it is
// decided again. Both are facts the approvals module reads from the
// register (internal/approval) and the caller hands over here, as every
// other input is.

// ApprovalFacts is what the approvals in the register owe.
type ApprovalFacts struct {
	Checked bool `json:"checked"`
	// Overdue are the decisions made alone whose review is past due, and
	// Lapsed the approvals that have stopped counting.
	Overdue []ApprovalFact `json:"overdue,omitempty"`
	Lapsed  []ApprovalFact `json:"lapsed,omitempty"`
}

// ApprovalFact is one decision: the record, what it is, and the day that
// passed.
type ApprovalFact struct {
	Record string    `json:"record"`
	Kind   string    `json:"kind"`
	Label  string    `json:"label,omitempty"`
	Due    time.Time `json:"due"`
}

func (f ApprovalFact) named() string {
	if f.Label != "" {
		return fmt.Sprintf("the %s %s (%s)", strings.ToLower(f.Kind), f.Label, f.Record)
	}
	return fmt.Sprintf("the %s %s", strings.ToLower(f.Kind), f.Record)
}

func init() {
	rules = append(rules,
		Rule{
			ID:       "approval.review-overdue",
			Title:    "A decision made alone has not had its compensating review",
			Severity: Medium,
			Controls: []string{"AC-5", "CA-7"},
			Remind:   true,
			Why: "AC-5 asks that no one person both raises and decides what the organisation answers for. A team " +
				"of one cannot keep that rule at the time, so its decision is marked as made alone and a review by " +
				"somebody else is owed: an executive, the risk function or an adviser from outside. A review that " +
				"has not come by its day is a decision nobody but its maker ever looked at.",
			Check: func(s State) []Finding {
				var out []Finding
				for _, f := range s.Approvals.Overdue {
					out = append(out, Finding{Resource: f.Record,
						Detail: fmt.Sprintf("%s was approved alone, and its review by somebody else was due on %s",
							f.named(), f.Due.UTC().Format("2 Jan 2006")),
						Fix: "quilzo approval review " + f.Record + " upheld --surface HASH  # by somebody else, or in the admin under Register › Approvals"})
				}
				return out
			},
		},
		Rule{
			ID:       "approval.lapsed",
			Title:    "An approval in the security record has lapsed",
			Severity: Medium,
			Controls: []string{"AC-5", "RA-7"},
			Remind:   true,
			Why: "An approval is given for a term. Once it has passed, what it decided (a risk accepted, an " +
				"exception granted, a scope approved) is held by nobody, and it is decided again or it stands " +
				"as a problem. A lapse nobody is told of is a decision that quietly became nobody's.",
			Check: func(s State) []Finding {
				var out []Finding
				for _, f := range s.Approvals.Lapsed {
					out = append(out, Finding{Resource: f.Record,
						Detail: fmt.Sprintf("the approval of %s lapsed on %s", f.named(), f.Due.UTC().Format("2 Jan 2006")),
						Fix:    "propose it again, and approve it: quilzo approval list"})
				}
				return out
			},
		},
	)
}
