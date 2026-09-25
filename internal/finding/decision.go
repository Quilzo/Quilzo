// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// A finding's state is the fold of an append-only log, not an editable field.
//
// # Why the obvious design is wrong
//
// Every GRC tool models this as a row with a status column that people
// update. It is the natural thing to build and it destroys the only property
// that matters: an auditor asking "who accepted this, when, and on what
// grounds" is asking about the past, and a mutable column has no past. The
// answer it gives is whatever the column says now, which is exactly as
// trustworthy as the last person with write access.
//
// This program already has the machinery for the other design. The audit log
// is a hash chain with a Merkle tree over it and dual Ed25519 + ML-DSA-65
// signatures; internal/siem exports it as OCSF with the record_integrity
// profile. So a triage decision is recorded there, and a finding's state is
// computed by replaying what was recorded.
//
// The register becomes a projection. Nothing edits a finding: things are said
// about it, in order, permanently, and the current state is what those
// statements add up to. Rewriting history requires forging a hash chain and
// two signatures, one of which is post-quantum.
//
// # What that buys, concretely
//
// "This risk was accepted on 3 March by Dana, because the component is not
// reachable from the internet, until 1 June; it lapsed and was re-accepted on
// 2 June by Kit on the same grounds" is a sentence the log can produce and a
// status column cannot. It is also, in most frameworks, the actual control —
// not that risks are accepted, but that acceptance is authorised, justified
// and reviewed.
//
// # A model cannot close a finding
//
// The rule the agent design already applies to publishing, arriving where it
// matters more. internal/agent refuses self-approval because "approvals must
// come from principals and a model is not a principal", and a finding is the
// same shape of judgement: somebody is deciding that a risk is acceptable, or
// that an alert is noise. A model that can close its own findings can close
// the one that would have caught it.
//
// So Decide refuses a decision from an AI actor. Not because a model's
// reading is worthless — it may be better than the analyst's — but because
// accountability is the thing being recorded, and a model cannot hold any.

// Decision is one thing somebody said about a finding.
type Decision struct {
	// Finding is the id this is about.
	Finding string    `json:"finding"`
	At      time.Time `json:"at"`
	// By is who decided. Never empty: a decision nobody made is the state
	// this design exists to make unrepresentable.
	By string `json:"by"`
	// Kind is what sort of actor By was, so that a decision made by a service
	// account reads differently from one made by a person.
	Kind audit.Kind `json:"kind"`

	// To is the state they moved it to.
	To State `json:"to"`
	// Because is their reasoning. Required for anything that stops work.
	Because string `json:"because,omitempty"`
	// Until is when an acceptance runs out.
	Until time.Time `json:"until,omitempty"`
}

// Validate refuses a decision that cannot be relied on later.
func (d Decision) Validate() error {
	if strings.TrimSpace(d.Finding) == "" {
		return fmt.Errorf("a decision names no finding")
	}
	if d.At.IsZero() {
		return fmt.Errorf("a decision about %s has no time, so it cannot be "+
			"ordered against the others", d.Finding)
	}
	if strings.TrimSpace(d.By) == "" {
		return fmt.Errorf(
			"a decision about %s names nobody. Accountability is the thing "+
				"being recorded; a decision with no author records none",
			d.Finding)
	}
	if d.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s was decided by a model. Approvals come from principals and a "+
				"model is not one — and a model that can close its own "+
				"findings can close the one that would have caught it. A "+
				"model may propose this; a person records it", d.Finding)
	}
	switch d.To {
	case Open, Triaged, Fixed, Stale:
	case Accepted:
		if strings.TrimSpace(d.Because) == "" {
			return fmt.Errorf(
				"%s is being accepted with no reason. In most frameworks the "+
					"control is not that risks are accepted, it is that "+
					"acceptance is justified", d.Finding)
		}
		if d.Until.IsZero() {
			return fmt.Errorf(
				"%s is being accepted for ever. Acceptance expires or the "+
					"register becomes fiction", d.Finding)
		}
		if !d.Until.After(d.At) {
			return fmt.Errorf(
				"%s is being accepted until a moment that has already passed",
				d.Finding)
		}
	default:
		return fmt.Errorf("%q is not a state a finding can be moved to", d.To)
	}
	return nil
}

// Record turns a decision into an audit entry.
//
// The entry is the decision. Writing it to the register as well would be two
// copies of one fact with no way to tell which was edited, so the register is
// rebuilt from these rather than kept beside them.
func (d Decision) Record() audit.Record {
	detail := map[string]string{
		"finding": d.Finding,
		"to":      string(d.To),
	}
	if d.Because != "" {
		detail["because"] = d.Because
	}
	if !d.Until.IsZero() {
		detail["until"] = d.Until.UTC().Format(time.RFC3339)
	}
	outcome := audit.Success
	if d.To == Accepted {
		// Recorded as a denial of the work rather than a success. Somebody
		// decided not to fix something, and a log where that reads the same
		// as fixing it is one nobody can search for the interesting cases.
		outcome = audit.Denied
	}
	return audit.Record{
		Action: "finding." + string(d.To), Resource: "/" + d.Finding,
		Outcome: outcome, Principal: d.By, Kind: d.Kind,
		Verified: d.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Apply folds decisions onto a finding, oldest first.
//
// The finding passed in is what the scanners reported: identity, severity,
// evidence, counts. What comes back is that with the human record applied.
// Nothing mutates — a copy is returned — because a projection that modified
// its input would make replaying the log twice give different answers.
func Apply(f Finding, decisions []Decision) Finding {
	mine := make([]Decision, 0, len(decisions))
	for _, d := range decisions {
		if d.Finding == f.ID {
			mine = append(mine, d)
		}
	}
	sort.Slice(mine, func(i, j int) bool {
		if !mine[i].At.Equal(mine[j].At) {
			return mine[i].At.Before(mine[j].At)
		}
		// Two decisions at the same instant. Ordering by what was decided
		// keeps the fold deterministic; without it, replaying the same log
		// twice can produce different states, which is the one thing a
		// projection must never do.
		return mine[i].To < mine[j].To
	})

	out := f
	for _, d := range mine {
		out.State = d.To
		out.Because, out.Until = d.Because, d.Until
		if d.To != Accepted {
			// Only an acceptance carries a justification and an expiry.
			// Leaving the previous one attached to a later state would let a
			// finding read as accepted-until-June while being open.
			out.Because, out.Until = "", time.Time{}
		}
	}
	return out
}

// Decided reports whether anybody has said anything about a finding.
//
// Distinct from being Open: a finding nobody has looked at and one somebody
// examined and returned to Open are different situations, and only the
// decision log can tell them apart.
func Decided(id string, decisions []Decision) bool {
	for _, d := range decisions {
		if d.Finding == id {
			return true
		}
	}
	return false
}

// History returns the decisions about one finding, oldest first.
//
// The sentence an auditor is actually asking for.
func History(id string, decisions []Decision) []Decision {
	var out []Decision
	for _, d := range decisions {
		if d.Finding == id {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Story writes a finding's history out for a person.
func Story(id string, decisions []Decision) string {
	h := History(id, decisions)
	if len(h) == 0 {
		return "nobody has looked at this"
	}
	parts := make([]string, 0, len(h))
	for _, d := range h {
		line := fmt.Sprintf("%s: %s by %s",
			d.At.UTC().Format("2006-01-02"), d.To, d.By)
		if d.Because != "" {
			line += ", because " + d.Because
		}
		if !d.Until.IsZero() {
			line += fmt.Sprintf(" (until %s)",
				d.Until.UTC().Format("2006-01-02"))
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, "; ")
}
