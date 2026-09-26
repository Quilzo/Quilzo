// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package engagement

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
)

// Assembling the package, and the four things that are deliberately not
// filtered out of it.
//
// A package is built once, from the log as it stands, and everything in it
// resolves against one head. Building it twice against two heads would give
// an auditor two commitments and no way to relate them, which is the same
// mistake as handing them two exports.

// Signer makes the head that every proof resolves against.
type Signer interface {
	Sign(audit.Head) (audit.SignedHead, error)
}

// InScope answers whether an entity is inside the engagement.
//
// Supplied by the caller rather than computed here, because the group
// structure lives in internal/entity and this package deliberately does not
// depend on it: an engagement over a deployment with no group is one where
// everything is in scope, and that should not require a tree.
type InScope func(entity string) bool

// Build assembles a package for an engagement.
//
// The evidence is filtered to the scope and the period, the audit entries
// that recorded it are found, and one inclusion proof per entry is taken
// against a single head. The head is signed last, so what it commits to is
// exactly what the package contains.
func Build(e Engagement, controls []assurance.Control,
	evidence []assurance.Evidence, events []audit.Event, in InScope,
	s Signer, now time.Time) (Package, error) {

	var p Package
	if err := e.Validate(); err != nil {
		return p, err
	}
	if !e.Open(now) {
		return p, fmt.Errorf(
			"%s is not open: %s. A package issued under a closed "+
				"engagement is access nobody agreed to", e.ID, e.Why(now))
	}
	if s == nil {
		return p, fmt.Errorf(
			"no signer. An unsigned package is a folder of files the " +
				"audited party assembled, which is the thing this replaces")
	}
	if in == nil {
		in = func(string) bool { return true }
	}

	// Controls first, so the package says what was claimed as well as what
	// was shown. A control with nothing behind it is named rather than
	// omitted: an auditor finds it anyway, and finding it themselves is the
	// version that costs a week.
	inScope := map[string]bool{}
	for _, c := range controls {
		if c.Entity != "" && !in(c.Entity) {
			continue
		}
		inScope[c.ID] = true
		p.Controls = append(p.Controls, c)
	}
	sort.Slice(p.Controls, func(i, j int) bool {
		return p.Controls[i].ID < p.Controls[j].ID
	})

	// The audit entries, indexed by what they recorded. An entry is matched
	// to its evidence on the reference, which is the field that identifies
	// the artefact rather than the act.
	byRef := map[string]audit.Event{}
	index := map[string]int{}
	for i, ev := range events {
		if !strings.HasPrefix(ev.Action, "control.") {
			continue
		}
		ref := ev.Detail["ref"]
		if ref == "" {
			continue
		}
		key := ev.Detail["control"] + "\x00" + ref
		byRef[key] = ev
		index[key] = i
	}

	var missing []string
	seen := map[string]bool{}
	for _, item := range evidence {
		if !inScope[item.Control] {
			continue
		}
		if item.Entity != "" && !in(item.Entity) {
			continue
		}
		if _, ok := (assurance.Period{From: item.From, To: item.To}).
			Overlap(e.Period); !ok {
			continue
		}
		seen[item.Control] = true
		key := item.Control + "\x00" + item.Ref
		entry, ok := byRef[key]
		if !ok {
			// Evidence with no audit entry. Reported rather than dropped:
			// it is either evidence added by hand outside the recorded path
			// or a log that has lost an entry, and both are things an
			// auditor should be told rather than shown a shorter package.
			missing = append(missing, item.Ref)
			continue
		}
		p.Items = append(p.Items, Item{Evidence: item, Entry: entry,
			Index: index[key]})
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return p, fmt.Errorf(
			"%d piece(s) of evidence have no entry in the audit log: %s. "+
				"Either they were added outside the recorded path or the "+
				"log has lost them, and a package that quietly left them "+
				"out would be a package whose completeness depends on this "+
				"program", len(missing), strings.Join(missing, ", "))
	}

	for id := range inScope {
		if !seen[id] {
			p.Unevidenced = append(p.Unevidenced, id)
		}
	}
	sort.Strings(p.Unevidenced)

	// One head for everything. Taken after the items are chosen so it
	// commits to a log that already contains them.
	head, err := audit.TreeHead(events, now)
	if err != nil {
		return p, err
	}
	for i := range p.Items {
		proof, _, perr := audit.Inclusion(events, p.Items[i].Entry.Seq)
		if perr != nil {
			return p, fmt.Errorf("%s: %w", p.Items[i].Evidence.Ref, perr)
		}
		p.Items[i].Proof = proof
	}
	signed, err := s.Sign(head)
	if err != nil {
		return p, err
	}

	p.Engagement = e
	p.Issued = now.UTC()
	p.Head = signed
	p.Coverage = coverageOf(p.Controls, evidenceIn(p.Items), e.Period)
	p.Note = note(p)

	sort.Slice(p.Items, func(i, j int) bool {
		if p.Items[i].Evidence.Control != p.Items[j].Evidence.Control {
			return p.Items[i].Evidence.Control < p.Items[j].Evidence.Control
		}
		return p.Items[i].Evidence.From.Before(p.Items[j].Evidence.From)
	})
	if outside := p.Outside(in); len(outside) > 0 {
		// Never reached by construction, and checked anyway: a package
		// carrying another company's evidence is a disclosure, and the
		// filter above is the only thing between here and that.
		return Package{}, fmt.Errorf(
			"the package would carry evidence the engagement does not "+
				"cover: %s", strings.Join(outside, "; "))
	}
	return p, nil
}

func evidenceIn(items []Item) []assurance.Evidence {
	out := make([]assurance.Evidence, 0, len(items))
	for _, i := range items {
		out = append(out, i.Evidence)
	}
	return out
}

func coverageOf(controls []assurance.Control, evidence []assurance.Evidence,
	period assurance.Period) []assurance.Coverage {

	_, covs := assurance.Assess(controls, evidence, period)
	return covs
}

// note is what the auditor reads first.
//
// Written into the package rather than into documentation, because the
// package is what gets forwarded and the documentation is what does not.
func note(p Package) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"%d piece(s) of evidence for %d control(s), covering %s over %s.\n",
		len(p.Items), len(p.Controls), p.Engagement.Scope,
		p.Engagement.Period)
	b.WriteString(
		"Each piece carries the audit entry that recorded it being " +
			"gathered and an inclusion proof against the one signed head " +
			"in this file. Verifying them needs the published key and " +
			"nothing from this organisation.\n")
	if len(p.Unevidenced) > 0 {
		fmt.Fprintf(&b,
			"\n%d control(s) in scope have nothing in the period: %s. They "+
				"are named here rather than omitted.\n",
			len(p.Unevidenced), strings.Join(p.Unevidenced, ", "))
	}
	b.WriteString(
		"\nWhat this proves: nothing in here was altered after it was " +
			"recorded, and a package issued to anybody else describes the " +
			"same log. What it does not prove: that the log is complete. " +
			"An entry can be omitted before the tree is built, and no " +
			"cryptography fixes that.\n")
	return b.String()
}

// Access is one read by an auditor, recorded.
//
// Auditors ask for this. An examination turns on being able to say what was
// looked at and when, and a firm that can point at the audited party's own
// tamper-evident log for that is in a better position than one relying on
// its own notes.
type Access struct {
	Engagement string    `json:"engagement"`
	At         time.Time `json:"at"`
	// What was issued: the package's head, which identifies it exactly.
	Head  string `json:"head"`
	Items int    `json:"items"`
	By    string `json:"by"`
}

// Record turns an issue into an audit entry.
func (a Access) Record() audit.Record {
	return audit.Record{
		Action: "engagement.issued", Resource: "/engagement/" + a.Engagement,
		Outcome: audit.Success, Principal: a.By, Kind: audit.KindHuman,
		Verified: true,
		Detail: map[string]string{
			"engagement": a.Engagement, "head": a.Head,
			"items": fmt.Sprint(a.Items),
		},
	}
}
