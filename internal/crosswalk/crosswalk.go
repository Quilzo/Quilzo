// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package crosswalk maps controls onto framework requirements without
// claiming more than the mapping says.
//
// # What every compliance platform gets wrong here
//
// A control is shown with a row of framework tags: SOC2 CC6.1, ISO 27001
// A.8.5, NIST AC-2. The tags are a list, so the reader takes them as
// equality — this control satisfies that requirement — and the platform then
// counts the requirement as covered. Adding a framework becomes a matter of
// clicking a mapping and watching a percentage appear.
//
// The tags are almost never equality. A control that enforces MFA on the
// identity provider is a *part* of a requirement about authenticating access
// to information systems; it says nothing about the database with local
// accounts, and an auditor will say so in week three. The industry complaint
// about these platforms is precisely this: the mapping was optimistic, the
// coverage figure was derived from it, and the gap surfaced during the audit.
//
// # Set theory, because NIST already did this properly
//
// NIST IR 8477 defines five relationships between two concepts — Equal,
// Subset Of, Superset Of, Intersects With, and No Relationship — and requires
// a documented rationale for each. Those are used here unchanged, because a
// mapping written against a published vocabulary is one another tool, and an
// auditor, can read.
//
// The arithmetic then follows from the relation rather than from a tag:
//
//	control ⊇ requirement   satisfying the control satisfies the requirement
//	control = requirement   the same
//	control ⊂ requirement   part of it. There is a remainder, and it is not
//	                        covered by this control
//	control ∩ requirement   overlaps. Same conclusion, less of it
//	no relationship         recorded, because somebody looked and said no,
//	                        and that is different from nobody having looked
//
// So a requirement is satisfied only where something is Equal to it or a
// Superset of it. Everything else is reported as partially addressed with the
// remainder named, and a partial mapping never becomes a covered requirement
// by being counted.
//
// # Evidence, not mapping, is what makes a requirement covered
//
// A mapping says a control would satisfy a requirement. It says nothing about
// whether the control operated. Joined against internal/assurance, a
// requirement mapped to a control with sixty days of missing evidence is
// reported as mapped and unevidenced — which is the state most programmes are
// actually in and the one no dashboard shows.
//
// # This package ships no framework text
//
// The requirements are the operator's file. ISO's standards are copyrighted,
// the AICPA's criteria are copyrighted, and shipping somebody's controlled
// document is both an infringement and a copy that goes stale. The same
// position internal/marking takes about classification registers, for the
// same two reasons.
package crosswalk

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Relation is one of NIST IR 8477's five.
type Relation string

const (
	// Equal is the two concepts are the same. Rare, and the one every
	// platform assumes by default.
	Equal Relation = "equal"
	// SupersetOf is the control is broader than the requirement: satisfying
	// it satisfies the requirement and more besides.
	SupersetOf Relation = "superset-of"
	// SubsetOf is the control is narrower: it addresses part of the
	// requirement and leaves a remainder.
	SubsetOf Relation = "subset-of"
	// Intersects is they overlap without either containing the other.
	Intersects Relation = "intersects-with"
	// NoRelation is somebody looked and concluded there is no relationship.
	//
	// Worth recording rather than leaving blank: "we considered this and it
	// does not apply" and "nobody has looked at this" are different states,
	// and only one of them is work.
	NoRelation Relation = "no-relationship"
)

// Relations lists them.
func Relations() []Relation {
	return []Relation{Equal, SupersetOf, SubsetOf, Intersects, NoRelation}
}

func (r Relation) known() bool {
	for _, x := range Relations() {
		if x == r {
			return true
		}
	}
	return false
}

// Satisfies reports whether a control in this relation to a requirement is
// enough on its own.
//
// Equal and Superset Of, and nothing else. This is the one line that stops a
// partial mapping becoming a covered requirement.
func (r Relation) Satisfies() bool {
	return r == Equal || r == SupersetOf
}

// Partial reports whether the relation leaves a remainder.
func (r Relation) Partial() bool {
	return r == SubsetOf || r == Intersects
}

// Describe says what a relation means for somebody reading a report.
func (r Relation) Describe() string {
	switch r {
	case Equal:
		return "the same thing, so satisfying the control satisfies the " +
			"requirement"
	case SupersetOf:
		return "the control is broader than the requirement, so satisfying " +
			"it satisfies the requirement and more"
	case SubsetOf:
		return "the control addresses part of the requirement and leaves a " +
			"remainder that nothing here covers"
	case Intersects:
		return "they overlap without either containing the other, so part " +
			"of the requirement is addressed and part is not"
	case NoRelation:
		return "somebody looked and concluded there is no relationship, " +
			"which is different from nobody having looked"
	default:
		return string(r)
	}
}

// Requirement is one line of somebody else's framework.
//
// The identifier and a title, never the text. See the package comment on why
// no framework content is shipped here.
type Requirement struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	// Family groups requirements for a report: "Access Control", "CC6".
	Family string `json:"family,omitempty"`
}

// Key is how a requirement is referred to everywhere.
func (r Requirement) Key() string { return r.Framework + ":" + r.ID }

// Validate refuses a requirement nothing can be mapped to.
func (r Requirement) Validate() error {
	if strings.TrimSpace(r.Framework) == "" {
		return fmt.Errorf("a requirement needs a framework")
	}
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%s has a requirement with no identifier",
			r.Framework)
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf(
			"%s has no title. A report of unmapped requirements that reads "+
				"as a column of identifiers is one nobody can work from",
			r.Key())
	}
	return nil
}

// Mapping is one control's relationship to one requirement.
type Mapping struct {
	Control     string   `json:"control"`
	Requirement string   `json:"requirement"`
	Relation    Relation `json:"relation"`
	// Rationale is why, and is required by IR 8477 rather than by taste.
	//
	// The relation and the rationale are meant to be read together: "subset
	// of" alone does not say what the remainder is, and the remainder is the
	// entire thing a reader needs.
	Rationale string `json:"rationale"`
	// Remainder names what the control does not cover, for a partial
	// relation. Required for those, meaningless for the others.
	Remainder string `json:"remainder,omitempty"`

	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
}

// Key identifies the pair this mapping is about.
func (m Mapping) Key() string { return m.Control + "\x00" + m.Requirement }

// Validate refuses a mapping that would claim something nobody wrote down.
func (m Mapping) Validate() error {
	if strings.TrimSpace(m.Control) == "" {
		return fmt.Errorf("a mapping needs a control")
	}
	if strings.TrimSpace(m.Requirement) == "" {
		return fmt.Errorf("%s maps to nothing", m.Control)
	}
	if !strings.Contains(m.Requirement, ":") {
		return fmt.Errorf(
			"%q does not name a framework. Two frameworks both have a "+
				"clause called 6.1 and they are not the same clause",
			m.Requirement)
	}
	if !m.Relation.known() {
		return fmt.Errorf(
			"%q is not one of the five relationships. NIST IR 8477 defines "+
				"equal, superset-of, subset-of, intersects-with and "+
				"no-relationship, and a sixth invented here is one no "+
				"auditor and no other tool can read", m.Relation)
	}
	if m.At.IsZero() {
		return fmt.Errorf("%s has no date", m.Key())
	}
	if strings.TrimSpace(m.By) == "" {
		return fmt.Errorf(
			"%s names nobody. A mapping is a judgement about whether one "+
				"organisation's control answers another organisation's "+
				"clause, and the person who made it is the one an auditor "+
				"asks", m.Key())
	}
	if m.Kind == audit.KindAI {
		// A model may propose a crosswalk and there is real value in that —
		// reading two documents and suggesting pairs is exactly what it is
		// good at. Signing one is different: the claim is that this
		// organisation's control answers that clause, and it is made to an
		// auditor.
		return fmt.Errorf(
			"%s was mapped by a model. Proposing a crosswalk is a good use "+
				"of one; asserting that a control answers a regulator's "+
				"clause is a claim this organisation makes, and a person "+
				"makes it", m.Key())
	}
	if strings.TrimSpace(m.Rationale) == "" {
		return fmt.Errorf(
			"%s records no rationale. IR 8477 requires the relation and the "+
				"rationale to be read together, because \"subset of\" alone "+
				"does not say what is missing", m.Key())
	}
	if m.Relation.Partial() && strings.TrimSpace(m.Remainder) == "" {
		return fmt.Errorf(
			"%s is %s and does not say what is left over. The remainder is "+
				"the whole reason to record a partial relationship rather "+
				"than ticking the requirement", m.Key(), m.Relation)
	}
	if !m.Relation.Partial() && strings.TrimSpace(m.Remainder) != "" {
		return fmt.Errorf(
			"%s is %s and names a remainder. A relation that satisfies the "+
				"requirement leaves nothing over, and a relation of none "+
				"covers nothing to leave", m.Key(), m.Relation)
	}
	return nil
}

// Record turns a mapping into an audit entry.
func (m Mapping) Record() audit.Record {
	detail := map[string]string{
		"control": m.Control, "requirement": m.Requirement,
		"relation": string(m.Relation), "rationale": m.Rationale,
	}
	if m.Remainder != "" {
		detail["remainder"] = m.Remainder
	}
	return audit.Record{
		Action:   "crosswalk." + string(m.Relation),
		Resource: "/requirement/" + m.Requirement, Outcome: audit.Success,
		Principal: m.By, Kind: m.Kind,
		Verified: m.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Latest folds a list of mappings down to the newest for each pair.
//
// Two mappings of one pair are somebody changing their mind rather than a
// conflict, which is the same rule internal/vuln applies to assessments.
func Latest(in []Mapping) []Mapping {
	byKey := map[string]Mapping{}
	for _, m := range in {
		if existing, ok := byKey[m.Key()]; ok && existing.At.After(m.At) {
			continue
		}
		byKey[m.Key()] = m
	}
	out := make([]Mapping, 0, len(byKey))
	for _, m := range byKey {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}
