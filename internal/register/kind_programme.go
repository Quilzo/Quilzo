// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// The kinds of the security programme: what the organisation has to do
// (requirements), what it does (controls), how the two relate (mappings and
// the statement of applicability), and what shows a control is working
// (tests, their runs, and the evidence a run leaves).

// Domain is the part of the organisation a control is about. Posture is
// shown a row per domain.
type Domain string

// Values lists the domains, in the order posture shows them.
func (Domain) Values() []string {
	return []string{"identity", "endpoints", "cloud", "code", "vulnerabilities", "vendors",
		"people", "ai", "data", "resilience", "incidents"}
}

// Control is something the organisation does to meet a requirement: second
// factors for every account, encrypted disks, a quarterly access review.
type Control struct {
	Ref       string `json:"ref" reg:"required,label" about:"the organisation's own reference, such as AC-01; its natural key"`
	Title     string `json:"title" reg:"required,label" about:"what the control is, in a line"`
	Domain    Domain `json:"domain" reg:"required" about:"the part of the organisation it is about"`
	Objective Text   `json:"objective,omitempty" about:"what it is there to achieve, held as a digest"`
	Owner     ID     `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
	Scope     ID     `json:"scope,omitempty" reg:"ref=Scope" about:"the scope it applies in"`
}

const KindControl Kind = "Control"

func (Control) Kind() Kind              { return KindControl }
func (c Control) Key() (string, string) { return Local, c.Ref }
func (Control) Check() error            { return nil }
func (c Control) index(r *Row) {
	r.About, r.Via, r.State = c.Owner.bytes(), c.Scope.bytes(), ordinal(c.Domain)
}

var _ = define[Control]("Something the organisation does to meet a requirement.", ClassInternal)

// Requirement is one clause of a framework or a law, in Quilzo's own words:
// the frameworks' texts are their publishers', and are not copied here.
type Requirement struct {
	Framework string `json:"framework" reg:"required,slug" about:"the framework it belongs to, such as iso27001-2022"`
	Ref       string `json:"ref" reg:"required,label" about:"the clause's reference in the framework, such as A.5.15"`
	Title     string `json:"title" reg:"required,label" about:"what the clause asks, in a line"`
	Words     Text   `json:"words,omitempty" about:"what it asks, in Quilzo's own words, held as a digest"`
}

const KindRequirement Kind = "Requirement"

func (Requirement) Kind() Kind              { return KindRequirement }
func (q Requirement) Key() (string, string) { return q.Framework, q.Ref }
func (Requirement) Check() error            { return nil }

var _ = define[Requirement]("One clause of a framework or a law, in Quilzo's own words.", ClassInternal)

// Relation is how two things relate, in the five relationships NIST IR 8477
// defines. They are the same five, spelt the same way, as the crosswalk
// package holds.
type Relation string

// Values lists the five relationships.
func (Relation) Values() []string {
	return []string{"equal", "superset-of", "subset-of", "intersects-with", "no-relationship"}
}

// Mapping says how a control relates to a requirement, or one requirement
// to another in a second framework. A mapping without a relation is a line
// drawn between two boxes: it says they are near each other and not whether
// one satisfies the other.
type Mapping struct {
	From      ID       `json:"from" reg:"required" about:"the control, or the requirement, the mapping starts from"`
	To        ID       `json:"to" reg:"required,ref=Requirement" about:"the requirement it is mapped to"`
	Relation  Relation `json:"relation" reg:"required" about:"how the two relate, as NIST IR 8477 names it"`
	Rationale Text     `json:"rationale" reg:"required" about:"why, held as a digest; IR 8477 asks for it"`
}

const KindMapping Kind = "Mapping"

func (Mapping) Kind() Kind              { return KindMapping }
func (m Mapping) Key() (string, string) { return Local, string(m.From) + "/" + string(m.To) }
func (m Mapping) Check() error {
	if m.From == m.To {
		return fmt.Errorf("a mapping relates two different things")
	}
	return nil
}
func (m Mapping) index(r *Row) {
	r.About, r.Via, r.State = m.From.bytes(), m.To.bytes(), ordinal(m.Relation)
}

var _ = define[Mapping]("How a control relates to a requirement, in a NIST IR 8477 relationship.", ClassInternal)

// Scope is what the programme covers, decided by a person: which domains,
// which populations and which frameworks. Every figure is "within the
// declared scope", and this record is that scope.
type Scope struct {
	Name        string    `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title       string    `json:"title" reg:"required,label" about:"what people call it"`
	Domains     []Domain  `json:"domains" reg:"required" about:"the domains it covers"`
	Populations []ID      `json:"populations,omitempty" reg:"ref=Population" about:"the populations coverage is counted against"`
	Frameworks  []string  `json:"frameworks,omitempty" reg:"slug" about:"the frameworks it answers to"`
	Approval    *Approval `json:"approval" reg:"required" about:"the approval that made it the scope"`
}

const KindScope Kind = "Scope"

func (Scope) Kind() Kind              { return KindScope }
func (s Scope) Key() (string, string) { return Local, s.Name }
func (s Scope) Check() error          { return boundTo(s, s.Approval, "scope") }

var _ = define[Scope]("What the programme covers: domains, populations and frameworks.", ClassInternal, signed)

// Applicability is one line of the statement of applicability: whether a
// requirement applies within a scope, and why. Leaving a requirement out is
// a decision somebody made, so the line carries its approval.
type Applicability struct {
	Requirement   ID        `json:"requirement" reg:"required,ref=Requirement" about:"the requirement the line is about"`
	Scope         ID        `json:"scope" reg:"required,ref=Scope" about:"the scope it is decided for"`
	Applicable    bool      `json:"applicable" about:"whether the requirement applies"`
	Justification Text      `json:"justification" reg:"required" about:"why it does or does not, held as a digest"`
	Approval      *Approval `json:"approval" reg:"required" about:"the approval of the line"`
}

const KindApplicability Kind = "Applicability"

func (Applicability) Kind() Kind { return KindApplicability }
func (a Applicability) Key() (string, string) {
	return Local, string(a.Scope) + "/" + string(a.Requirement)
}
func (a Applicability) Check() error {
	return boundTo(a, a.Approval, "line of the statement of applicability")
}
func (a Applicability) index(r *Row) {
	r.About, r.Via = a.Requirement.bytes(), a.Scope.bytes()
	if a.Applicable {
		r.State = 1
	}
}

var _ = define[Applicability]("One line of the statement of applicability: whether a requirement applies, and why.",
	ClassInternal, signed)

// Assertion is what a control test claims of the members its query selects.
type Assertion string

// Values lists the assertions: every member of the population is selected,
// or none is.
func (Assertion) Values() []string { return []string{"all", "none"} }

// ControlTest is how a control is checked: a typed query over observations,
// and what the query must find across a population. A person approves it,
// and approves it again when the query changes, because the query is what
// decides whether the control passes.
//
// The approval is bound to the test it approves: its Surface is the hash of
// the test as the approver was shown it (SurfaceOf), the query's digest
// among it. A test whose query changed under an approval given for another
// is refused by its own Check, wherever it is written from, so the only way
// to run a changed query is for a person to approve it again.
type ControlTest struct {
	Control    ID        `json:"control" reg:"required,ref=Control" about:"the control it checks"`
	Name       string    `json:"name" reg:"required,slug" about:"its machine name, which with the control is its natural key"`
	Population ID        `json:"population" reg:"required,ref=Population" about:"the population it is run over"`
	Query      Digest    `json:"query" reg:"required" about:"the digest of the typed query it runs"`
	Assertion  Assertion `json:"assertion" reg:"required" about:"what the query must find across the population"`
	// Every is how often the scheduler runs the test once it is approved.
	// A test is never run more often than hourly: a control's status
	// moving every minute is noise, and a run is a record kept for good.
	Every    int64     `json:"every,omitempty" reg:"min=3600" about:"how many seconds the scheduler leaves between runs; none is a day"`
	Approval *Approval `json:"approval" reg:"required" about:"the approval of this query and assertion"`
}

const KindControlTest Kind = "ControlTest"

func (ControlTest) Kind() Kind { return KindControlTest }
func (c ControlTest) Key() (string, string) {
	return Local, string(c.Control) + "/" + c.Name
}
func (c ControlTest) Check() error {
	if c.Approval != nil && c.Approval.Surface != SurfaceOf(c) {
		return fmt.Errorf("the approval is of another test: a test whose query, population, assertion or " +
			"schedule changed is approved again before it runs")
	}
	return nil
}
func (c ControlTest) index(r *Row) {
	r.About, r.Via, r.State = c.Control.bytes(), c.Population.bytes(), ordinal(c.Assertion)
}

var _ = define[ControlTest]("How a control is checked: an approved query and what it must find.", ClassInternal, signed)

// Outcome is how a test run, or a piece of evidence, came out.
type Outcome string

const (
	// Pass is every member meeting the assertion.
	Pass Outcome = "pass"
	// Fail is at least one member not meeting it.
	Fail Outcome = "fail"
	// Errored is a run that could not finish, which is neither.
	Errored Outcome = "error"
)

// Values lists the outcomes.
func (Outcome) Values() []string { return []string{string(Pass), string(Fail), string(Errored)} }

// TestRun is one run of a control test: when, over which members, and which
// of them failed. A control's status moves on a run and on nothing else.
// The members that failed are named by identifier, so the explanation of a
// failure is the assertion and this list, both written by code.
type TestRun struct {
	Test       ID      `json:"test" reg:"required,ref=ControlTest" about:"the test that was run"`
	Ran        Time    `json:"ran" reg:"required" about:"when it ran"`
	Outcome    Outcome `json:"outcome" reg:"required" about:"how it came out"`
	Population Digest  `json:"population" reg:"required" about:"the digest of the members it ran over"`
	Size       int64   `json:"size" reg:"min=0" about:"how many members it ran over"`
	Failing    []ID    `json:"failing,omitempty" about:"the members that did not meet the assertion"`
	Snapshot   Digest  `json:"snapshot" reg:"required" about:"the digest of the observations it read"`
	// Commit is the register as the run read it. The store keeps every
	// commit, so a replay reads the same facts, the same test and the same
	// population again, and says whether they still give this run.
	Commit string `json:"commit,omitempty" reg:"oid" about:"the register commit the run read, which a replay reads again"`
}

const KindTestRun Kind = "TestRun"

func (TestRun) Kind() Kind { return KindTestRun }
func (t TestRun) Key() (string, string) {
	return Local, string(t.Test) + "/" + fmt.Sprint(int64(t.Ran))
}
func (t TestRun) Check() error {
	switch {
	case int64(len(t.Failing)) > t.Size:
		return fmt.Errorf("more members failed than the run covered")
	case t.Outcome == Pass && len(t.Failing) > 0:
		return fmt.Errorf("a run that passed names no failing members")
	case t.Outcome == Fail && len(t.Failing) == 0:
		return fmt.Errorf("a run that failed names the members that failed")
	}
	return nil
}
func (t TestRun) index(r *Row) {
	r.About, r.At, r.N, r.M, r.State = t.Test.bytes(), int64(t.Ran), clamp32(t.Size), clamp32(int64(len(t.Failing))), ordinal(t.Outcome)
}

var _ = define[TestRun]("One run of a control test: when, over which members, and which failed.", ClassRestricted)

// Evidence is what shows how a control stood at a moment: one record for
// each control and each run of a test of it, or for each statement a person
// made about it. It points at the run it came from, so the figure a board
// reads can be followed back to the members that were counted.
//
// A statement is a person's. A model cannot make one: Put refuses evidence
// that names an attester and was written by an agent.
type Evidence struct {
	Control  ID      `json:"control" reg:"required,ref=Control" about:"the control it is evidence about"`
	Run      ID      `json:"run,omitempty" reg:"ref=TestRun" about:"the test run it came from"`
	Attested ID      `json:"attested,omitempty" reg:"ref=Subject" about:"the person who stated it, when it is a statement"`
	At       Time    `json:"at" reg:"required" about:"the moment it is evidence about"`
	Outcome  Outcome `json:"outcome" reg:"required" about:"how the control stood"`
	Grade    Grade   `json:"grade" reg:"required" about:"how the facts behind it reached the record"`
	Raw      Digest  `json:"raw,omitempty" about:"the sealed raw evidence behind a statement"`
}

const KindEvidence Kind = "Evidence"

func (Evidence) Kind() Kind { return KindEvidence }
func (e Evidence) Key() (string, string) {
	if e.Run != "" {
		return Local, string(e.Control) + "/run/" + string(e.Run)
	}
	return Local, string(e.Control) + "/stated/" + string(e.Attested) + "/" + fmt.Sprint(int64(e.At))
}
func (e Evidence) Check() error {
	if (e.Run == "") == (e.Attested == "") {
		return fmt.Errorf("evidence comes from a test run or from a person's statement: name one, and only one")
	}
	if e.Outcome == Errored {
		return fmt.Errorf("a run that could not finish is evidence of nothing; record the run and no evidence")
	}
	return nil
}

// attested says the record is a person's statement, which only a person
// may write.
func (e Evidence) attested() bool { return e.Attested != "" }

func (e Evidence) index(r *Row) {
	r.About, r.Via, r.At, r.State, r.Grade = e.Control.bytes(), e.Run.bytes(), int64(e.At), ordinal(e.Outcome), ordinal(e.Grade)
	if e.Attested != "" {
		r.Flags |= FlagAttested
	}
}

var _ = define[Evidence]("How a control stood at a moment, from a test run or a person's statement.", ClassInternal)

// boundTo holds a decision to an approval given for it: one whose Surface
// is the hash of this record as its approvers were shown it. An approval
// moved onto a changed record, or onto another, is the approval of
// something else, wherever it is written from.
func boundTo(rec Record, a *Approval, what string) error {
	if a != nil && a.Surface != SurfaceOf(rec) {
		return fmt.Errorf("the approval is of another %s: a decision that changed is approved again", what)
	}
	return nil
}

// SurfaceOf is the hash of a decision as its approvers are shown it: the
// kind, and the record's fields with its approval left out, since an
// approval cannot be part of what it approves. An approval whose Surface is
// this hash was given for this record and no other; change any field and
// the hash changes with it.
//
// The bytes hashed are a domain line, the kind, a line break and the
// record's fields as canonical JSON (canonicalFields), so the hash is the
// same whoever computes it and wherever: the screen that asks, the command
// that approves and the check that holds a record to it.
func SurfaceOf(rec Record) Digest {
	fields, err := canonicalFields(withApproval(rec, nil))
	if err != nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(surfaceDomain))
	h.Write([]byte(rec.Kind()))
	h.Write([]byte{'\n'})
	h.Write(fields)
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

// surfaceDomain separates the hash of a decision from every other use of
// SHA-256 in the program.
const surfaceDomain = "quilzo decision surface v1\n"

// Op is how a term of a query compares a field.
type Op string

// The five ways a term compares a field. None is an expression: each is a
// value, a list of values or nothing, compared with the field as it is
// stored.
const (
	// OpEquals is a field holding the one value given.
	OpEquals Op = "equals"
	// OpNotEquals is a field holding a value, and not the one given.
	OpNotEquals Op = "not-equals"
	// OpIn is a field holding one of the values given.
	OpIn Op = "in"
	// OpExists is a field that is there, and OpAbsent one that is not.
	OpExists Op = "exists"
	OpAbsent Op = "absent"
)

// Values lists the five.
func (Op) Values() []string {
	return []string{string(OpEquals), string(OpNotEquals), string(OpIn), string(OpExists), string(OpAbsent)}
}

// Term is one condition of a query: a field of the kind the query reads,
// how it is compared and what with. Every term of a query must hold of a
// record for the query to select it.
type Term struct {
	Field  string   `json:"field" reg:"required,slug" about:"the field of the record it compares, as the kind's schema names it"`
	Op     Op       `json:"op" reg:"required" about:"how it compares the field"`
	Values []Scalar `json:"values,omitempty" reg:"max=1000" about:"the value, or the values, it compares the field with"`
}

// Query is a typed query: which kind of record it reads, the field that
// names the member each record is about, and the terms a record must meet.
// It is what a control test and a population select with, and it is filed
// under its own digest, which is its natural key, so the test or the
// population that names the digest names this record and nothing else.
//
// A query is never changed: a different query is a different digest, and so
// a different record. That is what lets a run name the query it ran by a
// digest, and a replay a year later read the same one.
type Query struct {
	Of     string `json:"of" reg:"required,label" about:"the kind of record it reads, such as Observation"`
	Member string `json:"member,omitempty" reg:"slug" about:"the field naming the member a record is about; none is the record itself"`
	Terms  []Term `json:"terms,omitempty" reg:"max=32" about:"the conditions a record meets to be selected"`
	Digest Digest `json:"digest" reg:"required" about:"the digest of the query, which is its natural key"`
}

const KindQuery Kind = "Query"

func (Query) Kind() Kind              { return KindQuery }
func (q Query) Key() (string, string) { return Local, string(q.Digest) }
func (q Query) Check() error {
	if q.Digest != QueryDigest(q) {
		return fmt.Errorf("the digest is not the query's own")
	}
	seen := map[string]bool{}
	for _, t := range q.Terms {
		if seen[t.Field+" "+string(t.Op)] {
			return fmt.Errorf("the field %q is compared %s twice; one term says it", t.Field, t.Op)
		}
		seen[t.Field+" "+string(t.Op)] = true
		switch t.Op {
		case OpEquals, OpNotEquals:
			if len(t.Values) != 1 {
				return fmt.Errorf("the term on %q compares with one value, and holds %d", t.Field, len(t.Values))
			}
		case OpIn:
			if len(t.Values) == 0 {
				return fmt.Errorf("the term on %q is one of no values, which nothing is", t.Field)
			}
		case OpExists, OpAbsent:
			if len(t.Values) != 0 {
				return fmt.Errorf("the term on %q asks whether it is there, which takes no value", t.Field)
			}
		}
	}
	return nil
}

// QueryDigest is the digest a query is filed under: SHA-256 over a domain
// line and the query's kind, member and terms as canonical JSON, with its
// own digest left out.
func QueryDigest(q Query) Digest {
	q.Digest = ""
	fields, err := canonicalFields(q)
	if err != nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(queryDomain))
	h.Write(fields)
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

const queryDomain = "quilzo register query v1\n"

var _ = define[Query]("A typed query: the kind it reads, the field naming each member, and the terms a record meets.",
	ClassInternal, immutable)

// Starter is the decision to take a framework's starter into the
// programme, or to take it out: its requirements in Quilzo's own words, and
// its mappings to other frameworks, as one decision and one commit.
//
// The requirements stay in the register when a starter is taken out, as
// everything written does, and the programme reads them as in it only while
// their framework's starter is installed. Installing it again is another
// decision, and changes this record and nothing else that has not changed.
type Starter struct {
	Framework    string    `json:"framework" reg:"required,slug" about:"the framework, as the starter names it; its natural key"`
	Version      string    `json:"version" reg:"required,label" about:"the edition of the framework the starter is written against"`
	Content      Digest    `json:"content" reg:"required" about:"the digest of the requirements and mappings it brings"`
	Requirements int64     `json:"requirements" reg:"min=0" about:"how many requirements it brings"`
	Mappings     int64     `json:"mappings" reg:"min=0" about:"how many mappings to other frameworks it brings"`
	Installed    bool      `json:"installed" about:"whether it is in the programme"`
	Approval     *Approval `json:"approval" reg:"required" about:"the approval of taking it in, or out"`
}

const KindStarter Kind = "Starter"

func (Starter) Kind() Kind              { return KindStarter }
func (s Starter) Key() (string, string) { return Local, s.Framework }
func (s Starter) Check() error {
	if s.Approval != nil && s.Approval.Surface != SurfaceOf(s) {
		return fmt.Errorf("the approval is of another decision about the starter")
	}
	return nil
}
func (s Starter) index(r *Row) {
	r.N, r.M = clamp32(s.Requirements), clamp32(s.Mappings)
	if s.Installed {
		r.State = 1
	}
	if s.Approval != nil && s.Approval.Alone {
		r.Flags |= FlagAlone
	}
}

var _ = define[Starter]("The decision to take a framework's starter into the programme, or out of it.",
	ClassInternal, signed)
