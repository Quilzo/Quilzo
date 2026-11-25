// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Control tests.
//
// A test is a typed query and an assertion over a population: every member
// of the population is selected by the query (all), or none is (none). The
// members that fail are the difference between the two sets, by identifier,
// and that difference, with the assertion and the query's terms, is the
// whole of the explanation of a failure, written by code.
//
// A test is drafted, by a person or by a model filling the draft's typed
// schema (DraftSchema), and the draft is a proposal: it waits on the
// register's proposals ref, where nothing runs it, until a person who did
// not draft it approves it, through the approvals module (Programme.Approve,
// or Sign-off in the admin). Its approval is bound to the
// test, the query's digest among it and its population as it was defined
// (DenominatorOf), so a test whose query changed is refused, and one whose
// population was redefined runs over nothing, until somebody approves it
// again. Once approved the scheduler
// runs it (schedule.go), and each run writes a TestRun and an Evidence in
// one commit: a control's status moves on a run, and on nothing else.

// Draft is a control test as it is drafted: by the names a person knows the
// control and the population by, and the query in full. It is what a model
// fills in, and nothing else is read from what it sends.
type Draft struct {
	Control    string     `json:"control"`
	Name       string     `json:"name"`
	Population string     `json:"population"`
	Assertion  string     `json:"assertion"`
	Every      int64      `json:"every,omitempty"`
	Query      DraftQuery `json:"query"`
}

// DraftQuery is the query of a draft.
type DraftQuery struct {
	Of     string          `json:"of"`
	Member string          `json:"member,omitempty"`
	Terms  []register.Term `json:"terms,omitempty"`
}

// ParseDraft reads a draft, refusing a field the draft does not have and
// anything after it: what a model sends is held to the schema, and a field
// it invented, an explanation say, is a draft refused, not a field dropped.
func ParseDraft(b []byte) (Draft, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d Draft
	if err := dec.Decode(&d); err != nil {
		return Draft{}, fmt.Errorf("%w: the draft is not one: %v", register.ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Draft{}, fmt.Errorf("%w: the draft is followed by more than it", register.ErrInvalid)
	}
	return d, nil
}

// DraftSchema is the JSON schema of a draft, which is what a model's one
// typed call fills in.
func DraftSchema() map[string]any {
	var kinds []string
	for _, k := range register.Kinds() {
		if !k.Unconfirmed {
			kinds = append(kinds, string(k.Kind))
		}
	}
	str := map[string]any{"type": "string"}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"required": []string{"control", "name", "population", "assertion", "query"},
		"properties": map[string]any{
			"control":    map[string]any{"type": "string", "description": "the control's reference, such as AC-01"},
			"name":       map[string]any{"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]*$", "description": "the test's machine name"},
			"population": map[string]any{"type": "string", "description": "the population's machine name"},
			"assertion":  map[string]any{"enum": register.Assertion("").Values()},
			"every":      map[string]any{"type": "integer", "minimum": 3600, "description": "seconds between runs; none is a day"},
			"query": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"of"},
				"properties": map[string]any{
					"of":     map[string]any{"enum": kinds},
					"member": str,
					"terms": map[string]any{"type": "array", "maxItems": 32, "items": map[string]any{
						"type": "object", "additionalProperties": false, "required": []string{"field", "op"},
						"properties": map[string]any{
							"field":  str,
							"op":     map[string]any{"enum": register.Op("").Values()},
							"values": map[string]any{"type": "array", "maxItems": 1000, "items": map[string]any{"type": []string{"string", "number", "boolean"}}},
						}}},
				}},
		},
	}
}

// Proposed is a draft as it waits: the test and its query.
type Proposed struct {
	Test    register.ControlTest `json:"test"`
	TestID  register.ID          `json:"test_id"`
	Query   register.Query       `json:"query"`
	Receipt register.Receipt     `json:"receipt"`
}

// ProposeDraft holds a draft to the schema and to the register as it is,
// and proposes the test and its query, to wait for a person. A model, a
// crew or a person may call it; it writes nothing to the register.
func (p *Programme) ProposeDraft(by register.Actor, d Draft) (Proposed, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return Proposed{}, err
	}
	control, err := named(v, register.KindControl, register.Local, d.Control)
	if err != nil {
		return Proposed{}, err
	}
	pop, err := named(v, register.KindPopulation, register.Local, d.Population)
	if err != nil {
		return Proposed{}, err
	}
	pe, err := v.Get(pop)
	if err != nil {
		return Proposed{}, err
	}
	q, err := CheckQuery(register.Query{Of: d.Query.Of, Member: d.Query.Member, Terms: d.Query.Terms})
	if err != nil {
		return Proposed{}, err
	}
	// The test names its population as it is defined now, so the person
	// who approves it approves the denominator too (DenominatorOf).
	test := register.ControlTest{Control: control, Name: d.Name, Population: pop, Query: q.Digest,
		Denominator: DenominatorOf(pe.Record.(register.Population)), Assertion: register.Assertion(d.Assertion), Every: d.Every}
	id, err := register.IDOf(test)
	if err != nil {
		return Proposed{}, err
	}
	recs := []register.Record{test}
	// A query already in the register is not proposed again: it is filed
	// under its own digest and never changed.
	if qid, _ := QueryID(q.Digest); !has(v, qid) {
		recs = append(recs, q)
	}
	rc, err := p.Reg.Propose(by, "a draft of the control test "+d.Name, recs...)
	if err != nil {
		return Proposed{}, err
	}
	return Proposed{Test: test, TestID: id, Query: q, Receipt: rc}, nil
}

// named is the identifier of a record a person names, which is in the
// register at the view.
func named(v *register.View, kind register.Kind, source, natural string) (register.ID, error) {
	id, err := register.DeriveID(kind, source, natural)
	if err != nil {
		return "", fmt.Errorf("%w: name the %s", register.ErrInvalid, strings.ToLower(string(kind)))
	}
	if !has(v, id) {
		return "", fmt.Errorf("%w: the register holds no %s %q", register.ErrNotFound, strings.ToLower(string(kind)), clip(natural))
	}
	return id, nil
}

func has(v *register.View, id register.ID) bool {
	_, err := v.Get(id)
	return err == nil
}

// sameDenominator refuses to approve a test drafted over its population as
// it was defined before it was redefined: approved, it would run over
// nothing, and the person approving would have approved a denominator that
// is no longer the population's.
func (p *Programme) sameDenominator(t register.ControlTest) error {
	e, err := p.Reg.Get(t.Population)
	if err != nil {
		return fmt.Errorf("%w: the population the test is run over is not in the register", register.ErrNotFound)
	}
	pop, ok := e.Record.(register.Population)
	if !ok || t.Denominator != DenominatorOf(pop) {
		return fmt.Errorf("%w: the population was redefined after the test was drafted; draft it again over the "+
			"population as it now is", register.ErrInvalid)
	}
	return nil
}

// waitingQuery is the query a test that waits names: in the register
// already, which brings nothing, or waiting beside the test.
func (p *Programme) waitingQuery(waiting []register.Proposal, d register.Digest) (*register.Query, error) {
	qid, err := QueryID(d)
	if err != nil {
		return nil, err
	}
	if _, err := p.Reg.Get(qid); err == nil {
		return nil, nil
	}
	for _, w := range waiting {
		if q, ok := w.Record.(register.Query); ok && w.ID == qid {
			if _, err := CheckQuery(q); err != nil {
				return nil, err
			}
			return &q, nil
		}
	}
	return nil, fmt.Errorf("%w: the query the test runs is neither in the register nor waiting beside it", register.ErrNotFound)
}

// Run is one run of a test as code found it, before it is written.
type Run struct {
	TestID   register.ID          `json:"test_id"`
	Test     register.ControlTest `json:"test"`
	Query    register.Query       `json:"query"`
	PopQuery register.Query       `json:"population_query"`
	// Population is the population the test was run over, as the register
	// held it.
	Population register.Population `json:"population"`
	Record     register.TestRun    `json:"run"`
	// Circular says the facts the test read came from the source its
	// population is counted from, so the denominator is the tool being
	// measured.
	Circular bool `json:"circular,omitempty"`
	// Problem is why a run could not finish, in a line code wrote.
	Problem string         `json:"problem,omitempty"`
	Grade   register.Grade `json:"grade,omitempty"`
}

// Evaluate runs a test at a view, as of at, and writes nothing. It is what
// a run and a replay both do, so the two cannot differ in how they count.
func Evaluate(v *register.View, testID register.ID, at time.Time) (Run, error) {
	e, err := v.Get(testID)
	if err != nil {
		return Run{}, err
	}
	test, ok := e.Record.(register.ControlTest)
	if !ok {
		return Run{}, fmt.Errorf("%w: %s is not a control test", register.ErrNotFound, testID)
	}
	run := Run{TestID: testID, Test: test, Record: register.TestRun{Test: testID, Ran: register.TimeOf(at),
		Commit: v.Commit()}}
	fail := func(problem string) (Run, error) {
		run.Problem = problem
		run.Record.Outcome = register.Errored
		run.Record.Population = membersDigest(nil)
		run.Record.Snapshot = readDigest()
		return run, nil
	}
	// An approval lapses at the end of its rule's term, and a test whose
	// approval lapsed is a decision nobody holds until a person approves
	// it again.
	if test.Approval.Lapsed(register.TimeOf(at)) {
		return fail("its approval lapsed on " + test.Approval.Expires.At().Format("2 January 2006") +
			", so the test runs again once a person approves it again")
	}
	q, err := queryAt(v, test.Query)
	if err != nil {
		return fail("the query the test runs is not in the register")
	}
	run.Query = q
	// The register holds a reference to the kind it names by the schema,
	// not by a check at each write, so what the test names is asked to be
	// a population before it is read as one: a run on the admin server's
	// timer that met anything else would stop the timer.
	pe, err := v.Get(test.Population)
	pop, isPopulation := pe.Record.(register.Population)
	if err != nil || !isPopulation {
		return fail("the population the test is run over is not in the register")
	}
	run.Population = pop
	if test.Denominator != DenominatorOf(pop) {
		return fail("the population was redefined after the test was approved, so the test runs again once a person " +
			"approves it over the population as it now is")
	}
	pq, err := queryAt(v, pop.Query)
	if err != nil {
		return fail("the query that selects the population is not in the register")
	}
	run.PopQuery = pq
	members, err := Select(v, pq, pop.Source)
	if err != nil {
		return fail("the population's query could not be run")
	}
	selected, err := Select(v, q, "")
	if err != nil {
		return fail("the test's query could not be run")
	}
	if len(members.Members) == 0 {
		return fail("the population has no members, so the test shows nothing")
	}
	in := map[register.ID]bool{}
	for _, id := range selected.Members {
		in[id] = true
	}
	var failing []register.ID
	for _, id := range members.Members {
		if in[id] != (test.Assertion == "all") {
			failing = append(failing, id)
		}
	}
	run.Record.Population = membersDigest(members.Members)
	run.Record.Size = int64(len(members.Members))
	run.Record.Failing = failing
	run.Record.Snapshot = readDigest(members.Read, selected.Read)
	run.Record.Outcome = register.Pass
	if len(failing) > 0 {
		run.Record.Outcome = register.Fail
	}
	run.Circular = selected.Sources[pop.Source]
	run.Grade = weakest(v, pop.Source, selected.Grades)
	return run, nil
}

// DenominatorOf is what a test binds of its population: the digest of the
// source its members are read from and the query that selects them, which
// together decide who is counted. The population's name, its title, its
// cross-check and its last count are left out: none of them changes who a
// test is run over.
func DenominatorOf(p register.Population) register.Digest {
	return digestOf("quilzo/programme denominator v1\n", []string{string(p.Source), string(p.Query)})
}

// queryAt is the query a digest names, at a view.
func queryAt(v *register.View, d register.Digest) (register.Query, error) {
	id, err := QueryID(d)
	if err != nil {
		return register.Query{}, err
	}
	e, err := v.Get(id)
	if err != nil {
		return register.Query{}, err
	}
	q, ok := e.Record.(register.Query)
	if !ok {
		return register.Query{}, fmt.Errorf("%w: %s is not a query", register.ErrNotFound, id)
	}
	return q, nil
}

// weakest is the weakest grade among the facts a run read, and the grade
// of the population's source: evidence is as strong as its weakest part.
func weakest(v *register.View, source register.ID, grades []register.Grade) register.Grade {
	if e, err := v.Get(source); err == nil {
		if s, ok := e.Record.(register.Source); ok {
			grades = append(grades, s.Grade)
		}
	}
	worst := register.GradeConnector
	for _, g := range grades {
		if g.Rank() > worst.Rank() && g.Rank() < len(g.Values()) {
			worst = g
		}
	}
	return worst
}

// Scheduler is the actor runs are written as: a service, which writes the
// runs of tests a person approved and the evidence they leave, and nothing
// else.
func Scheduler() register.Actor {
	return register.Actor{Name: "control-test-scheduler", Kind: audit.KindService, Verified: true,
		May: func(act auth.Action, resource string) error {
			for _, k := range []register.Kind{register.KindTestRun, register.KindEvidence, register.KindPopulation} {
				if s, _ := register.SpecOf(string(k)); act == auth.ActEditDraft && resource == s.Resource() {
					return nil
				}
			}
			return fmt.Errorf("the scheduler writes runs, their evidence and counts, and not %s", resource)
		}}
}

// RunTest runs an approved test at the register's head and writes its run,
// and the evidence of the control it leaves, as one commit. A run that
// could not finish is written as such, with no evidence: it shows nothing
// about the control.
func (p *Programme) RunTest(by register.Actor, testID register.ID) (Run, register.Receipt, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return Run{}, register.Receipt{}, err
	}
	run, err := Evaluate(v, testID, p.now())
	if err != nil {
		return Run{}, register.Receipt{}, err
	}
	recs := []register.Record{run.Record}
	if run.Record.Outcome != register.Errored {
		runID, err := register.IDOf(run.Record)
		if err != nil {
			return run, register.Receipt{}, err
		}
		recs = append(recs, register.Evidence{Control: run.Test.Control, Run: runID, At: run.Record.Ran,
			Outcome: run.Record.Outcome, Grade: run.Grade})
	}
	rc, err := p.Reg.Put(by, "a run of the control test "+run.Test.Name, recs...)
	return run, rc, err
}

// Explain is why a run came out as it did, in lines code writes from the
// test's assertion, its query's terms, its population and the members that
// failed, named by identifier. Nothing a model wrote is in it: not the
// draft's words, which were never kept, nor anything a proposal said.
func Explain(run Run) []string {
	what := populationName(run.Population)
	var lines []string
	switch run.Test.Assertion {
	case "all":
		lines = append(lines, fmt.Sprintf("The test asserts that every member of %s is selected by the query.", what))
	default:
		lines = append(lines, fmt.Sprintf("The test asserts that no member of %s is selected by the query.", what))
	}
	lines = append(lines, "The query reads "+describeQuery(run.Query)+".")
	r := run.Record
	switch r.Outcome {
	case register.Errored:
		lines = append(lines, "The run could not finish: "+run.Problem+".")
	case register.Pass:
		lines = append(lines, fmt.Sprintf("All %d members met the assertion.", r.Size))
	default:
		verb := "were not selected"
		if run.Test.Assertion != "all" {
			verb = "were selected"
		}
		ids := make([]string, len(r.Failing))
		for i, id := range r.Failing {
			ids[i] = string(id)
		}
		sort.Strings(ids)
		lines = append(lines, fmt.Sprintf("%d of %d members %s: %s.", len(r.Failing), r.Size, verb, strings.Join(ids, ", ")))
	}
	if run.Circular {
		lines = append(lines, "Circular: the facts the test read come from the source its population is counted from.")
	}
	return lines
}

// describeQuery is a query in words: its kind, its member field and each
// term, written from the typed values.
func describeQuery(q register.Query) string {
	var b strings.Builder
	b.WriteString(q.Of + " records")
	if q.Member != "" {
		b.WriteString(", each about the record its " + q.Member + " names")
	}
	if len(q.Terms) == 0 {
		b.WriteString(", every one of them")
		return b.String()
	}
	b.WriteString(", where ")
	for i, t := range q.Terms {
		if i > 0 {
			b.WriteString(" and ")
		}
		b.WriteString(describeTerm(t))
	}
	return b.String()
}

func describeTerm(t register.Term) string {
	vals := make([]string, len(t.Values))
	for i, v := range t.Values {
		vals[i] = quoteValue(v)
	}
	switch t.Op {
	case register.OpEquals:
		return t.Field + " is " + vals[0]
	case register.OpNotEquals:
		return t.Field + " is present and is not " + vals[0]
	case register.OpIn:
		return t.Field + " is one of " + strings.Join(vals, ", ")
	case register.OpExists:
		return t.Field + " is present"
	case register.OpAbsent:
		return t.Field + " is absent"
	}
	return t.Field
}

// quoteValue is a value as the explanation writes it: text in quotes, a
// number or a yes or no as itself.
func quoteValue(v register.Scalar) string {
	if s, ok := v.Value().(string); ok {
		return fmt.Sprintf("%q", s)
	}
	return v.String()
}

func populationName(p register.Population) string {
	if p.Title != "" {
		return "the population " + p.Name + " (" + p.Title + ")"
	}
	return "the population " + p.Name
}

// Standing is how a control stands, from the runs of its tests and nothing
// else: the newest run of one of its own tests that finished, read from the
// run itself. A run that could not finish shows nothing about the control.
// Evidence does not move it: evidence that names no run, a statement among
// it, is not a run, and evidence that names a run and says it came out
// otherwise, or at another moment, than the run records is not believed
// over the run, so writing over the evidence a failing run left does not
// make the control pass, nor hide that it failed. The grade is the one the
// run's own evidence gives, where that evidence agrees with the run.
type Standing struct {
	Outcome register.Outcome `json:"outcome,omitempty"`
	At      register.Time    `json:"at,omitempty"`
	Run     register.ID      `json:"run,omitempty"`
	Grade   register.Grade   `json:"grade,omitempty"`
	// Runs is how many runs of its tests finished, and Failed how many of
	// those failed.
	Runs, Failed int
}

// Standings is how every control stands at a view, by its identifier.
func Standings(v *register.View) (map[register.ID]Standing, error) {
	tests := map[register.ID]register.ID{} // test -> control
	if err := v.Each(register.KindControlTest, func(e register.Entry, _ map[string]any) error {
		tests[e.ID] = e.Record.(register.ControlTest).Control
		return nil
	}); err != nil {
		return nil, err
	}
	runs := map[register.ID]register.TestRun{}
	if err := v.Each(register.KindTestRun, func(e register.Entry, _ map[string]any) error {
		runs[e.ID] = e.Record.(register.TestRun)
		return nil
	}); err != nil {
		return nil, err
	}
	// The grade of each run's facts is on the evidence it left, where that
	// evidence says what the run says.
	grades := map[register.ID]register.Grade{}
	if err := v.Each(register.KindEvidence, func(e register.Entry, _ map[string]any) error {
		ev := e.Record.(register.Evidence)
		if run, ok := runs[ev.Run]; ok && tests[run.Test] == ev.Control && ev.Outcome == run.Outcome && ev.At == run.Ran {
			grades[ev.Run] = ev.Grade
		}
		return nil
	}); err != nil {
		return nil, err
	}
	ids := make([]register.ID, 0, len(runs))
	for id := range runs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := map[register.ID]Standing{}
	for _, id := range ids {
		run := runs[id]
		control, ok := tests[run.Test]
		if !ok || run.Outcome != register.Pass && run.Outcome != register.Fail {
			continue
		}
		s := out[control]
		s.Runs++
		if run.Outcome == register.Fail {
			s.Failed++
		}
		if s.Outcome == "" || run.Ran > s.At || run.Ran == s.At && run.Outcome == register.Fail {
			s.Outcome, s.At, s.Run, s.Grade = run.Outcome, run.Ran, id, grades[id]
		}
		out[control] = s
	}
	return out, nil
}
