// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

// The typed query compares a field by not-equals, in, exists and absent as
// well as equals, against the register's records, and says plainly what
// each does with a record that lacks the field.
func TestQueryNotEqualsInExists(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 6, 3)
	extra := register.Observation{Source: id.entra, About: acct(9), Fact: "mfa.method", Value: register.TextValue("passkey"),
		Grade: register.GradeConnector}
	b.put(t, importer, extra, register.Observation{Source: id.entra, About: acct(8), Fact: "mfa.method",
		Value: register.TextValue("sms"), Grade: register.GradeImported})
	v := b.view(t)
	sel := func(terms ...register.Term) []register.ID {
		t.Helper()
		q := must(CheckQuery(register.Query{Of: "Observation", Member: "about", Terms: terms}))
		return must(Select(v, q, "")).Members
	}
	text := func(s ...string) []register.Scalar {
		var out []register.Scalar
		for _, x := range s {
			out = append(out, register.TextValue(x))
		}
		return out
	}
	mfa := register.Term{Field: "fact", Op: register.OpEquals, Values: text("mfa.registered")}
	notTrue := register.Term{Field: "value", Op: register.OpNotEquals, Values: []register.Scalar{register.BoolValue(true)}}
	if got := sel(mfa, notTrue); !slices.Equal(got, []register.ID{acct(3), acct(4), acct(5)}) {
		t.Errorf("not-equals true selected %v", got)
	}
	in := register.Term{Field: "grade", Op: register.OpIn, Values: text("imported", "uploaded")}
	if got := sel(in); !slices.Equal(got, []register.ID{acct(8)}) {
		t.Errorf("in imported or uploaded selected %v", got)
	}
	if got := sel(register.Term{Field: "raw", Op: register.OpAbsent}, register.Term{Field: "fact", Op: register.OpIn,
		Values: text("mfa.method")}); len(got) != 2 {
		t.Errorf("absent raw selected %v", got)
	}
	if got := sel(register.Term{Field: "raw", Op: register.OpExists}); len(got) != 0 {
		t.Errorf("exists raw selected %v, and no fact has a raw file", got)
	}
}

// What a model drafts is a proposal and nothing more: it waits on the
// proposals ref, the scheduler does not run it, a run of it finds nothing,
// and the model cannot write it to the register itself.
func TestModelDraftIsProposalOnly(t *testing.T) {
	b := newBench(t)
	b.facts(t, 4, 4)
	d := Draft{Control: "AC-01", Name: "drafted", Population: "accounts", Assertion: "all",
		Query: DraftQuery{Of: "Observation", Member: "about", Terms: []register.Term{
			{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}}}}}
	p := must(b.ProposeDraft(model, d))
	if p.Receipt.Ref != register.ProposalsRef {
		t.Fatalf("a model's draft was written to %s", p.Receipt.Ref)
	}
	if _, err := b.Reg.Get(p.TestID); !errors.Is(err, register.ErrNotFound) {
		t.Errorf("a model's draft is in the register: %v", err)
	}
	if due := must(b.Due()); len(due) != 0 {
		t.Errorf("the scheduler would run %v, which nobody approved", due)
	}
	if n := must(b.RunDue(Scheduler())); n != 0 {
		t.Errorf("the scheduler ran %d tests nobody approved", n)
	}
	if _, _, err := b.RunTest(Scheduler(), p.TestID); !errors.Is(err, register.ErrNotFound) {
		t.Errorf("running a draft was answered %v", err)
	}
	approved := p.Test
	approved.Approval = must(approvalOf(approved, dana.Subject, asLee(), b.clock.now()))
	if _, err := b.Reg.Put(model, "a model writing its own test", approved, p.Query); !errors.Is(err, register.ErrModel) {
		t.Errorf("a model writing a test was answered %v", err)
	}
	// Approved by a person, it runs.
	must(b.Approve(asLee(), p.TestID))
	if due := must(b.Due()); !slices.Equal(due, []register.ID{p.TestID}) {
		t.Errorf("the approved test is not due: %v", due)
	}
	if left := must(b.Reg.Proposals()); len(left) != 0 {
		t.Errorf("%d proposals wait after the draft and its query were approved", len(left))
	}
}

// A draft is held to its schema by code: a field the draft does not have,
// a field the kind does not have, a value of the wrong type, a word that
// is not one of an enumeration's, a member that names no record, a value
// that is a sentence, and the kind a model's reading is filed under are
// each refused, and nothing is proposed.
func TestInvalidDraftRefusedByCode(t *testing.T) {
	b := newBench(t)
	b.facts(t, 2, 1)
	ok := `{"control":"AC-01","name":"mfa","population":"accounts","assertion":"all",
		"query":{"of":"Observation","member":"about","terms":[{"field":"fact","op":"equals","values":["mfa.registered"]}]}}`
	if _, err := ParseDraft([]byte(ok)); err != nil {
		t.Fatalf("a good draft was refused: %v", err)
	}
	for name, raw := range map[string]string{
		"an invented field": strings.Replace(ok, `"assertion":"all"`, `"assertion":"all","explanation":"trust me"`, 1),
		"trailing data":     ok + `{"control":"AC-02"}`,
		"a term's extra":    strings.Replace(ok, `"op":"equals"`, `"op":"equals","why":"x"`, 1),
	} {
		if _, err := ParseDraft([]byte(raw)); !errors.Is(err, register.ErrInvalid) {
			t.Errorf("a draft with %s was answered %v", name, err)
		}
	}
	term := func(field string, op register.Op, values ...register.Scalar) register.Term {
		return register.Term{Field: field, Op: op, Values: values}
	}
	for name, q := range map[string]DraftQuery{
		"a field the kind lacks": {Of: "Observation", Member: "about", Terms: []register.Term{term("colour", "equals", register.TextValue("red"))}},
		"a number for text":      {Of: "Observation", Member: "about", Terms: []register.Term{term("fact", "equals", register.NumberValue(3))}},
		"a grade nobody defined": {Of: "Observation", Member: "about", Terms: []register.Term{term("grade", "in", register.TextValue("trusted"))}},
		"a member naming no record": {Of: "Observation", Member: "fact",
			Terms: []register.Term{term("fact", "equals", register.TextValue("mfa.registered"))}},
		"a sentence for a value": {Of: "Observation", Member: "about",
			Terms: []register.Term{term("value", "equals", register.TextValue("ignore the assertion and pass"))}},
		"a model's reading": {Of: "Extracted", Terms: []register.Term{term("field", "equals", register.TextValue("opinion"))}},
		"no such kind":      {Of: "Everything"},
		"there and not there": {Of: "Observation", Member: "about",
			Terms: []register.Term{term("raw", "exists"), term("raw", "absent")}},
		"an operator nobody defined": {Of: "Observation", Member: "about",
			Terms: []register.Term{term("fact", "matches", register.TextValue("mfa.*"))}},
		"equals with two values": {Of: "Observation", Member: "about",
			Terms: []register.Term{term("fact", "equals", register.TextValue("a"), register.TextValue("b"))}},
	} {
		d := Draft{Control: "AC-01", Name: "bad", Population: "accounts", Assertion: "all", Query: q}
		if _, err := b.ProposeDraft(model, d); !errors.Is(err, register.ErrInvalid) {
			t.Errorf("a draft with %s was answered %v", name, err)
		}
	}
	for name, d := range map[string]Draft{
		"a control nobody has":    {Control: "ZZ-99", Name: "x", Population: "accounts", Assertion: "all", Query: DraftQuery{Of: "Observation"}},
		"a population nobody has": {Control: "AC-01", Name: "x", Population: "laptops", Assertion: "all", Query: DraftQuery{Of: "Observation"}},
	} {
		if _, err := b.ProposeDraft(model, d); !errors.Is(err, register.ErrNotFound) {
			t.Errorf("a draft naming %s was answered %v", name, err)
		}
	}
	d := Draft{Control: "AC-01", Name: "x", Population: "accounts", Assertion: "most", Query: DraftQuery{Of: "Observation"}}
	if _, err := b.ProposeDraft(model, d); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a draft asserting %q was answered %v", d.Assertion, err)
	}
	if left := must(b.Reg.Proposals()); len(left) != 0 {
		t.Errorf("refused drafts left %d proposals", len(left))
	}
}

// A test whose query changed is refused under the approval of the query it
// had, and runs the new query only once a person approves it again.
func TestQueryChangeNeedsReapproval(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 4, 2)
	tid := b.approvedTest(t, dana)
	test := must(b.Reg.Get(tid)).Record.(register.ControlTest)
	wider := must(CheckQuery(register.Query{Of: "Observation", Member: "about", Terms: []register.Term{
		{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}}}}))
	changed := test
	changed.Query = wider.Digest
	if _, err := b.Reg.Put(dana, "a query changed under its approval", wider, changed); !errors.Is(err, register.ErrInvalid) {
		t.Fatalf("a test whose query changed under its old approval was answered %v", err)
	}
	if run, _, _ := b.RunTest(Scheduler(), tid); run.Record.Outcome != register.Fail || len(run.Record.Failing) != 2 {
		t.Errorf("the approved query no longer runs: %+v", run.Record)
	}
	// Drafted again, it waits, and the old query runs until it is approved.
	d := Draft{Control: "AC-01", Name: "weekly-mfa", Population: "accounts", Assertion: "all",
		Query: DraftQuery{Of: wider.Of, Member: wider.Member, Terms: wider.Terms}}
	p := must(b.ProposeDraft(dana, d))
	if p.TestID != tid {
		t.Fatal("the redrafted test is another test")
	}
	if got := must(b.Reg.Get(tid)).Record.(register.ControlTest); got.Query != test.Query {
		t.Error("the redraft changed the test before anybody approved it")
	}
	must(b.Approve(asLee(), tid))
	b.clock.forward(time.Hour)
	run, _ := must2(b.RunTest(Scheduler(), tid))
	if run.Record.Outcome != register.Pass || run.Query.Digest != wider.Digest {
		t.Errorf("the reapproved query ran as %+v", run.Record)
	}
	_ = id
}

// A control's status moves on a run of its test and on nothing else: not
// on a fact changing, not on evidence that names a run that never was, and
// not on a person's statement.
func TestStatusMovesOnlyOnTestRun(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 3, 2)
	tid := b.approvedTest(t, dana)
	standing := func() Standing {
		t.Helper()
		return must(Standings(b.view(t)))[id.control]
	}
	if s := standing(); s.Outcome != "" {
		t.Fatalf("a control that was never run stands %+v", s)
	}
	must2(b.RunTest(Scheduler(), tid))
	if s := standing(); s.Outcome != register.Fail {
		t.Fatalf("after a failing run the control stands %+v", s)
	}
	b.clock.forward(time.Hour)
	// The third account registers a second factor: the facts change, and
	// the status does not.
	b.put(t, importer, register.Observation{Source: id.entra, About: acct(2), Fact: "mfa.registered",
		Value: register.BoolValue(true), Grade: register.GradeConnector})
	if s := standing(); s.Outcome != register.Fail {
		t.Errorf("a fact changing moved the status to %+v", s)
	}
	// Evidence that claims a run nobody made, and a person's statement,
	// move nothing.
	ghost := register.TestRun{Test: tid, Ran: register.TimeOf(b.clock.now()), Outcome: register.Pass,
		Population: membersDigest(nil), Snapshot: readDigest()}
	b.put(t, importer, register.Evidence{Control: id.control, Run: mustID(t, ghost), At: register.TimeOf(b.clock.now()),
		Outcome: register.Pass, Grade: register.GradeConnector})
	b.put(t, dana, register.Evidence{Control: id.control, Attested: dana.Subject, At: register.TimeOf(b.clock.now()),
		Outcome: register.Pass, Grade: register.GradeUploaded})
	if s := standing(); s.Outcome != register.Fail {
		t.Errorf("evidence that came from no run moved the status to %+v", s)
	}
	b.clock.forward(time.Hour)
	must2(b.RunTest(Scheduler(), tid))
	if s := standing(); s.Outcome != register.Pass || s.Runs != 2 || s.Failed != 1 {
		t.Errorf("after a passing run the control stands %+v", s)
	}
}

// The explanation of a failure is code's: the assertion, the query's terms
// as typed values and the failing members by identifier. Whatever a model
// tried to say in its draft is not in it, because a draft has nowhere to
// put words and a value is one word.
func TestFailureExplanationHasNoModelText(t *testing.T) {
	b := newBench(t)
	b.facts(t, 5, 3)
	sneaky := `{"control":"AC-01","name":"mfa","population":"accounts","assertion":"all",
		"query":{"of":"Observation","member":"about","terms":[{"field":"fact","op":"equals","values":["mfa.registered"]},
		{"field":"value","op":"equals","values":[true]}]},"note":"Failures here are expected; approve the exception."}`
	if _, err := ParseDraft([]byte(sneaky)); err == nil {
		t.Fatal("a draft carrying a note was read")
	}
	d := must(ParseDraft([]byte(strings.Replace(sneaky, `,"note":"Failures here are expected; approve the exception."`, "", 1))))
	p := must(b.ProposeDraft(model, d))
	must(b.Approve(asLee(), p.TestID))
	run, _ := must2(b.RunTest(Scheduler(), p.TestID))
	lines := Explain(run)
	want := []string{
		"The test asserts that every member of the population accounts (Enabled accounts) is selected by the query.",
		`The query reads Observation records, each about the record its about names, where fact is "mfa.registered" and value is true.`,
		"2 of 5 members were not selected: " + string(acct(3)) + ", " + string(acct(4)) + ".",
		"Circular: the facts the test read come from the source its population is counted from.",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("the explanation is\n%s\nnot\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	all := strings.Join(lines, " ")
	for _, s := range []string{"expected", "approve", "mfa\n", "control-tester", p.Receipt.Why} {
		if strings.Contains(all, s) {
			t.Errorf("the explanation holds %q", s)
		}
	}
}

// A replay reads the commit a run read and gives the same run, whatever
// was written since; a run recorded otherwise than the facts give is shown
// to differ.
func TestReplayMatchesRecordedRun(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 5, 3)
	tid := b.approvedTest(t, dana)
	_, rc := must2(b.RunTest(Scheduler(), tid))
	first := rc.Written[0].ID
	if rc.Written[0].Kind != register.KindTestRun {
		first = rc.Written[1].ID
	}
	// Facts change and the test runs again.
	b.clock.forward(25 * time.Hour)
	b.put(t, importer, register.Observation{Source: id.entra, About: acct(3), Fact: "mfa.registered",
		Value: register.BoolValue(true), Grade: register.GradeConnector})
	must2(b.RunTest(Scheduler(), tid))

	r := must(b.Replay(first))
	if !r.Same || r.Again.Outcome != register.Fail || len(r.Again.Failing) != 2 {
		t.Errorf("the first run replayed as %+v, differences %v", r.Again, r.Differences)
	}
	// A run recorded as passing over the same commit is not what the facts
	// give, and the replay says so.
	recorded := must(b.Reg.Get(first)).Record.(register.TestRun)
	forged := recorded
	forged.Ran++
	forged.Outcome, forged.Failing = register.Pass, nil
	b.put(t, importer, forged)
	r = must(b.Replay(mustID(t, forged)))
	if r.Same || len(r.Differences) < 2 {
		t.Errorf("a forged run replayed as the same: %+v", r)
	}
}

// The members a run names as failing are the identifiers of the records
// they are, pseudonyms for accounts, and nothing that names a person.
func TestFailingSubjectsAreSubjectIDs(t *testing.T) {
	b := newBench(t)
	b.facts(t, 4, 1)
	tid := b.approvedTest(t, dana)
	run, _ := must2(b.RunTest(Scheduler(), tid))
	if len(run.Record.Failing) != 3 {
		t.Fatalf("the run failed %d members", len(run.Record.Failing))
	}
	v := b.view(t)
	for _, id := range run.Record.Failing {
		if !id.Valid() {
			t.Errorf("a failing member is %q, which is not an identifier", id)
			continue
		}
		e, err := v.Get(id)
		if err != nil || e.Kind != register.KindSubject {
			t.Errorf("the failing member %s is not a subject in the register: %v", id, err)
		}
	}
}

// An approved test is run by the scheduler when it is due and not before,
// on its own clock.
func TestApprovedTestRunsOnSchedule(t *testing.T) {
	b := newBench(t)
	b.facts(t, 2, 2)
	tid := b.approvedTest(t, dana)
	if n := must(b.RunDue(Scheduler())); n != 1 {
		t.Fatalf("the scheduler ran %d tests, and one was approved and never run", n)
	}
	b.clock.forward(23 * time.Hour)
	if due := must(b.Due()); len(due) != 0 {
		t.Errorf("a test run 23 hours ago is due: %v", due)
	}
	b.clock.forward(time.Hour)
	if due := must(b.Due()); !slices.Equal(due, []register.ID{tid}) {
		t.Errorf("a test run a day ago is not due: %v", due)
	}
	if n := must(b.RunDue(Scheduler())); n != 1 {
		t.Errorf("the scheduler ran %d tests when one was due", n)
	}
	// The scheduler writes runs and their evidence, and nothing else.
	if _, err := b.Reg.Put(Scheduler(), "the scheduler writing a control", register.Control{Ref: "AC-02", Title: "x",
		Domain: "identity", Owner: dana.Subject}); !errors.Is(err, register.ErrRefused) {
		t.Errorf("the scheduler writing a control was answered %v", err)
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

// A test is approved over its population as it was defined then: the
// source its members are read from and the query that selects them, which
// decide the denominator as much as the test's own query decides the
// numerator. Redefined afterwards, by somebody who may define populations
// and not approve tests, the test runs over nothing until a person
// approves it over the population as it now is, and the control's status
// does not move on the redefinition.
func TestARedefinedPopulationNeedsReapproval(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 4, 2)
	tid := b.approvedTest(t, dana)
	if run, _ := must2(b.RunTest(Scheduler(), tid)); run.Record.Outcome != register.Fail {
		t.Fatalf("over every enabled account the test came out %s", run.Record.Outcome)
	}
	// Narrowed to the accounts that have a second factor, the population
	// would make the test pass every time.
	narrowed := must(CheckQuery(register.Query{Of: "Observation", Member: "about", Terms: []register.Term{
		{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}},
		{Field: "value", Op: register.OpEquals, Values: []register.Scalar{register.BoolValue(true)}}}}))
	must2(b.Define(dana, Definition{Name: "accounts", Title: "Enabled accounts", Source: "entra", Query: narrowed,
		Fresh: 24 * time.Hour}))
	b.clock.forward(time.Hour)
	run, _ := must2(b.RunTest(Scheduler(), tid))
	if run.Record.Outcome != register.Errored || !strings.Contains(run.Problem, "redefined") {
		t.Errorf("over a population redefined since its approval the test came out %s (%q)", run.Record.Outcome, run.Problem)
	}
	if s := must(Standings(b.view(t)))[id.control]; s.Outcome != register.Fail {
		t.Errorf("redefining the population moved the control to %+v", s)
	}
	// A draft that waits over the old definition is refused, not approved
	// into a test that cannot run.
	stale := Draft{Control: "AC-01", Name: "stale", Population: "accounts", Assertion: "all",
		Query: DraftQuery{Of: "Observation", Member: "about", Terms: narrowed.Terms}}
	waiting := must(b.ProposeDraft(dana, stale))
	must2(b.Define(dana, Definition{Name: "accounts", Title: "Enabled accounts", Source: "entra", Query: id.popQuery,
		Fresh: 24 * time.Hour}))
	if _, err := b.Approve(asLee(), waiting.TestID); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("approving a draft over a population redefined since was answered %v", err)
	}
	// Drafted again over the population as it is, and approved, it runs.
	must2(b.Define(dana, Definition{Name: "accounts", Title: "Enabled accounts", Source: "entra", Query: narrowed,
		Fresh: 24 * time.Hour}))
	again := Draft{Control: "AC-01", Name: "weekly-mfa", Population: "accounts", Assertion: "all",
		Query: DraftQuery{Of: "Observation", Member: "about", Terms: narrowed.Terms}}
	p := must(b.ProposeDraft(dana, again))
	if p.TestID != tid {
		t.Fatal("the redrafted test is another test")
	}
	must(b.Approve(asLee(), tid))
	b.clock.forward(time.Hour)
	if run, _ := must2(b.RunTest(Scheduler(), tid)); run.Record.Outcome != register.Pass {
		t.Errorf("approved again over the narrowed population the test came out %s (%q)", run.Record.Outcome, run.Problem)
	}
}

// A control stands as its runs came out, read from the runs themselves.
// Evidence that names a real run and says it came out otherwise, written
// over the evidence the run left or beside it, does not move the control:
// the run is what the status moves on, and the evidence only points at it.
func TestEvidenceIsReadAsItsRunCameOut(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 3, 2)
	tid := b.approvedTest(t, dana)
	run, rc := must2(b.RunTest(Scheduler(), tid))
	if run.Record.Outcome != register.Fail {
		t.Fatalf("the run came out %s", run.Record.Outcome)
	}
	runID := mustID(t, run.Record)
	over := register.Evidence{Control: id.control, Run: runID, At: run.Record.Ran, Outcome: register.Pass,
		Grade: register.GradeConnector}
	b.put(t, importer, over)
	if got := must(b.Reg.Get(mustID(t, over))).Record.(register.Evidence); got.Outcome != register.Pass {
		t.Fatalf("the evidence was not written over: %+v (%s)", got, rc.Commit)
	}
	if s := must(Standings(b.view(t)))[id.control]; s.Outcome != register.Fail || s.Failed != 1 {
		t.Errorf("evidence saying a failing run passed moved the control to %+v", s)
	}
	later := over
	later.At = run.Record.Ran + 3600
	b.put(t, importer, later)
	if s := must(Standings(b.view(t)))[id.control]; s.Outcome != register.Fail || s.At != run.Record.Ran {
		t.Errorf("evidence dated after its run moved the control to %+v", s)
	}
}

// A test that says how often it runs is due on its own period, and a
// draft asking to run more often than hourly is refused.
func TestATestRunsOnItsOwnPeriod(t *testing.T) {
	b := newBench(t)
	b.facts(t, 2, 2)
	d := Draft{Control: "AC-01", Name: "twice-daily", Population: "accounts", Assertion: "all", Every: 12 * 3600,
		Query: DraftQuery{Of: "Observation", Member: "about", Terms: []register.Term{
			{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}}}}}
	p := must(b.ProposeDraft(model, d))
	must(b.Approve(asLee(), p.TestID))
	if n := must(b.RunDue(Scheduler())); n != 1 {
		t.Fatalf("the scheduler ran %d tests", n)
	}
	b.clock.forward(11 * time.Hour)
	if due := must(b.Due()); len(due) != 0 {
		t.Errorf("a test run every twelve hours is due after eleven: %v", due)
	}
	b.clock.forward(time.Hour)
	if due := must(b.Due()); !slices.Equal(due, []register.ID{p.TestID}) {
		t.Errorf("a test run every twelve hours is not due after twelve: %v", due)
	}
	d.Name, d.Every = "every-minute", 60
	if _, err := b.ProposeDraft(model, d); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a draft run every minute was answered %v", err)
	}
}
