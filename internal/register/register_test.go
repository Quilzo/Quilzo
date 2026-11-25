// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/crosswalk"
	"github.com/quilzo/quilzo/internal/store"
)

// clock is a clock a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) forward(d time.Duration) { c.t = c.t.Add(d) }

// bench is a register on a store of its own, with the audit entries it
// wrote and its clock.
type bench struct {
	*Register
	log   []audit.Record
	clock *clock
}

func newBench(t testing.TB) *bench {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	b := &bench{Register: Open(s), clock: &clock{time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}}
	b.Now = b.clock.now
	b.Audit = func(r audit.Record) error { b.log = append(b.log, r); return nil }
	return b
}

// allow is a policy gate that lets everything through, and deny one that
// lets nothing.
func allow(auth.Action, string) error { return nil }
func deny(act auth.Action, resource string) error {
	return fmt.Errorf("dana holds no role that allows %s on %s", act, resource)
}

var (
	dana     = Actor{Name: "dana", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, Verified: true, May: allow}
	lee      = Actor{Name: "lee", Subject: "1ee00000000000000000000000000002", Kind: audit.KindHuman, Verified: true, May: allow}
	importer = Actor{Name: "evidence-clerk", Kind: audit.KindService, Verified: true, May: allow}
	model    = Actor{Name: "control-tester", Kind: audit.KindAI, Model: "an-agent", Verified: true, May: allow}
)

const owner ID = "0123456789abcdef0123456789abcdef"

func digest(n int) Digest { return probeDigest("test", n) }

// signedBy is an approval asked for by one person and given by another.
func signedBy(raised, approver ID) *Approval {
	return &Approval{Atom: "approve-test", Rule: "author-is-not-approver", Needed: 1, Of: 2,
		Surface: digest(1), Raised: raised,
		Signers: []Signer{{Subject: approver, At: 1_790_000_000, Assertion: digest(2)}}}
}

func control(ref string) Control {
	return Control{Ref: ref, Title: "Second factor for every account", Domain: "identity", Owner: owner}
}

func mustPut(t testing.TB, b *bench, by Actor, recs ...Record) Receipt {
	t.Helper()
	rc, err := b.Put(by, "a test's write", recs...)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	return rc
}

func mustID(t testing.TB, rec Record) ID {
	t.Helper()
	id, err := IDOf(rec)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A record's identifier is the same whoever works it out, and whenever.
//
// The value below is the identifier of the control AC-01 as this program
// first derived it. It is written out because the derivation can never
// change: every record ever written is filed under it, and every bundle
// handed to an auditor names records by it. A change to the hash, to the
// domain line or to how the three parts are framed fails here before it
// renames anything.
func TestDeterministicIDStable(t *testing.T) {
	const want ID = "6ab6549f3cd1653d58a109708cbf62ab"
	got := mustID(t, control("AC-01"))
	if got != want {
		t.Errorf("the control AC-01 is %s; it has always been %s", got, want)
	}
	if again := mustID(t, control("AC-01")); again != got {
		t.Errorf("the same control was %s and then %s", got, again)
	}
	// The title is not the key: a control renamed is the same control.
	renamed := control("AC-01")
	renamed.Title = "Second factors"
	if mustID(t, renamed) != got {
		t.Error("renaming a control changed which record it is")
	}
	// The source and the key are framed, not joined: ("ab", "c") is not
	// ("a", "bc").
	one, _ := DeriveID(KindControl, "ab", "c")
	two, _ := DeriveID(KindControl, "a", "bc")
	if one == two {
		t.Error("two different sources and keys made one identifier")
	}
	// And a control and a risk that share a reference are two records.
	risk, _ := DeriveID(KindRisk, Local, "AC-01")
	if risk == got {
		t.Error("a risk and a control with one reference share an identifier")
	}
	if _, err := DeriveID(KindControl, Local, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("a record with no natural key was given an identifier: %v", err)
	}
	// A subject's identifier is its pseudonym, which is random.
	a, _ := NewSubjectID()
	b, _ := NewSubjectID()
	if !a.Valid() || a == b {
		t.Errorf("two minted pseudonyms were %q and %q", a, b)
	}
	if id := mustID(t, Subject{Pseudonym: a, Type: "person"}); id != a {
		t.Errorf("a subject's identifier is %s, not its pseudonym %s", id, a)
	}
}

// Writing what is already there writes nothing.
func TestUnchangedRecordMakesNoCommit(t *testing.T) {
	b := newBench(t)
	first := mustPut(t, b, dana, control("AC-01"), control("AC-02"))
	if first.Commit == "" || len(first.Written) != 2 {
		t.Fatalf("the first write made %q and wrote %d", first.Commit, len(first.Written))
	}
	head, entries := b.Head(), len(b.log)

	b.clock.forward(time.Hour)
	again := mustPut(t, b, dana, control("AC-01"), control("AC-02"))
	if again.Commit != "" || len(again.Written) != 0 || again.Unchanged != 2 {
		t.Errorf("an identical write made commit %q, wrote %d and found %d unchanged", again.Commit, len(again.Written), again.Unchanged)
	}
	if b.Head() != head {
		t.Error("an identical write moved the register's head")
	}
	if len(b.log) != entries {
		t.Errorf("an identical write added %d audit entries for a write that did not happen", len(b.log)-entries)
	}

	// One of two changed: one record written, one found as it was, and the
	// changed one keeps the moment it was first written.
	b.clock.forward(time.Hour)
	changed := control("AC-02")
	changed.Title = "Second factor, phishing-resistant"
	mixed := mustPut(t, b, dana, control("AC-01"), changed)
	if len(mixed.Written) != 1 || mixed.Unchanged != 1 || mixed.Written[0].New {
		t.Errorf("a write of one changed record wrote %+v and found %d unchanged", mixed.Written, mixed.Unchanged)
	}
	e, err := b.Get(mustID(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	if e.Created != first.At || e.Updated != mixed.At {
		t.Errorf("the changed record was created %d and updated %d; it was first written %d and changed %d",
			e.Created, e.Updated, first.At, mixed.At)
	}
}

// The invariants are the kind's own, in Go, and run on every record of
// every batch: there is no schema to bind, to forget or to skip.
func TestPutChecksInvariantsWithoutSchema(t *testing.T) {
	approver := ID("a0000000000000000000000000000009")
	good := Exception{Ref: "EX-1", About: mustID(t, control("AC-01")), Reason: Text(digest(3)), Owner: owner,
		Starts: 1_790_000_000, Expires: 1_790_000_000 + 90*86_400, Approval: signedBy(owner, approver)}
	for name, tc := range map[string]struct {
		rec  Record
		says string
	}{
		"a field that is needed": {Control{Ref: "AC-01", Title: "No owner", Domain: "identity"}, `"owner" is needed`},
		"a value outside its enumeration": {Control{Ref: "AC-01", Title: "T", Domain: "everything", Owner: owner},
			`"domain" is "everything"`},
		"an identifier that is a name":  {Control{Ref: "AC-01", Title: "T", Domain: "identity", Owner: "dana"}, `"owner" is not a record's identifier`},
		"a label that is two lines":     {Control{Ref: "AC-01", Title: "T\nsecond line", Domain: "identity", Owner: owner}, "control character"},
		"a label with a hidden letter":  {Control{Ref: "AC​-01", Title: "T", Domain: "identity", Owner: owner}, "not shown"},
		"free text where a digest goes": {Control{Ref: "AC-01", Title: "T", Domain: "identity", Owner: owner, Objective: "Keep attackers out."}, `"objective" is not a digest`},
		"a number out of range":         {Risk{Ref: "R-1", Title: "T", Owner: owner, Raised: owner, Likelihood: 9, Impact: 2, Status: "open"}, `"likelihood" is 9`},
		"a decision with no approval": {func() Record { e := good; e.Approval = nil; return e }(),
			`"approval" is needed`},
		"an exception with no end in sight": {func() Record { e := good; e.Expires = e.Starts + 400*86_400; return e }(),
			"at most 366 days"},
		"an approval by whoever asked": {func() Record { e := good; e.Approval = signedBy(owner, owner); return e }(),
			"cannot be the one who approves"},
		"an approval with too few approvers": {func() Record {
			e := good
			a := *signedBy(owner, approver)
			a.Needed = 2
			e.Approval = &a
			return e
		}(), "needs 2 approver(s) and holds 1"},
		"a decision made alone with no review": {func() Record {
			e := good
			a := *signedBy(owner, owner)
			a.Alone, a.Of = true, 1
			e.Approval = &a
			return e
		}(), "compensating review"},
		"an accepted risk nobody accepted": {Risk{Ref: "R-1", Title: "T", Owner: owner, Raised: owner, Likelihood: 2, Impact: 2,
			Status: "accepted"}, "carries the approval"},
		"a run that passed with failures": {TestRun{Test: owner, Ran: 1_790_000_000, Outcome: Pass, Population: digest(4),
			Size: 10, Failing: []ID{owner}, Snapshot: digest(5)}, "names no failing members"},
		"evidence from nowhere": {Evidence{Control: owner, At: 1_790_000_000, Outcome: Pass, Grade: GradeConnector},
			"a test run or from a person's statement"},
		"a minuted decision with no minute": {Decision{Ref: "D-1", Title: "T", Authority: "minuted", Decided: 1_790_000_000,
			Decider: owner}, "minute's reference"},
		"a connector that may reach anything": {Source{Name: "entra", Type: "connector", Fresh: 3600, Grade: GradeConnector},
			"names the hosts"},
		"a host that is a pattern": {Source{Name: "entra", Type: "connector", Fresh: 3600, Grade: GradeConnector,
			Hosts: []string{"*.example.com"}}, "not a pattern"},
		"a source that writes unapproved": {Source{Name: "okta", Type: "connector", Fresh: 3600, Grade: GradeConnector,
			Hosts: []string{"example.okta.com"}, Write: true}, "reads only"},
		"an AI system live unapproved": {AISystem{Name: "helper", Title: "Helper", Owner: owner, Role: "deployer", Risk: "other",
			Status: "live", Enforcement: "none"}, "does not go live without an approval"},
		"a fact that is a list": {Observation{Source: owner, About: owner, Fact: "groups", Value: Scalar{[]any{"a"}},
			Grade: GradeConnector}, "text, a number or true or false"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBench(t)
			_, err := b.Put(dana, "a test's write", tc.rec)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("it was answered %v; it is refused as not valid, saying %q", err, tc.says)
			}
			if b.Head() != "" {
				t.Error("a refused record moved the register's head")
			}
		})
	}
	// The good one is written, and one bad record refuses the whole batch.
	b := newBench(t)
	mustPut(t, b, dana, good)
	head := b.Head()
	if _, err := b.Put(dana, "a test's write", control("AC-07"), Control{Ref: "AC-08"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a batch with one bad record was answered %v", err)
	}
	if b.Head() != head {
		t.Error("a batch with one bad record wrote the good ones")
	}
}

// A batch is one commit, whatever it holds.
func TestBatchIsOneCommit(t *testing.T) {
	b := newBench(t)
	var recs []Record
	for i := 0; i < 50; i++ {
		recs = append(recs, control(fmt.Sprintf("AC-%02d", i)))
	}
	recs = append(recs, Service{Name: "payments", Title: "Payments", Owner: owner, Criticality: "critical"})
	first := mustPut(t, b, importer, recs...)
	hist, err := b.Store.History(b.Head(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].ID != first.Commit || len(first.Written) != 51 {
		t.Fatalf("a batch of 51 records made %d commit(s) and wrote %d", len(hist), len(first.Written))
	}
	if hist[0].Commit.Author != "" || strings.Contains(fmt.Sprint(hist[0].Commit), "evidence-clerk") {
		t.Errorf("the commit names its writer, %+v; a name belongs in the audit log, which can be erased from", hist[0].Commit)
	}
	second := mustPut(t, b, dana, control("AC-90"), control("AC-91"))
	if hist, _ = b.Store.History(b.Head(), 10); len(hist) != 2 || second.Parent != first.Commit {
		t.Errorf("a second batch left %d commits, the newest after %q", len(hist), second.Parent)
	}
	if hist[0].Commit.Author != string(dana.Subject) {
		t.Errorf("the commit's author is %q; it is the writer's pseudonym", hist[0].Commit.Author)
	}
	// The same record twice in a batch is one record; two that differ
	// under one identifier are refused.
	if rc := mustPut(t, b, dana, control("AC-95"), control("AC-95")); len(rc.Written) != 1 {
		t.Errorf("a record given twice was written %d times", len(rc.Written))
	}
	other := control("AC-96")
	other.Title = "Something else"
	if _, err := b.Put(dana, "a test's write", control("AC-96"), other); !errors.Is(err, ErrInvalid) {
		t.Errorf("two different records under one identifier were answered %v", err)
	}
}

// Every write is recorded, and its receipt and its audit entry are about
// the same thing.
func TestEveryPutHasAuditEntryAndReceipt(t *testing.T) {
	b := newBench(t)
	rc := mustPut(t, b, dana, control("AC-01"))
	if len(b.log) != 1 {
		t.Fatalf("one write left %d audit entries", len(b.log))
	}
	e := b.log[0]
	if e.Action != AuditAction || e.Outcome != audit.Success || e.Principal != "dana" || e.Kind != audit.KindHuman || !e.Verified {
		t.Errorf("the entry is %+v", e)
	}
	if e.Detail["commit"] != rc.Commit || e.Detail["receipt"] != string(rc.Digest) || e.Detail["written"] != "1" ||
		e.Detail["kinds"] != "sec_control" {
		t.Errorf("the entry's detail %v does not match the receipt %+v", e.Detail, rc)
	}
	for k := range e.Detail {
		if why := audit.ForbiddenKey(k); why != "" {
			t.Errorf("the audit log would refuse the whole entry: %s", why)
		}
	}
	if !rc.Digest.Valid() || rc.By != "dana" || rc.At != TimeOf(b.clock.t) || rc.Ref != Ref {
		t.Errorf("the receipt is %+v", rc)
	}
	sealed := rc
	sealed.seal()
	if sealed.Digest != rc.Digest {
		t.Error("the receipt's digest is not the digest of the receipt")
	}
	got, err := b.Get(rc.Written[0].ID)
	if err != nil || got.Object != rc.Written[0].Object || got.Record != Record(control("AC-01")) {
		t.Errorf("the receipt names %s, and the register holds %+v (%v)", rc.Written[0].Object, got, err)
	}

	// With no audit log there is no write.
	bare := newBench(t)
	bare.Audit = nil
	if _, err := bare.Put(dana, "a test's write", control("AC-01")); err == nil || bare.Head() != "" {
		t.Errorf("a register with no audit log wrote: %v", err)
	}
	// An audit log that cannot take the entry stops the write before it
	// is made.
	unready := newBench(t)
	unready.Ready = func() error { return errors.New("the log's disk is full") }
	if _, err := unready.Put(dana, "a test's write", control("AC-01")); err == nil || unready.Head() != "" {
		t.Errorf("a write went ahead with the audit log unable to record it: %v", err)
	}
	// And one that fails afterwards is said, with the receipt.
	failing := newBench(t)
	failing.Audit = func(audit.Record) error { return errors.New("the writer refused") }
	if rc, err := failing.Put(dana, "a test's write", control("AC-01")); !errors.Is(err, ErrUnrecorded) || rc.Commit == "" {
		t.Errorf("a write whose entry failed was answered %v with receipt %+v", err, rc)
	}
}

// The policy gate is asked first, about each kind, and a refusal is
// recorded as one.
func TestPutAsksThePolicyGate(t *testing.T) {
	b := newBench(t)
	var asked []string
	gated := dana
	gated.May = func(act auth.Action, resource string) error {
		asked = append(asked, string(act)+" "+resource)
		if strings.HasSuffix(resource, "/sec_risk") {
			return deny(act, resource)
		}
		return nil
	}
	risk := Risk{Ref: "R-1", Title: "T", Owner: owner, Raised: owner, Likelihood: 2, Impact: 3, Status: "open"}
	_, err := b.Put(gated, "a test's write", control("AC-01"), control("AC-02"), risk)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "holds no role") {
		t.Fatalf("a writer refused for one kind was answered %v", err)
	}
	if want := "edit-draft /@compliance/register/sec_control"; len(asked) != 2 || asked[0] != want {
		t.Errorf("the gate was asked %q; each kind is asked once, as %q", asked, want)
	}
	if b.Head() != "" {
		t.Error("a refused batch wrote the records its writer was allowed")
	}
	if len(b.log) != 1 || b.log[0].Outcome != audit.Denied || b.log[0].Detail["kind"] != "sec_risk" {
		t.Errorf("the refusal was recorded as %+v", b.log)
	}
	// A refusal comes before anything is said about the record.
	if _, err := b.Put(gated, "a test's write", Risk{Ref: "R-2"}); !errors.Is(err, ErrRefused) {
		t.Errorf("somebody who may not write risks was told what was wrong with theirs: %v", err)
	}
	// A surface that forgot the gate has none.
	if _, err := b.Put(Actor{Name: "dana", Kind: audit.KindHuman}, "a test's write", control("AC-01")); !errors.Is(err, ErrRefused) {
		t.Errorf("a write with no gate was answered %v", err)
	}
}

// A model proposes. It does not write the record, and it does not state
// how a control stands.
func TestAModelDoesNotWriteTheRecord(t *testing.T) {
	b := newBench(t)
	if _, err := b.Put(model, "a test's write", control("AC-01")); !errors.Is(err, ErrModel) || b.Head() != "" {
		t.Fatalf("a model's write was answered %v", err)
	}
	if len(b.log) != 1 || b.log[0].Outcome != audit.Denied {
		t.Errorf("the refusal was recorded as %+v", b.log)
	}
	stated := Evidence{Control: mustID(t, control("AC-01")), Attested: owner, At: 1_790_000_000, Outcome: Pass, Grade: GradeUploaded}
	if _, err := b.Put(importer, "a test's write", stated); !errors.Is(err, ErrModel) {
		t.Errorf("a service's statement about a control was answered %v", err)
	}
	mustPut(t, b, dana, stated)
}

// A record of a kind that is never changed is never changed.
func TestAnImmutableKindIsWrittenOnce(t *testing.T) {
	b := newBench(t)
	d := Decision{Ref: "D-2026-014", Title: "Accept the residual risk on the legacy VPN", Authority: "management",
		Decided: 1_790_000_000, Decider: owner}
	mustPut(t, b, dana, d)
	if rc := mustPut(t, b, dana, d); rc.Commit != "" {
		t.Error("the same decision written again made a commit")
	}
	d.Title = "Accept nothing"
	if _, err := b.Put(dana, "a test's write", d); !errors.Is(err, ErrImmutable) {
		t.Errorf("a change to a decision was answered %v", err)
	}
	if got, _ := b.Get(mustID(t, d)); got.Record.(Decision).Title != "Accept the residual risk on the legacy VPN" {
		t.Error("the decision was changed")
	}
}

// The approvals module's check is asked about every approval written.
func TestAnApprovalIsHandedToItsVerifier(t *testing.T) {
	b := newBench(t)
	var seen []ID
	b.Approvals = func(rec Record, id ID, a *Approval) error {
		seen = append(seen, id)
		if a.Signers[0].Assertion == digest(99) {
			return errors.New("the assertion is for another surface")
		}
		return nil
	}
	scope := Scope{Name: "group", Title: "The group", Domains: []Domain{"identity"}}
	scope.Approval = signedBy(owner, "a0000000000000000000000000000009")
	scope.Approval.Surface = SurfaceOf(scope)
	mustPut(t, b, dana, scope)
	if len(seen) != 1 || seen[0] != mustID(t, scope) {
		t.Fatalf("the verifier was asked about %v", seen)
	}
	bad := *scope.Approval
	bad.Signers = []Signer{{Subject: bad.Signers[0].Subject, At: bad.Signers[0].At, Assertion: digest(99)}}
	scope.Approval = &bad
	if _, err := b.Put(dana, "a test's write", scope); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "another surface") {
		t.Errorf("an approval its verifier refused was answered %v", err)
	}
}

// Every kind is whole: it has a schema, a class and a collection the
// generic record surfaces refuse, and its records read back as they were
// written.
func TestEveryKindIsDefinedWhole(t *testing.T) {
	want := []Kind{KindAISystem, KindAcknowledgement, KindApplicability, KindAsset, KindControl, KindControlTest,
		KindDecision, KindEvidence, KindException, KindExtracted, KindIncident, KindLink, KindMapping,
		KindMetricValue, KindObservation, KindPolicy, KindPopulation, KindRequirement, KindRisk, KindRiskAppetite,
		KindScope, KindService, KindSource, KindSubject, KindTestRun, KindVendor}
	have := map[Kind]Spec{}
	for _, s := range Kinds() {
		have[s.Kind] = s
	}
	for _, k := range want {
		s, ok := have[k]
		if !ok {
			t.Errorf("the kind %s is not defined", k)
			continue
		}
		if !strings.HasPrefix(s.Collection, Prefix) || collection.Reserved(s.Collection) == nil {
			t.Errorf("%s is filed under %q, which the generic record surfaces would write to", k, s.Collection)
		}
		if s.Summary == "" || len(s.Fields) == 0 || ordinal(s.Class) == 0 {
			t.Errorf("%s has no summary, no fields or no class: %+v", k, s)
		}
		for _, f := range s.Fields {
			if f.About == "" {
				t.Errorf("%s.%s does not say what it is for", k, f.Name)
			}
			if f.Ref != "" {
				if _, ok := have[f.Ref]; !ok {
					t.Errorf("%s.%s points at %s, which is not a kind", k, f.Name, f.Ref)
				}
			}
		}
		if got, ok := SpecOf(s.Collection); !ok || got.Kind != k {
			t.Errorf("%s is not found by its collection's name", k)
		}
		if s.Resource() != "/@compliance/register/"+s.Collection {
			t.Errorf("%s is asked about as %s", k, s.Resource())
		}
	}
	// The approval is part of the record it approves, not a kind.
	if _, ok := SpecOf("Approval"); ok {
		t.Error("Approval is a kind of its own; it is embedded in the record it approves")
	}
	if _, ok := SpecOf("control-test"); !ok {
		t.Error("a kind is not found by its name written with a dash")
	}
	// What a model extracted is the one kind nothing is counted from.
	for _, s := range Kinds() {
		if s.Unconfirmed != (s.Kind == KindExtracted) {
			t.Errorf("%s is marked unconfirmed=%v", s.Kind, s.Unconfirmed)
		}
	}
	// The relations are the crosswalk's five, spelt the same way.
	var theirs []string
	for _, r := range crosswalk.Relations() {
		theirs = append(theirs, string(r))
	}
	if ours := Relation("").Values(); strings.Join(ours, " ") != strings.Join(theirs, " ") {
		t.Errorf("a mapping's relations are %v and the crosswalk's are %v", ours, theirs)
	}
}

// Every kind's probe record goes in and comes back the same.
func TestRecordsReadBackAsWritten(t *testing.T) {
	b := newBench(t)
	recs, err := Probe{Observations: 20, Controls: 12, Rows: 60}.Records()
	if err != nil {
		t.Fatal(err)
	}
	rc := mustPut(t, b, importer, recs...)
	if len(rc.Written) != len(recs) {
		t.Fatalf("%d records were written of %d", len(rc.Written), len(recs))
	}
	for _, rec := range recs {
		got, err := b.Get(mustID(t, rec))
		if err != nil {
			t.Fatalf("%s: %v", rec.Kind(), err)
		}
		want, _ := canonicalFields(rec)
		have, _ := canonicalFields(got.Record)
		if string(want) != string(have) || got.Kind != rec.Kind() {
			t.Fatalf("a %s was written as %s and read back as %s", rec.Kind(), want, have)
		}
	}
	list, total, err := b.List(KindControl, 5, 4)
	if err != nil || total != 12 || len(list) != 4 {
		t.Fatalf("a page of controls was %d of %d (%v)", len(list), total, err)
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Error("a page is not in the order of its identifiers")
		}
	}
	if _, err := b.Get("ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a record that is not there was answered %v", err)
	}
	if _, err := b.Get("not an identifier"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a word that is no identifier was answered %v", err)
	}
	counts, err := b.Counts()
	if err != nil || counts[KindControl] != 12 || counts[KindEvidence] != 30 || counts[KindRisk] != 0 {
		t.Errorf("the counts are %v (%v)", counts, err)
	}
}

// Put is the only thing that moves the register's refs.
//
// One write path is only one while nothing else writes. So the source of
// the whole program is read for anything that sets either ref, or names
// either in a call that could: outside this package there is to be none.
func TestOnlyThisPackageMovesTheRegistersRefs(t *testing.T) {
	root := filepath.Join("..", "..")
	read := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == ".git" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			filepath.Dir(path) == filepath.Join(root, "internal", "register") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		read++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "SetRef" && sel.Sel.Name != "CompareAndSwapRef") || len(call.Args) == 0 {
				return true
			}
			switch a := call.Args[0].(type) {
			case *ast.BasicLit:
				if strings.Contains(a.Value, `"register`) {
					t.Errorf("%s moves a register ref itself; register.Put is the one way a record is written", path)
				}
			case *ast.SelectorExpr:
				if x, ok := a.X.(*ast.Ident); ok && x.Name == "register" {
					t.Errorf("%s moves %s.%s itself; register.Put is the one way a record is written", path, x.Name, a.Sel.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read < 400 {
		t.Fatalf("only %d source files were read; the walk is wrong", read)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the walk did not start at the repository's root: %v", err)
	}
}
