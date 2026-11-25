// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
)

// clock is a clock a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) forward(d time.Duration) { c.t = c.t.Add(d) }

// bench is a programme on a register of its own, with its audit entries,
// its clock, the access policy its approvers are asked by, and who
// approves what dana raises: lee, where two people may approve, and dana
// herself where she is the only one.
type bench struct {
	*Programme
	log      []audit.Record
	clock    *clock
	access   *auth.Policy
	approver string
}

// newBench is a programme where dana and lee may each approve.
func newBench(t testing.TB) *bench { return benchOf(t, "dana", "lee") }

// newBenchAlone is a programme where dana is the only person who may.
func newBenchAlone(t testing.TB) *bench { return benchOf(t, "dana") }

func benchOf(t testing.TB, approvers ...string) *bench {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	b := &bench{clock: &clock{time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}, access: &auth.Policy{},
		approver: approvers[len(approvers)-1]}
	for _, who := range approvers {
		if err := b.access.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: register.Area}); err != nil {
			t.Fatal(err)
		}
	}
	reg := register.Open(s)
	reg.Now = b.clock.now
	reg.Audit = func(r audit.Record) error { b.log = append(b.log, r); return nil }
	// dana and lee are in the subject map under the pseudonyms the test
	// names them by, so the approvals know them as the register does.
	for _, a := range []register.Actor{dana, lee} {
		if _, err := reg.Side().Adopt(a.Name, "person", string(a.Subject)); err != nil {
			t.Fatal(err)
		}
	}
	m := &approval.Approvals{Root: s.Root(), Register: reg, Access: b.access, Audit: reg.Audit, Now: b.clock.now}
	b.Programme = &Programme{Reg: reg, Approvals: m, Now: b.clock.now}
	return b
}

func allow(auth.Action, string) error { return nil }

var (
	dana     = register.Actor{Name: "dana", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, Verified: true, May: allow}
	lee      = register.Actor{Name: "lee", Subject: "1ee00000000000000000000000000002", Kind: audit.KindHuman, Verified: true, May: allow}
	importer = register.Actor{Name: "evidence-clerk", Kind: audit.KindService, Verified: true, May: allow}
	model    = register.Actor{Name: "control-tester", Kind: audit.KindAI, Model: "an-agent", Verified: true, May: allow}
)

// console is somebody at the store's console, as the approvals module
// knows them, asked the access policy as themselves.
func (b *bench) console(name string) approval.Person {
	return approval.Person{Name: name, Kind: audit.KindHuman, Verified: true, Console: true,
		May: func(act auth.Action, resource string) error {
			if d := b.access.Evaluate(name, act, resource); !d.Allowed {
				return errors.New(d.Reason)
			}
			return nil
		}}
}

// approve is somebody approving a waiting decision at the console, typing
// back the hash it shows now.
func (b *bench) approve(name string, id register.ID) (Decided, error) {
	a, err := b.Approvals.Ask(id)
	if err != nil {
		return Decided{}, err
	}
	return b.Approve(b.console(name), id, approval.Proof{Console: &approval.ConsoleProof{Typed: a.Hash}})
}

// agreed is a decision dana raised, approved by the bench's approver.
func (b *bench) agreed(t testing.TB, d Decided) Decided {
	t.Helper()
	if !d.Waits {
		t.Fatalf("a decision raised did not wait for its approval: %+v", d)
	}
	return must(b.approve(b.approver, d.ID))
}

// byHand is an approval of rec put together without the approvals module,
// over what rec shows now: what a writer that went round it would send.
func (b *bench) byHand(t testing.TB, rec register.Record) *register.Approval {
	t.Helper()
	shown := must(b.Reg.Surface(withApproval(rec, nil), mustID(t, withApproval(rec, nil))))
	return &register.Approval{Atom: "approve", Rule: "control-test", Needed: 1, Of: 2, Surface: shown, Raised: dana.Subject,
		Signers: []register.Signer{{Subject: lee.Subject, At: register.TimeOf(b.clock.now()), Method: "console",
			Assertion: register.Digest("sha256:" + strings.Repeat("0", 64))}}}
}

// must is a value a test needs, or the end of the test. It panics, which
// the test runner reports as the test's failure with where it was.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func mustID(t testing.TB, rec register.Record) register.ID {
	t.Helper()
	return must(register.IDOf(rec))
}

func (b *bench) put(t testing.TB, by register.Actor, recs ...register.Record) register.Receipt {
	t.Helper()
	return must(b.Reg.Put(by, "a test's write", recs...))
}

func (b *bench) view(t testing.TB) *register.View {
	t.Helper()
	return must(b.Reg.At(""))
}

// source is a source record, with the grade of the facts it yields.
func source(name string, grade register.Grade) register.Source {
	return register.Source{Name: name, Type: "import", Fresh: 86400, Grade: grade}
}

// hashOf stands in for the hash of somebody's address, as a source
// reports it.
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// acct is a pseudonym the test makes from a number, so that a failure
// names a member a reader can find.
func acct(n int) register.ID {
	return register.ID(fmt.Sprintf("%032x", n+1))
}

// identity is a small estate: an identity provider that knows of n
// accounts, each with or without a second factor, and the control,
// population and test that check them.
type identity struct {
	entra, hr  register.ID
	control    register.ID
	population register.ID
	popQuery   register.Query
	mfaQuery   register.Query
}

// facts writes n accounts from the identity provider, the first enrolled
// of them with a second factor.
func (b *bench) facts(t testing.TB, n, enrolled int) identity {
	t.Helper()
	entra, hr := source("entra", register.GradeConnector), source("hr", register.GradeImported)
	recs := []register.Record{entra, hr}
	id := identity{entra: mustID(t, entra), hr: mustID(t, hr)}
	for i := 0; i < n; i++ {
		recs = append(recs, register.Subject{Pseudonym: acct(i), Type: "account"},
			register.Observation{Source: id.entra, About: acct(i), Fact: "account.enabled", Value: register.BoolValue(true),
				Grade: register.GradeConnector},
			register.Observation{Source: id.entra, About: acct(i), Fact: "mfa.registered",
				Value: register.BoolValue(i < enrolled), Grade: register.GradeConnector})
	}
	ctl := register.Control{Ref: "AC-01", Title: "Every account has a second factor", Domain: "identity", Owner: dana.Subject}
	recs = append(recs, ctl)
	b.put(t, importer, recs...)
	id.control = mustID(t, ctl)
	id.popQuery = must(CheckQuery(register.Query{Of: "Observation", Member: "about",
		Terms: []register.Term{{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("account.enabled")}}}}))
	id.mfaQuery = must(CheckQuery(register.Query{Of: "Observation", Member: "about",
		Terms: []register.Term{{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}},
			{Field: "value", Op: register.OpEquals, Values: []register.Scalar{register.BoolValue(true)}}}}))
	id.population = must(func() (register.ID, error) {
		pid, _, err := b.Define(dana, Definition{Name: "accounts", Title: "Enabled accounts", Source: "entra",
			Query: id.popQuery, Fresh: 24 * time.Hour})
		return pid, err
	}())
	return id
}

// approvedTest drafts the second-factor test as dana and approves it as
// lee, and returns the test's identifier.
func (b *bench) approvedTest(t testing.TB, by register.Actor) register.ID {
	t.Helper()
	d := Draft{Control: "AC-01", Name: "weekly-mfa", Population: "accounts", Assertion: "all",
		Query: DraftQuery{Of: "Observation", Member: "about", Terms: []register.Term{
			{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue("mfa.registered")}},
			{Field: "value", Op: register.OpEquals, Values: []register.Scalar{register.BoolValue(true)}}}}}
	p := must(b.ProposeDraft(by, d))
	must(b.approve("lee", p.TestID))
	return p.TestID
}
