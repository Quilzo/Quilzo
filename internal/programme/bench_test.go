// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
)

// clock is a clock a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) forward(d time.Duration) { c.t = c.t.Add(d) }

// bench is a programme on a register of its own, with its audit entries and
// its clock.
type bench struct {
	*Programme
	log   []audit.Record
	clock *clock
}

func newBench(t testing.TB) *bench {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	b := &bench{clock: &clock{time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}}
	reg := register.Open(s)
	reg.Now = b.clock.now
	reg.Audit = func(r audit.Record) error { b.log = append(b.log, r); return nil }
	b.Programme = &Programme{Reg: reg, Keep: &MemKeeper{}, Now: b.clock.now}
	return b
}

func allow(auth.Action, string) error { return nil }

var (
	dana     = register.Actor{Name: "dana", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, Verified: true, May: allow}
	lee      = register.Actor{Name: "lee", Subject: "1ee00000000000000000000000000002", Kind: audit.KindHuman, Verified: true, May: allow}
	importer = register.Actor{Name: "evidence-clerk", Kind: audit.KindService, Verified: true, May: allow}
	model    = register.Actor{Name: "control-tester", Kind: audit.KindAI, Model: "an-agent", Verified: true, May: allow}
)

// asDana and asLee are the two people who decide, with two eligible.
func asDana() Decider { return Decider{By: dana, Eligible: 2, Proof: "dana's session"} }
func asLee() Decider  { return Decider{By: lee, Eligible: 2, Proof: "lee's session"} }

// alone is dana as the only person eligible.
func alone() Decider { return Decider{By: dana, Eligible: 1, Proof: "dana's session"} }

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
	must(b.Approve(asLee(), p.TestID))
	return p.TestID
}
