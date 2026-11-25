// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

// laptops writes two sources' assets, each by serial number.
func (b *bench) laptops(t testing.TB, mdm, cmdb []string) (register.ID, register.ID) {
	t.Helper()
	a, c := source("intune", register.GradeConnector), source("cmdb", register.GradeImported)
	recs := []register.Record{a, c}
	for _, s := range mdm {
		recs = append(recs, register.Asset{Source: mustID(t, a), Ref: s, Type: "device"})
	}
	for _, s := range cmdb {
		recs = append(recs, register.Asset{Source: mustID(t, c), Ref: s, Type: "device"})
	}
	b.put(t, importer, recs...)
	return mustID(t, a), mustID(t, c)
}

func assetID(t testing.TB, src register.ID, ref string) register.ID {
	return mustID(t, register.Asset{Source: src, Ref: ref, Type: "device"})
}

// A link is made where two sources report the same identifier exactly,
// and only there. An identifier two records of one source share is
// ambiguous and links neither.
func TestLinkOnlyOnExactIdentifier(t *testing.T) {
	b := newBench(t)
	mdm, cmdb := b.laptops(t, []string{"C02XL0ABJGH5", "C02XL0ABJGH6", "PF2KQ7"}, []string{"C02XL0ABJGH5", "PF2KQ7", "9X1"})
	c, _ := must2(b.Link(importer, "serial", Side{Source: mdm}, Side{Source: cmdb}))
	if len(c.Links) != 2 {
		t.Fatalf("%d links were made, and two serials are shared", len(c.Links))
	}
	for _, l := range c.Links {
		if l.On != "serial" || l.A >= l.B || !l.Match.Valid() {
			t.Errorf("the link %+v", l)
		}
	}
	want := []register.ID{assetID(t, mdm, "C02XL0ABJGH5"), assetID(t, cmdb, "C02XL0ABJGH5")}
	slices.Sort(want)
	if !slices.ContainsFunc(c.Links, func(l register.Link) bool { return l.A == want[0] && l.B == want[1] }) {
		t.Errorf("the shared serial did not link its two assets: %+v", c.Links)
	}
	if n := must(b.Reg.Counts())[register.KindLink]; n != 2 {
		t.Errorf("the register holds %d links", n)
	}
	// A serial a second asset of the same source reports too is ambiguous.
	other := source("intune", register.GradeConnector)
	b.put(t, importer, register.Asset{Source: mustID(t, other), Ref: "PF2KQ7", Type: "application"})
	c2 := must(Correlate(b.view(t), "serial", Side{Source: mdm}, Side{Source: cmdb}))
	if len(c2.Links) != 1 || c2.Ambiguous != 1 {
		t.Errorf("with one serial on two records of one source, %d links and %d ambiguous", len(c2.Links), c2.Ambiguous)
	}
	if _, err := Correlate(b.view(t), "colour", Side{Source: mdm}, Side{Source: cmdb}); err == nil {
		t.Error("a link was made on something that is not an identifier")
	}
}

// No link is made on a near match: a different case, another punctuation
// mark, a character
// that looks the same, a prefix or a trailing dot.
func TestNoFuzzyLink(t *testing.T) {
	b := newBench(t)
	mdm, cmdb := b.laptops(t,
		[]string{"LAPTOP-07", "host_12", "srv-ﾛ1", "db-01", "web01.example.com"},
		[]string{"laptop-07", "host-12", "srv-ロ1", "db-01.example.com", "web01.example.com."})
	c := must(Correlate(b.view(t), "hostname", Side{Source: mdm}, Side{Source: cmdb}))
	if len(c.Links) != 0 {
		t.Errorf("near matches were linked: %+v", c.Links)
	}
}

// staff writes an identity provider's accounts and the people HR employs,
// each side reporting the hash of an address, of which shared are the
// same people.
func (b *bench) staff(t testing.TB, accounts, people, shared int) (register.ID, register.ID) {
	t.Helper()
	entra, hr := source("entra", register.GradeConnector), source("hr", register.GradeImported)
	eid, hid := mustID(t, entra), mustID(t, hr)
	recs := []register.Record{entra, hr}
	for i := 0; i < accounts; i++ {
		recs = append(recs, register.Observation{Source: eid, About: acct(i), Fact: "account.enabled",
			Value: register.BoolValue(true), Grade: register.GradeConnector},
			register.Observation{Source: eid, About: acct(i), Fact: "email.hash",
				Value: register.TextValue(hashOf(fmt.Sprintf("person%d@example.org", i))), Grade: register.GradeConnector})
	}
	for i := 0; i < people; i++ {
		n := i
		if i >= shared {
			n = accounts + i // somebody HR employs who has no account
		}
		recs = append(recs, register.Observation{Source: hid, About: acct(10000 + i), Fact: "email.hash",
			Value: register.TextValue(hashOf(fmt.Sprintf("person%d@example.org", n))), Grade: register.GradeImported})
	}
	b.put(t, importer, recs...)
	return eid, hid
}

func factQuery(t testing.TB, fact string) register.Query {
	return must(CheckQuery(register.Query{Of: "Observation", Member: "about", Terms: []register.Term{
		{Field: "fact", Op: register.OpEquals, Values: []register.Scalar{register.TextValue(fact)}}}}))
}

// The disagreement between a population's source and its cross-check is a
// number of its own: the identity provider's 641 accounts against HR's 598
// staff, linked on the hash of each address, leave 43 unexplained.
func TestDisagreementNumber(t *testing.T) {
	b := newBench(t)
	eid, hid := b.staff(t, 641, 598, 598)
	must2(b.Link(importer, "email-hash", Side{Source: eid, Fact: "email.hash"}, Side{Source: hid, Fact: "email.hash"}))
	cross := factQuery(t, "email.hash")
	pid, _ := must2(b.Define(dana, Definition{Name: "staff-accounts", Title: "Staff accounts", Source: "entra",
		Query: factQuery(t, "account.enabled"), Fresh: 24 * time.Hour, Independent: true,
		CrossCheck: "hr", CrossQuery: &cross}))
	c, _ := must2(b.Recount(importer, pid))
	if len(c.Members) != 641 || len(c.Cross) != 598 || c.Unexplained() != 43 {
		t.Fatalf("entra %d accounts, hr %d staff: %d unexplained", len(c.Members), len(c.Cross), c.Unexplained())
	}
	if len(c.OnlyHere) != 43 || len(c.OnlyThere) != 0 {
		t.Errorf("%d only in entra and %d only in hr", len(c.OnlyHere), len(c.OnlyThere))
	}
	got := must(b.Reg.Get(pid)).Record.(register.Population)
	if got.Size != 641 || got.CrossSize != 598 || got.Unexplained != 43 || got.Commit == "" || got.Counted == 0 {
		t.Errorf("the population records %d, %d and %d unexplained", got.Size, got.CrossSize, got.Unexplained)
	}
	if line := Disagreement(c); line != "entra 641, hr 598: 43 unexplained" {
		t.Errorf("the disagreement is said %q", line)
	}
	// Disagreement both ways is counted both ways, never netted off.
	b2 := newBench(t)
	e2, h2 := b2.staff(t, 10, 12, 7)
	must2(b2.Link(importer, "email-hash", Side{Source: e2, Fact: "email.hash"}, Side{Source: h2, Fact: "email.hash"}))
	p2, _ := must2(b2.Define(dana, Definition{Name: "staff-accounts", Source: "entra", Query: factQuery(t, "account.enabled"),
		Fresh: time.Hour, Independent: true, CrossCheck: "hr", CrossQuery: &cross}))
	c2, _ := must2(b2.Recount(importer, p2))
	if c2.Unexplained() != 3+5 {
		t.Errorf("10 accounts and 12 staff sharing 7 leave %d unexplained, not 8", c2.Unexplained())
	}
}

// A population with one source is labelled as unchecked wherever it is
// shown.
func TestSingleSourceLabelled(t *testing.T) {
	b := newBench(t)
	b.facts(t, 3, 3)
	pid := must(register.DeriveID(register.KindPopulation, register.Local, "accounts"))
	c, _ := must2(b.Recount(importer, pid))
	if !slices.Contains(c.Labels, Unchecked) {
		t.Errorf("a population with one source is labelled %v", c.Labels)
	}
	if c.Unexplained() != 0 || c.Population.CrossSize != 0 {
		t.Errorf("a population with one source has a disagreement: %+v", c.Population)
	}
	if line := Disagreement(c); line != "entra 3: single source, unchecked" {
		t.Errorf("a population with one source is said %q", line)
	}
}

// A population not declared independent of the tool it measures is
// labelled circular, and so is a run whose facts come from the source its
// population is counted from.
func TestCircularDenominatorLabelled(t *testing.T) {
	b := newBench(t)
	b.facts(t, 3, 2)
	pid := must(register.DeriveID(register.KindPopulation, register.Local, "accounts"))
	c, _ := must2(b.Recount(importer, pid))
	if !slices.Contains(c.Labels, Circular) {
		t.Errorf("a population drawn from the tool it measures is labelled %v", c.Labels)
	}
	tid := b.approvedTest(t, dana)
	run, _ := must2(b.RunTest(Scheduler(), tid))
	if !run.Circular {
		t.Error("a run reading facts from its population's source is not marked circular")
	}
	independent := register.Population{Name: "people", Source: c.Population.Source, Query: c.Population.Query,
		Fresh: 3600, Independent: true, CrossCheck: must(register.DeriveID(register.KindSource, register.Local, "hr")),
		CrossQuery: c.Population.Query, Counted: register.TimeOf(b.clock.now())}
	if slices.Contains(Labels(independent, b.clock.now()), Circular) {
		t.Error("a population declared independent is labelled circular")
	}
	b.clock.forward(2 * time.Hour)
	if !slices.Contains(Labels(independent, b.clock.now()), Stale) {
		t.Error("a count older than the population allows is not labelled stale")
	}
}

// A population's members are read from its source, so it is drawn from a
// kind whose records say which source reported them. Subjects, links and
// the programme's own records name no source, and a population over them
// would read every one of them whatever source it named, and agree with
// any cross-check: it is refused, and one written some other way counts
// nothing.
func TestAPopulationIsReadFromItsSource(t *testing.T) {
	b := newBench(t)
	id := b.facts(t, 3, 3)
	everyone := must(CheckQuery(register.Query{Of: "Subject"}))
	facts := factQuery(t, "account.enabled")
	for name, d := range map[string]Definition{
		"its members":     {Name: "people", Source: "entra", Query: everyone, Fresh: time.Hour},
		"its cross-check": {Name: "people", Source: "entra", Query: facts, Fresh: time.Hour, CrossCheck: "hr", CrossQuery: &everyone},
	} {
		if _, _, err := b.Define(dana, d); !errors.Is(err, register.ErrInvalid) {
			t.Errorf("a population whose query for %s reads a kind with no source was answered %v", name, err)
		}
	}
	pop := register.Population{Name: "people", Source: id.entra, Query: everyone.Digest, Fresh: 3600, Independent: true,
		CrossCheck: id.hr, CrossQuery: everyone.Digest}
	b.put(t, dana, everyone, pop)
	if c, err := CountAt(b.view(t), mustID(t, pop), b.clock.now()); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a population over subjects, cross-checked against a source that reported none, counted %q (%v)",
			Disagreement(c), err)
	}
}
