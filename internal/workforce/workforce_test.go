// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package workforce

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

func person(issuer, value, email, name string) Identity {
	return Identity{
		ID: telemetry.ID{Issuer: issuer, Value: value}, Subject: APerson,
		Email: email, Name: name, Active: yes(), Observed: now,
	}
}

func device(issuer, value string, owner telemetry.ID, seen time.Time) Identity {
	return Identity{
		ID: telemetry.ID{Issuer: issuer, Value: value}, Subject: ADevice,
		Owner: owner, Seen: seen, Observed: now,
	}
}

func roster(t *testing.T, ids ...Identity) *Roster {
	t.Helper()
	r := New()
	for _, i := range ids {
		if err := r.Observe(i); err != nil {
			t.Fatalf("observe %s: %v", i.ID, err)
		}
	}
	return r
}

func link(t *testing.T, r *Roster, a, b telemetry.ID) {
	t.Helper()
	if err := r.Link(Link{A: a, B: b, At: now, By: "rashik",
		Kind: audit.KindHuman, Because: "same person, confirmed"}); err != nil {
		t.Fatalf("link: %v", err)
	}
}

// The finding that needs the join and that neither console will ever raise.
func TestALeaverWhoseLaptopStillChecksIn(t *testing.T) {
	okta := person("okta", "u-1", "jane@acme.test", "Jane Doe")
	okta.Active = no()
	mdm := device("kandji", "MBP-0042",
		telemetry.ID{Issuer: "okta", Value: "u-1"}, now.Add(-2*time.Hour))
	r := roster(t, okta, mdm)

	out := r.Findings(Expect{}, now)
	if len(out) == 0 {
		t.Fatal("a disabled account with a live laptop produced nothing")
	}
	top := out[0]
	if top.Severity != telemetry.SeverityCritical {
		t.Errorf("severity is %v, want critical", top.Severity)
	}
	if !strings.Contains(top.Title, "disabled in okta") ||
		!strings.Contains(top.Title, "MBP-0042") {
		t.Errorf("the title does not say what happened: %q", top.Title)
	}
	if !strings.Contains(top.Evidence[0].What, "neither will raise this") {
		t.Errorf("the evidence does not say why this needs the join: %q",
			top.Evidence[0].What)
	}
}

func TestALeaverIsNotAlsoReportedAsUntrainedAndUnenrolled(t *testing.T) {
	okta := person("okta", "u-1", "jane@acme.test", "Jane Doe")
	okta.Active = no()
	r := roster(t, okta, person("okta", "u-2", "sam@acme.test", "Sam"))

	out := r.Findings(Expect{
		In: []string{"knowbe4"}, Device: true,
	}, now)
	for _, f := range out {
		if strings.Contains(f.Title, "Jane") {
			t.Errorf("a leaver is still in the queue: %q", f.Title)
		}
	}
	// And the person who is still here is.
	var sam int
	for _, f := range out {
		if strings.Contains(f.Title, "Sam") {
			sam++
		}
	}
	if sam != 2 {
		t.Errorf("%d findings for the person who is still here, want the "+
			"missing system and the missing device", sam)
	}
}

func TestADeviceNobodyOwnsIsReportedRatherThanSkipped(t *testing.T) {
	r := roster(t,
		device("kandji", "MBP-0001", telemetry.ID{}, now),
		device("kandji", "MBP-0002",
			telemetry.ID{Issuer: "okta", Value: "u-gone"}, now),
	)
	o := r.Orphans()
	if len(o.Unowned) != 1 || len(o.Dangling) != 1 {
		t.Fatalf("orphans: %d unowned, %d dangling",
			len(o.Unowned), len(o.Dangling))
	}
	out := r.Findings(Expect{}, now)
	if len(out) != 2 {
		t.Fatalf("%d findings for two ownerless devices", len(out))
	}
	for _, f := range out {
		if f.Severity != telemetry.SeverityHigh {
			t.Errorf("%q is %v", f.Title, f.Severity)
		}
		if !strings.Contains(f.Evidence[0].What, "still counted as enrolled") {
			t.Errorf("the evidence does not say why it is invisible: %q",
				f.Evidence[0].What)
		}
	}
}

func TestAbsentFromASystemIsNotTheSameAsFailingItsCheck(t *testing.T) {
	okta := person("okta", "u-1", "jane@acme.test", "Jane Doe")
	kb := person("knowbe4", "k-1", "jane@acme.test", "Jane Doe")
	other := person("okta", "u-2", "sam@acme.test", "Sam Patel")
	r := roster(t, okta, kb, other)
	link(t, r, okta.ID, kb.ID)

	out := r.Findings(Expect{
		In: []string{"knowbe4"},
		Require: []Requirement{{
			Name: "security awareness training", Issuer: "knowbe4",
			Attribute: "training.completed",
			Severity:  telemetry.SeverityMedium,
		}},
	}, now)

	var missing, untrained int
	for _, f := range out {
		switch {
		case strings.Contains(f.Title, "not in knowbe4 at all"):
			missing++
			if !strings.Contains(f.Title, "Sam") {
				t.Errorf("the wrong person is missing: %q", f.Title)
			}
		case strings.Contains(f.Title, "no security awareness training"):
			untrained++
			if !strings.Contains(f.Title, "Jane") {
				t.Errorf("the wrong person is untrained: %q", f.Title)
			}
		}
	}
	if missing != 1 {
		t.Errorf("%d people reported as absent from knowbe4", missing)
	}
	if untrained != 1 {
		t.Errorf("%d people reported as untrained", untrained)
	}
	// Sam is absent from the system entirely and must not also appear as
	// untrained: one person, one queue, one fix.
	for _, f := range out {
		if strings.Contains(f.Title, "Sam") &&
			strings.Contains(f.Title, "training") {
			t.Error("somebody who was never enrolled is in the training " +
				"queue, where the suggested fix is a reminder")
		}
	}
}

func TestAnEmailMatchIsProposedAndNotApplied(t *testing.T) {
	okta := person("okta", "u-1", "Jane.Doe@ACME.test", "Jane Doe")
	kb := person("knowbe4", "k-1", "jane.doe@acme.test", "J Doe")
	r := roster(t, okta, kb)

	props := r.Propose()
	if len(props) != 1 {
		t.Fatalf("%d proposals for one obvious match", len(props))
	}
	if props[0].Doubt == "" {
		t.Error("a proposal with no stated way of being wrong is one " +
			"somebody accepts in a batch of forty without reading")
	}
	// Proposed, not applied. Until somebody confirms it, these are two
	// people, and the report says so.
	if len(r.People()) != 2 {
		t.Fatalf("a proposal joined them on its own: %d people",
			len(r.People()))
	}
	link(t, r, okta.ID, kb.ID)
	if len(r.People()) != 1 {
		t.Fatalf("confirming did not join them: %d people", len(r.People()))
	}
	if len(r.Propose()) != 0 {
		t.Error("the same match is proposed again after being confirmed")
	}
}

// A role mailbox joins everybody who has ever used it into one person, who
// then reports as compliant because at least one of them was.
func TestARoleMailboxIsNeverJoinedOnAndSaysSo(t *testing.T) {
	r := roster(t,
		person("okta", "u-1", "security@acme.test", "Security"),
		person("knowbe4", "k-1", "security@acme.test", "Security Team"),
		person("okta", "u-2", "security+kandji@acme.test", "Security"),
	)
	if props := r.Propose(); len(props) != 0 {
		t.Fatalf("%d proposals on a role mailbox: %+v", len(props), props)
	}
	skipped := r.Skipped()
	if len(skipped) == 0 {
		t.Fatal("nothing said the address was skipped, which looks exactly " +
			"like a join that simply found nothing")
	}
	for _, why := range skipped {
		if !strings.Contains(why, "role mailbox") {
			t.Errorf("the reason is %q", why)
		}
	}
}

func TestAnAmbiguousAddressIsLeftToTheSystemThatOwnsIt(t *testing.T) {
	r := roster(t,
		person("okta", "u-1", "chen@acme.test", "A Chen"),
		person("okta", "u-2", "chen@acme.test", "B Chen"),
		person("knowbe4", "k-1", "chen@acme.test", "Chen"),
	)
	if props := r.Propose(); len(props) != 0 {
		t.Fatalf("%d proposals where one system holds the address twice",
			len(props))
	}
	skipped := r.Skipped()
	if why := skipped["chen@acme.test"]; !strings.Contains(why, "okta") {
		t.Errorf("the reason does not name the system to fix it: %q", why)
	}
}

func TestAnAddressInOneSystemOnlyIsNotAMatch(t *testing.T) {
	r := roster(t, person("okta", "u-1", "solo@acme.test", "Solo"))
	if props := r.Propose(); len(props) != 0 {
		t.Fatalf("%d proposals from one record", len(props))
	}
}

func TestALinkNeedsAnAuthorAReasonAndTwoSystems(t *testing.T) {
	a := telemetry.ID{Issuer: "okta", Value: "u-1"}
	b := telemetry.ID{Issuer: "knowbe4", Value: "k-1"}
	for name, l := range map[string]Link{
		"no author": {A: a, B: b, At: now, Because: "same"},
		"no reason": {A: a, B: b, At: now, By: "rashik"},
		"no time":   {A: a, B: b, By: "rashik", Because: "same"},
		"a model": {A: a, B: b, At: now, By: "assistant",
			Kind: audit.KindAI, Because: "same"},
		"one system": {A: a, B: telemetry.ID{Issuer: "okta", Value: "u-2"},
			At: now, By: "rashik", Because: "same"},
		"itself": {A: a, B: a, At: now, By: "rashik", Because: "same"},
	} {
		if err := l.Validate(); err == nil {
			t.Errorf("a link with %s was accepted", name)
		}
	}
	good := Link{A: a, B: b, At: now, By: "rashik", Kind: audit.KindHuman,
		Because: "confirmed with the person"}
	if err := good.Validate(); err != nil {
		t.Fatalf("a defensible link was refused: %v", err)
	}
	if good.Record().Action != "workforce.linked" {
		t.Errorf("the audit action is %q", good.Record().Action)
	}
}

func TestLinkingSomethingNobodyHasReadIsRefused(t *testing.T) {
	r := roster(t, person("okta", "u-1", "a@acme.test", "A"))
	err := r.Link(Link{
		A:  telemetry.ID{Issuer: "okta", Value: "u-1"},
		B:  telemetry.ID{Issuer: "knowbe4", Value: "k-9"},
		At: now, By: "rashik", Kind: audit.KindHuman, Because: "same",
	})
	if err == nil {
		t.Fatal("a person was joined to a record nobody has read")
	}
}

// A source that does not report the field has told us nothing, and treating
// silence as "gone" quietly stops raising findings about everybody in it.
func TestSilenceAboutActivityIsNotADeparture(t *testing.T) {
	quiet := person("vanta", "v-1", "a@acme.test", "A")
	quiet.Active = nil
	if !quiet.Live() {
		t.Error("a source that says nothing was read as reporting a leaver")
	}
	if quiet.Says(false) {
		t.Error("silence was read as an explicit answer")
	}
	loud := person("okta", "u-1", "a@acme.test", "A")
	loud.Active = no()
	if loud.Live() || !loud.Says(false) {
		t.Error("an explicit no was not read as one")
	}
}

func TestTheNewerObservationWins(t *testing.T) {
	old := person("okta", "u-1", "a@acme.test", "A")
	old.Observed = now.Add(-time.Hour)
	fresh := person("okta", "u-1", "a@acme.test", "A")
	fresh.Active = no()
	r := roster(t, fresh, old)
	people := r.People()
	if gone, _ := people[0].Gone(); !gone {
		t.Fatal("a stale export overwrote a fresher one")
	}
}

func TestAPersonsKeyDoesNotDependOnReadOrder(t *testing.T) {
	a := person("okta", "u-1", "j@acme.test", "Jane")
	b := person("knowbe4", "k-1", "j@acme.test", "Jane")

	one := roster(t, a, b)
	link(t, one, a.ID, b.ID)
	two := roster(t, b, a)
	link(t, two, b.ID, a.ID)

	if one.People()[0].Key != two.People()[0].Key {
		t.Errorf("reading the systems in the other order renamed the "+
			"person: %q then %q", one.People()[0].Key, two.People()[0].Key)
	}
}

func TestCoverageRefusesToSummariseAJoinThatDidNotWork(t *testing.T) {
	// One system is an export, not a reconciliation.
	one := roster(t, person("okta", "u-1", "a@acme.test", "A"))
	c := one.Coverage()
	if c.Trustworthy() {
		t.Error("one system was reported as a reconciliation")
	}
	if !strings.Contains(c.Why(), "not a reconciliation") {
		t.Errorf("the explanation is %q", c.Why())
	}

	// Two systems, and almost nothing joined.
	r := New()
	for n := range 10 {
		if err := r.Observe(person("okta", "u-"+string(rune('a'+n)),
			"", "")); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Observe(person("knowbe4", "k-1", "", "")); err != nil {
		t.Fatal(err)
	}
	c = r.Coverage()
	if c.Trustworthy() {
		t.Fatal("a join where nothing matched was reported as trustworthy")
	}
	if !strings.Contains(c.Why(), "appear in only one system") {
		t.Errorf("the explanation buries it: %q", c.Why())
	}
	if !strings.Contains(c.Why(), "where the problems are") {
		t.Errorf("the explanation does not say why it matters: %q", c.Why())
	}
}

func TestCoverageCountsOnlyTheSystemsThatHoldPeople(t *testing.T) {
	a := person("okta", "u-1", "j@acme.test", "Jane")
	b := person("knowbe4", "k-1", "j@acme.test", "Jane")
	r := roster(t, a, b, device("kandji", "MBP-1", a.ID, now))
	link(t, r, a.ID, b.ID)

	c := r.Coverage()
	if c.People != 1 {
		t.Fatalf("%d people", c.People)
	}
	// An MDM holding nothing but devices is not a system somebody is
	// missing from.
	if c.Complete != 1 {
		t.Errorf("%d complete; the device-only system counted as one "+
			"somebody was absent from", c.Complete)
	}
	if c.Devices != 1 || c.Unowned != 0 {
		t.Errorf("devices %d, unowned %d", c.Devices, c.Unowned)
	}
	if !c.Trustworthy() {
		t.Errorf("a clean join was not trusted: %s", c.Why())
	}
}

func TestADeviceThatStoppedCheckingInIsReported(t *testing.T) {
	a := person("okta", "u-1", "j@acme.test", "Jane")
	r := roster(t, a, device("kandji", "MBP-1", a.ID, now.Add(-90*24*time.Hour)))
	out := r.Findings(Expect{}, now)
	var found bool
	for _, f := range out {
		if strings.Contains(f.Title, "has not checked in") {
			found = true
			if !strings.Contains(f.Evidence[0].What, "last good answer") {
				t.Errorf("the evidence is %q", f.Evidence[0].What)
			}
		}
	}
	if !found {
		t.Fatal("a laptop quiet for three months produced nothing")
	}
}

func TestAnIdentityWithoutAnIssuerOrATimeIsRefused(t *testing.T) {
	for name, i := range map[string]Identity{
		"no issuer": {ID: telemetry.ID{Value: "1043"}, Subject: APerson,
			Observed: now},
		"no observation time": {
			ID: telemetry.ID{Issuer: "okta", Value: "u-1"}, Subject: APerson},
		"no subject": {ID: telemetry.ID{Issuer: "okta", Value: "u-1"},
			Observed: now},
		"owner with no issuer": {
			ID:      telemetry.ID{Issuer: "kandji", Value: "MBP-1"},
			Subject: ADevice, Observed: now,
			Owner: telemetry.ID{Value: "u-1"}},
	} {
		if err := i.Validate(); err == nil {
			t.Errorf("an identity with %s was accepted", name)
		}
	}
}

func TestAServiceAccountIsNotAPersonWithTrainingGaps(t *testing.T) {
	svc := person("okta", "svc-ci", "ci@acme.test", "CI Runner")
	svc.Subject = AService
	human := person("okta", "u-1", "j@acme.test", "Jane")
	r := roster(t, svc, human)

	out := r.Findings(Expect{Device: true}, now)
	for _, f := range out {
		if strings.Contains(f.Title, "CI Runner") {
			t.Errorf("a service account is in the human queue: %q", f.Title)
		}
	}
	// And it is not proposed for joining either.
	if len(r.Propose()) != 0 {
		t.Error("a service account was offered for merging with a person")
	}
}

// Coverage compared a count of records against a count of people, and printed
// "11 of 10 record(s) joined to nothing" and "the -1 the join worked for".
// Arithmetic that can produce a negative is arithmetic over two different
// things.
func TestCoverageNeverComparesRecordsAgainstPeople(t *testing.T) {
	r := New()
	for n := range 10 {
		if err := r.Observe(person("okta", fmt.Sprintf("u-%d", n),
			fmt.Sprintf("p%d@acme.test", n), "")); err != nil {
			t.Fatal(err)
		}
	}
	for n := range 10 {
		if err := r.Observe(person("knowbe4", fmt.Sprintf("k-%d", n),
			fmt.Sprintf("other%d@acme.test", n), "")); err != nil {
			t.Fatal(err)
		}
	}
	// Devices belonging to nobody, which used to be counted into the same
	// number as the people.
	for n := range 5 {
		if err := r.Observe(device("kandji", fmt.Sprintf("MBP-%d", n),
			telemetry.ID{}, now)); err != nil {
			t.Fatal(err)
		}
	}
	c := r.Coverage()
	if c.Orphaned > c.People {
		t.Fatalf("%d orphaned out of %d people", c.Orphaned, c.People)
	}
	why := c.Why()
	if strings.Contains(why, "-") && strings.Contains(why, "the -") {
		t.Fatalf("the explanation contains a negative count: %q", why)
	}
	if c.Unowned != 5 {
		t.Errorf("%d unowned devices, want 5", c.Unowned)
	}
	if c.Trustworthy() {
		t.Error("a join where nothing matched was trusted")
	}
}

// A device belonging to nobody is a different problem from a person the join
// missed, and a coverage figure that folds them together cannot be acted on.
func TestUnownedDevicesAreReportedApartFromUnjoinedPeople(t *testing.T) {
	a := person("okta", "u-1", "j@acme.test", "Jane")
	b := person("knowbe4", "k-1", "j@acme.test", "Jane")
	r := roster(t, a, b)
	link(t, r, a.ID, b.ID)
	for n := range 4 {
		if err := r.Observe(device("kandji", fmt.Sprintf("MBP-%d", n),
			telemetry.ID{}, now)); err != nil {
			t.Fatal(err)
		}
	}
	c := r.Coverage()
	if c.Orphaned != 0 {
		t.Errorf("%d people orphaned; the devices were counted as people",
			c.Orphaned)
	}
	if c.Trustworthy() {
		t.Error("every device belonging to nobody, and the join was trusted")
	}
	if !strings.Contains(c.Why(), "belong to nobody") {
		t.Errorf("the explanation does not name the real problem: %q",
			c.Why())
	}
}

// Go prints 2280h0m0s for three months, which is correct and is not an
// answer to "how long has this laptop been missing".
func TestDurationsAreSaidTheWaySomebodyReadingAQueueWouldSayThem(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Minute:    "30 minutes",
		8 * time.Hour:       "8 hours",
		95 * 24 * time.Hour: "3 months",
		10 * 24 * time.Hour: "10 days",
	} {
		if got := plainly(d); got != want {
			t.Errorf("%s reads %q, want %q", d, got, want)
		}
	}
	a := person("okta", "u-1", "j@acme.test", "Jane")
	r := roster(t, a,
		device("kandji", "MBP-1", a.ID, now.Add(-95*24*time.Hour)))
	for _, f := range r.Findings(Expect{}, now) {
		if strings.Contains(f.Title, "h0m0s") {
			t.Errorf("a finding prints a raw duration: %q", f.Title)
		}
	}
}

// A leaver present in one system is a leaver, not a join failure. Reporting
// them as one puts the finding that matters about them next to a row saying
// the reconciliation did not work.
func TestALeaverIsNotAlsoReportedAsAJoinFailure(t *testing.T) {
	gone := person("okta", "u-9", "dana@acme.test", "Dana Ito")
	gone.Active = no()
	here := person("okta", "u-1", "j@acme.test", "Jane")
	other := person("knowbe4", "k-1", "j@acme.test", "Jane")
	r := roster(t, gone, here, other)
	link(t, r, here.ID, other.ID)

	for _, f := range r.Findings(Expect{}, now) {
		if strings.Contains(f.Title, "Dana Ito") &&
			strings.Contains(f.Title, "appears only in") {
			t.Errorf("a leaver is in the join-failure queue: %q", f.Title)
		}
	}
}
