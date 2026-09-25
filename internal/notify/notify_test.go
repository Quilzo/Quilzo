// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var (
	now  = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	then = now.Add(-30 * 24 * time.Hour)
)

func key(t *testing.T) []byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func audience(t *testing.T) *Audience {
	t.Helper()
	a, err := NewAudience(key(t))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func who(n int) telemetry.ID {
	return telemetry.ID{Issuer: "crm", Value: fmt.Sprintf("cust-%d", n)}
}

func contact(n int) Contact {
	return Contact{
		ID: who(n), Name: "Customer", Channel: Email,
		Address: fmt.Sprintf("c%d@example.test", n),
		Source:  "signed up in the product", Since: then,
	}
}

func breach() Notice {
	n := Notice{
		Kind: Breach, Subject: "Unauthorised access to backup storage",
		Body:         "What happened, what we did, what you should do.",
		Occurred:     now.Add(-96 * time.Hour),
		Aware:        now.Add(-6 * time.Hour),
		Nature:       "a backup bucket was readable; names and email addresses for 12 accounts",
		Contact:      "dpo@example.test, +44 20 7946 0000",
		Consequences: "the addresses may be used for targeted phishing",
		Measures:     "access revoked, credentials rotated, monitoring added",
		Author:       "rashik", Kinded: audit.KindHuman,
		Affected: []telemetry.ID{who(1), who(2)},
	}
	n.ID = Ident(n.Kind, n.Subject, n.Aware)
	return n
}

// The failure this package exists to make impossible: one preference screen
// governing both marketing and breach notification, so that somebody who
// unsubscribed from everything is not told their data leaked.
func TestUnsubscribingFromEverythingDoesNotSilenceABreachNotice(t *testing.T) {
	a := audience(t)
	if _, err := a.Add(contact(1)); err != nil {
		t.Fatal(err)
	}
	ignored, err := a.Object(who(1), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	// The objection is recorded, and the kinds it cannot cover are reported
	// back rather than silently dropped.
	var sawBreach bool
	for _, k := range ignored {
		if k == Breach {
			sawBreach = true
		}
	}
	if !sawBreach {
		t.Error("objecting to everything did not report that a breach " +
			"notice cannot be declined")
	}

	c, _ := a.Find(who(1))
	if c.Objects(Breach) {
		t.Fatal("an objection silenced a breach notice")
	}
	if !c.Objects(Marketing) {
		t.Fatal("the objection did not stop marketing")
	}
	if ok, why := c.MayReceive(Breach); !ok {
		t.Fatalf("a breach notice was withheld: %s", why)
	}
	if ok, _ := c.MayReceive(Marketing); ok {
		t.Fatal("marketing survived an objection")
	}
}

func TestTheLawfulBasisIsAPropertyOfTheKindAndNotASetting(t *testing.T) {
	for kind, want := range map[Kind]Basis{
		Breach: LegalObligation, Incident: Contract,
		Maintenance: Contract, Deprecation: Contract,
		Change: LegitimateInterest, Marketing: Consent,
	} {
		if got := kind.Basis(); got != want {
			t.Errorf("%s rests on %s, want %s", kind, got, want)
		}
	}
	for _, k := range []Kind{Breach, Incident, Maintenance, Deprecation} {
		if k.Objectable() {
			t.Errorf("%s can be declined, and it rests on %s", k, k.Basis())
		}
	}
	for _, k := range []Kind{Change, Marketing} {
		if !k.Objectable() {
			t.Errorf("%s cannot be declined, and it rests on %s", k, k.Basis())
		}
	}
	if !Marketing.NeedsConsent() || Breach.NeedsConsent() {
		t.Error("consent is required for the wrong kinds")
	}
}

func TestABreachNoticeMissingWhatArticle34RequiresIsRefused(t *testing.T) {
	for _, drop := range []struct {
		field string
		blank func(*Notice)
	}{
		{"nature", func(n *Notice) { n.Nature = "" }},
		{"contact point", func(n *Notice) { n.Contact = "" }},
		{"consequences", func(n *Notice) { n.Consequences = "" }},
		{"measures", func(n *Notice) { n.Measures = "" }},
	} {
		n := breach()
		drop.blank(&n)
		err := n.Validate()
		if err == nil {
			t.Errorf("a breach notice with no %s was accepted", drop.field)
			continue
		}
		if !strings.Contains(err.Error(), "Article 34") {
			t.Errorf("the refusal for %s does not cite the article: %v",
				drop.field, err)
		}
	}
	if err := breach().Validate(); err != nil {
		t.Fatalf("a complete breach notice was refused: %v", err)
	}
}

func TestABreachNoticeToEverybodyNeedsTheArticle34SubsectionThreeReason(t *testing.T) {
	n := breach()
	n.Affected = nil
	err := n.Validate()
	if err == nil {
		t.Fatal("a breach notice addressed to the whole list was accepted")
	}
	if !strings.Contains(err.Error(), "34(3)(c)") {
		t.Errorf("the refusal does not name the lawful way to do it: %v", err)
	}

	n.Public = "the affected accounts cannot be identified individually " +
		"from the logs that survive"
	if err := n.Validate(); err != nil {
		t.Fatalf("a recorded public communication was refused: %v", err)
	}
}

func TestOnlyABreachMayClaimAnArticle34Exemption(t *testing.T) {
	n := Notice{
		Kind: Change, Subject: "New export format", Body: "Details.",
		Occurred: now, Aware: now, Author: "rashik", Kinded: audit.KindHuman,
		Mitigated: "the data was encrypted",
	}
	n.ID = Ident(n.Kind, n.Subject, n.Aware)
	if err := n.Validate(); err == nil {
		t.Fatal("a product change claimed a breach exemption")
	}
}

func TestTheSeventyTwoHourClockRunsFromAwarenessAndOnlyForTheRegulator(t *testing.T) {
	n := breach()
	want := n.Aware.Add(AuthorityDeadline)
	if got := n.AuthorityDue(); !got.Equal(want) {
		t.Errorf("the deadline is %s, want 72 hours after awareness", got)
	}
	// Not 72 hours after it happened. Occurred is four days ago; if the clock
	// ran from there the deadline would already have passed on a breach found
	// six hours ago.
	if n.Overdue(now) {
		t.Fatal("a breach discovered six hours ago is already overdue, " +
			"which means the clock is running from the wrong moment")
	}
	if !n.Overdue(n.Aware.Add(AuthorityDeadline + time.Minute)) {
		t.Error("the deadline never passes")
	}

	// And Article 34 has no deadline. Inventing one tells an incident team
	// they have three days to warn people whose credentials are exposed.
	due, why := n.SubjectDue()
	if !due.IsZero() {
		t.Errorf("a deadline was invented for Article 34: %s", due)
	}
	if !strings.Contains(why, "without undue delay") {
		t.Errorf("the explanation does not say what the law says: %q", why)
	}
	if got := n.Undue(now); got != 6*time.Hour {
		t.Errorf("elapsed since awareness is %s, want 6h", got)
	}
}

func TestKnowingAboutSomethingBeforeItHappenedIsRefused(t *testing.T) {
	n := breach()
	n.Aware = n.Occurred.Add(-time.Hour)
	if err := n.Validate(); err == nil {
		t.Fatal("a notice aware of an event before it happened was accepted")
	}
}

func TestAModelMayDraftANoticeAndNotSendOne(t *testing.T) {
	n := breach()
	n.Kinded = audit.KindAI
	err := n.Validate()
	if err == nil {
		t.Fatal("a model sent a notice on the organisation's behalf")
	}
	if !strings.Contains(err.Error(), "a person sends it") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
}

func TestAnErasedContactStaysSuppressedThroughAReimport(t *testing.T) {
	a := audience(t)
	c := contact(1)
	if _, err := a.Add(c); err != nil {
		t.Fatal(err)
	}
	if err := a.Erase(who(1), now); err != nil {
		t.Fatal(err)
	}

	got, _ := a.Find(who(1))
	if got.Address != "" || got.Name != "" {
		t.Error("erasure left identifying data behind")
	}
	if got.Fingerprint == "" {
		t.Fatal("erasure discarded the fingerprint, so a re-import would " +
			"put this person straight back on the list")
	}

	// The CRM syncs the same person back next week under a fresh identifier.
	// Honouring the first request must not produce a second infringement.
	fresh := contact(1)
	fresh.ID = telemetry.ID{Issuer: "crm", Value: "cust-1-reimported"}
	_, err := a.Add(fresh)
	if err == nil {
		t.Fatal("a re-imported address was added after an erasure")
	}
	if !strings.Contains(err.Error(), "21(3)") {
		t.Errorf("the refusal does not cite why: %v", err)
	}
}

func TestTheSuppressionListHoldsNoAddresses(t *testing.T) {
	a := audience(t)
	if err := a.Suppress("someone@example.test", now); err != nil {
		t.Fatal(err)
	}
	for fp := range a.Suppressions() {
		if strings.Contains(fp, "@") || strings.Contains(fp, "example") {
			t.Fatalf("the suppression list contains an address: %q", fp)
		}
	}
	if !a.Suppressed("SOMEONE@Example.Test") {
		t.Error("suppression is case-sensitive, so a different capitalisation " +
			"gets through")
	}
	if a.Suppressed("other@example.test") {
		t.Error("an unrelated address is suppressed")
	}
	// And it is only checkable by somebody holding the key.
	if !a.Matches(a.Fingerprint("someone@example.test"),
		"someone@example.test") {
		t.Error("a fingerprint does not match its own address")
	}
}

func TestTwoAudiencesWithDifferentKeysProduceDifferentFingerprints(t *testing.T) {
	a, b := audience(t), audience(t)
	if a.Fingerprint("x@example.test") == b.Fingerprint("x@example.test") {
		t.Fatal("the fingerprint does not depend on the key, so a stolen " +
			"suppression list is a dictionary attack away from a list of " +
			"addresses")
	}
}

func TestAKeylessAudienceIsRefused(t *testing.T) {
	if _, err := NewAudience(nil); err == nil {
		t.Fatal("an audience with no fingerprinting key was created")
	}
	if _, err := NewAudience(make([]byte, 8)); err == nil {
		t.Fatal("an eight-byte key was accepted")
	}
}

func TestAContactWithoutProvenanceOrAnIssuerIsRefused(t *testing.T) {
	a := audience(t)
	bare := contact(1)
	bare.Source = ""
	if _, err := a.Add(bare); err == nil {
		t.Error("a contact nobody can say where it came from was added")
	}

	noIssuer := contact(2)
	noIssuer.ID = telemetry.ID{Value: "1043"}
	if _, err := a.Add(noIssuer); err == nil {
		t.Error("a contact identified by a bare number was added")
	}

	consentNoWords := contact(3)
	consentNoWords.ConsentAt = now
	if _, err := a.Add(consentNoWords); err == nil {
		t.Error("consent with no record of what was agreed to was accepted")
	}
}

func TestMarketingNeedsConsentAndABreachDoesNot(t *testing.T) {
	a := audience(t)
	if _, err := a.Add(contact(1)); err != nil {
		t.Fatal(err)
	}
	opted := contact(2)
	opted.ConsentAt = then
	opted.ConsentText = "Email me about new features"
	if _, err := a.Add(opted); err != nil {
		t.Fatal(err)
	}
	if a.Reachable(Marketing) != 1 {
		t.Errorf("%d contact(s) reachable for marketing, want the one who "+
			"opted in", a.Reachable(Marketing))
	}
	if a.Reachable(Breach) != 2 {
		t.Errorf("%d contact(s) reachable for a breach notice, want both",
			a.Reachable(Breach))
	}
}

func TestPreparingSendsNothingAndNamesWhoIsNotBeingTold(t *testing.T) {
	a := audience(t)
	for i := 1; i <= 3; i++ {
		if _, err := a.Add(contact(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Erase(who(2), now); err != nil {
		t.Fatal(err)
	}

	n := breach()
	n.Affected = []telemetry.ID{who(1), who(2), who(9)}
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Send) != 1 || p.Send[0].To != who(1) {
		t.Fatalf("would send to %v, want only the reachable affected contact",
			p.Send)
	}
	// Erased, and someone affected who is not on the list at all. Both are
	// unreachable, and for a breach that count is the Article 34(3)(c)
	// conversation rather than a footnote.
	if p.Unreachable != 2 {
		t.Errorf("%d unreachable, want the erased one and the missing one",
			p.Unreachable)
	}
	if len(p.Missing) != 1 || p.Missing[0] != who(9) {
		t.Errorf("missing is %v", p.Missing)
	}
	var sawErased bool
	for _, h := range p.Hold {
		if h.To == who(2) && strings.Contains(h.Why, "34(3)(c)") {
			sawErased = true
		}
	}
	if !sawErased {
		t.Error("the erased contact is not reported as the reason a public " +
			"communication may be needed")
	}
	if !strings.Contains(p.Why(), "cannot be reached") {
		t.Errorf("the summary hides the unreachable count: %q", p.Why())
	}
}

// recorder is a Sender that remembers, and can be told to fail.
type recorder struct {
	sent []Delivery
	fail map[string]bool
}

func (r *recorder) Send(n Notice, d Delivery) error {
	if r.fail[d.To.String()] {
		return fmt.Errorf("mailbox full")
	}
	r.sent = append(r.sent, d)
	return nil
}

func TestEveryDeliveryIsAddressedToExactlyOnePerson(t *testing.T) {
	a := audience(t)
	for i := 1; i <= 4; i++ {
		if _, err := a.Add(contact(i)); err != nil {
			t.Fatal(err)
		}
	}
	n := breach()
	n.Affected = []telemetry.ID{who(1), who(2), who(3), who(4)}
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	out, err := Deliver(n, p, NewOutbox(), r, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Sent) != 4 || len(r.sent) != 4 {
		t.Fatalf("sent %d deliveries for 4 people", len(r.sent))
	}
	seen := map[string]bool{}
	for _, d := range r.sent {
		if strings.ContainsAny(d.Address, ",;") {
			t.Errorf("a delivery carries more than one address: %q",
				d.Address)
		}
		if seen[d.Address] {
			t.Errorf("%s was written to twice", d.Address)
		}
		seen[d.Address] = true
	}
}

func TestARetryAfterACrashTellsNobodyTwice(t *testing.T) {
	a := audience(t)
	for i := 1; i <= 2; i++ {
		if _, err := a.Add(contact(i)); err != nil {
			t.Fatal(err)
		}
	}
	n := breach()
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	box := NewOutbox()
	r := &recorder{}
	if _, err := Deliver(n, p, box, r, now); err != nil {
		t.Fatal(err)
	}
	first := len(r.sent)

	// The process restarts and the operator, not knowing how far it got,
	// runs it again. Telling somebody twice that their data has leaked is a
	// second shock, not a duplicate email.
	again := NewOutbox()
	again.Load(box.Done())
	out, err := Deliver(n, p, again, r, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.sent) != first {
		t.Fatalf("%d extra delivery(s) on the retry", len(r.sent)-first)
	}
	if len(out.Skipped) != first {
		t.Errorf("%d skipped, want %d", len(out.Skipped), first)
	}
}

func TestOneBadAddressDoesNotStopEverybodyElseBeingTold(t *testing.T) {
	a := audience(t)
	for i := 1; i <= 3; i++ {
		if _, err := a.Add(contact(i)); err != nil {
			t.Fatal(err)
		}
	}
	n := breach()
	n.Affected = []telemetry.ID{who(1), who(2), who(3)}
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{fail: map[string]bool{who(2).String(): true}}
	out, err := Deliver(n, p, NewOutbox(), r, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Sent) != 2 {
		t.Errorf("%d sent; one stale mailbox became a failure to notify "+
			"everybody else", len(out.Sent))
	}
	if len(out.Failed) != 1 {
		t.Fatalf("%d failures recorded", len(out.Failed))
	}
	if !strings.Contains(out.Summary(), "failed") {
		t.Errorf("the summary hides the failure: %q", out.Summary())
	}
}

func TestAFailedDeliveryIsNotRecordedAsSent(t *testing.T) {
	a := audience(t)
	if _, err := a.Add(contact(1)); err != nil {
		t.Fatal(err)
	}
	n := breach()
	n.Affected = []telemetry.ID{who(1)}
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	box := NewOutbox()
	r := &recorder{fail: map[string]bool{who(1).String(): true}}
	if _, err := Deliver(n, p, box, r, now); err != nil {
		t.Fatal(err)
	}
	if len(box.Done()) != 0 {
		t.Fatal("a delivery that failed was recorded as sent, so the retry " +
			"will skip somebody who was never told")
	}
	// And the retry, with a working mailbox, reaches them.
	r.fail = nil
	out, err := Deliver(n, p, box, r, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Sent) != 1 {
		t.Error("the retry did not reach the person who was never told")
	}
}

func TestAPlanNobodyMadeIsRefused(t *testing.T) {
	n := breach()
	_, err := Deliver(n, Plan{Notice: n.ID}, NewOutbox(), &recorder{}, now)
	if err == nil {
		t.Fatal("a hand-made plan was delivered without anybody seeing it")
	}
}

func TestAPlanForADifferentNoticeIsRefused(t *testing.T) {
	a := audience(t)
	if _, err := a.Add(contact(1)); err != nil {
		t.Fatal(err)
	}
	n := breach()
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	other := n
	other.Subject = "A different breach entirely"
	other.ID = Ident(other.Kind, other.Subject, other.Aware)
	if _, err := Deliver(other, p, NewOutbox(), &recorder{}, now); err == nil {
		t.Fatal("one notice was sent under another's approved plan")
	}
}

func TestTheRecordOfABreachHoldsNoAddressesOrNames(t *testing.T) {
	a := audience(t)
	if _, err := a.Add(contact(1)); err != nil {
		t.Fatal(err)
	}
	n := breach()
	n.Affected = []telemetry.ID{who(1)}
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}

	rec := n.Record(len(p.Send), len(p.Hold))
	if rec.Action != "notice.breach" {
		t.Errorf("action is %q", rec.Action)
	}
	// Article 33(5): the facts, the effects, the remedial action.
	for _, want := range []string{"nature", "consequences", "measures",
		"aware", "occurred", "authority_due"} {
		if rec.Detail[want] == "" {
			t.Errorf("the Article 33(5) record has no %s", want)
		}
	}
	dRec := p.Send[0].Record(n, "rashik", audit.KindHuman)
	for k, v := range dRec.Detail {
		if strings.Contains(v, "@") {
			t.Errorf("the delivery record holds an address in %q: %q", k, v)
		}
		if strings.Contains(strings.ToLower(v), "customer") {
			t.Errorf("the delivery record holds a name in %q: %q", k, v)
		}
	}
	if dRec.Detail["contact"] == "" {
		t.Error("the delivery record cannot show that anybody was told")
	}
}

// The audit log refuses a detail key that looks like a credential, and
// refuses the whole record rather than the key. A carelessly named field here
// would mean the notice goes out and nothing records it, which is the
// Article 33(5) documentation failing silently.
func TestEveryNoticeKindReachesARealAuditLog(t *testing.T) {
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{
		Path: dir + "/audit.jsonl", Key: k, Source: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range Kinds() {
		n := breach()
		n.Kind = kind
		if kind != Breach {
			n.Mitigated, n.Public = "", ""
		}
		n.ID = Ident(kind, n.Subject, n.Aware)
		if _, err := log.Append(n.Record(3, 1)); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		d := Delivery{Key: "k", Notice: n.ID, To: who(1), Channel: Email,
			Fingerprint: "c_abc"}
		if _, err := log.Append(d.Record(n, "rashik", audit.KindHuman)); err != nil {
			t.Fatalf("%s delivery: %v", kind, err)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Kinds())*2 {
		t.Fatalf("%d entries for %d kinds", len(events), len(Kinds()))
	}
}

func TestAnInAppContactNeedsNoAddress(t *testing.T) {
	a := audience(t)
	c := Contact{ID: who(1), Channel: InApp,
		Source: "signed up in the product", Since: then}
	if _, err := a.Add(c); err != nil {
		t.Fatalf("an in-app contact was refused: %v", err)
	}
	if ok, why := c.MayReceive(Incident); !ok {
		t.Errorf("an in-app contact cannot be told about an incident: %s", why)
	}
	// And there is still something to put in the record.
	d := Delivery{Notice: "n", To: who(1), Channel: InApp}
	if h := d.Record(breach(), "rashik", audit.KindHuman).
		Detail["contact"]; !strings.HasPrefix(h, "c_") {
		t.Errorf("the record handle is %q", h)
	}
}

func TestAContactIsNotToldTwiceBecauseTheCrmListedThemTwice(t *testing.T) {
	a := audience(t)
	c := contact(1)
	if _, err := a.Add(c); err != nil {
		t.Fatal(err)
	}
	n := breach()
	n.Affected = []telemetry.ID{who(1), who(1), who(2)}
	p, err := Prepare(n, a, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Send) != 1 {
		t.Fatalf("%d deliveries for one person listed twice", len(p.Send))
	}
}

// An in-app contact has no address, so fingerprinting only addresses left
// nothing behind on erasure and the re-import this mechanism exists to refuse
// went straight through.
func TestAnErasedInAppContactIsStillSuppressed(t *testing.T) {
	a := audience(t)
	c := Contact{ID: who(1), Channel: InApp,
		Source: "signed up in the product", Since: then}
	if _, err := a.Add(c); err != nil {
		t.Fatal(err)
	}
	if err := a.Erase(who(1), now); err != nil {
		t.Fatal(err)
	}
	got, _ := a.Find(who(1))
	if got.Fingerprint == "" {
		t.Fatal("an erased in-app contact left nothing to suppress")
	}
	// The CRM re-imports the same account under a new customer number. The
	// account is the same account, and that is what the fingerprint holds.
	again := c
	again.ID = telemetry.ID{Issuer: "crm", Value: "cust-1-reimported"}
	if _, err := a.Add(again); err != nil {
		t.Fatalf("a re-import under a different id was refused, and it is a "+
			"different account: %v", err)
	}
	// Re-adding the same account, however, is not.
	revived := c
	if _, err := a.Add(revived); err == nil {
		t.Fatal("the erased account was put straight back on the list")
	}
}

// The reason an erased contact is skipped should not advise a public
// communication about a newsletter.
func TestTheReasonForWithholdingFitsTheKindOfNotice(t *testing.T) {
	a := audience(t)
	if _, err := a.Add(contact(1)); err != nil {
		t.Fatal(err)
	}
	if err := a.Erase(who(1), now); err != nil {
		t.Fatal(err)
	}
	c, _ := a.Find(who(1))
	_, breachWhy := c.MayReceive(Breach)
	if !strings.Contains(breachWhy, "34(3)(c)") {
		t.Errorf("a breach does not mention the public-communication "+
			"route: %q", breachWhy)
	}
	_, marketingWhy := c.MayReceive(Marketing)
	if strings.Contains(marketingWhy, "34(3)(c)") {
		t.Errorf("a marketing plan advises a public breach communication: %q",
			marketingWhy)
	}
}
