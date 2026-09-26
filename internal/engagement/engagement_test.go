// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package engagement

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
)

var (
	now    = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	period = assurance.Period{From: now.Add(-182 * 24 * time.Hour), To: now}
)

func day(n int) time.Time {
	return period.From.Add(time.Duration(n) * 24 * time.Hour)
}

func engaged() Engagement {
	return Engagement{
		ID: "soc2-2026", Firm: "Mendel & Co", Auditor: "j.mendel",
		Scope: "acme-us", Period: period, Frameworks: []string{"SOC2"},
		Opened: now.Add(-7 * 24 * time.Hour),
		Until:  now.Add(90 * 24 * time.Hour),
		By:     "rashik", Kind: audit.KindHuman,
		Because: "SOC 2 Type II for the American company, FY26",
	}
}

func control(id, entity string) assurance.Control {
	return assurance.Control{ID: id, Name: id,
		Cadence: assurance.Continuous, Owner: "rashik", Entity: entity}
}

func ev(control, entity, ref string, from, to int) assurance.Evidence {
	return assurance.Evidence{
		Control: control, Entity: entity, From: day(from), To: day(to),
		Outcome: assurance.Operated, What: "an export", Source: "connector",
		Ref: ref, At: day(to), By: "rashik", Kind: audit.KindHuman,
	}
}

// signer wraps a real HeadSigner. Real keys, real signatures: the point of
// the exercise is that an auditor can check these, and a fake signature
// proves nothing about whether they can.
type signer struct{ s *audit.HeadSigner }

func (s signer) Sign(h audit.Head) (audit.SignedHead, error) {
	return s.s.Sign(h)
}

func keys(t *testing.T) (*audit.HeadSigner, *audit.HeadVerifier) {
	t.Helper()
	ed, ml, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	s, err := audit.NewHeadSigner(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.Verifier()
}

// logged writes evidence into a real audit log and hands back the events.
func logged(t *testing.T, in []assurance.Evidence) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Key: k,
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	// Some unrelated traffic, so the tree is not only this evidence and the
	// proofs have something to prove.
	for range 3 {
		if _, aerr := log.Append(audit.Record{Action: "content.add",
			Resource: "/", Outcome: audit.Success, Principal: "rashik",
			Kind: audit.KindHuman}); aerr != nil {
			t.Fatal(aerr)
		}
	}
	for _, e := range in {
		if verr := e.Validate(); verr != nil {
			t.Fatalf("%s: %v", e.Ref, verr)
		}
		if _, aerr := log.Append(e.Record()); aerr != nil {
			t.Fatal(aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func inUS(entity string) bool { return entity == "acme-us" || entity == "" }

// The whole point: a package an auditor checks on their own machine, with a
// published key and nothing from this organisation.
func TestAPackageVerifiesWithNothingButTheKey(t *testing.T) {
	s, v := keys(t)
	controls := []assurance.Control{control("mfa", "acme-us"),
		control("backups", "acme-us")}
	evidence := []assurance.Evidence{
		ev("mfa", "acme-us", "audit:mfa-1", 0, 91),
		ev("mfa", "acme-us", "audit:mfa-2", 91, 182),
		ev("backups", "acme-us", "audit:bk-1", 0, 182),
	}
	events := logged(t, evidence)

	p, err := Build(engaged(), controls, evidence, events, inUS, signer{s},
		now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 3 {
		t.Fatalf("%d items", p.Count())
	}
	if err := p.Verify(v); err != nil {
		t.Fatalf("a package built here does not verify: %v", err)
	}
	// And the head is genuinely signed twice, which is the argument.
	if p.Head.Ed25519 == "" || p.Head.MLDSA == "" {
		t.Error("the head carries half its signatures")
	}
	if p.Head.Root == "" || p.Head.Size < 6 {
		t.Errorf("the head commits to %d entries", p.Head.Size)
	}
}

func TestAPackageWithNoKeyIsNotVerified(t *testing.T) {
	s, _ := keys(t)
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	p, err := Build(engaged(), []assurance.Control{control("mfa", "acme-us")},
		evidence, logged(t, evidence), inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Verify(nil)
	if err == nil {
		t.Fatal("a package verified with no key at all")
	}
	if !strings.Contains(err.Error(), "the audited party wrote") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// Somebody else's signature is not this organisation's signature.
func TestAHeadSignedByAnotherKeyIsRefused(t *testing.T) {
	mine, _ := keys(t)
	_, theirs := keys(t)
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	p, err := Build(engaged(), []assurance.Control{control("mfa", "acme-us")},
		evidence, logged(t, evidence), inUS, signer{mine}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(theirs); err == nil {
		t.Fatal("a package verified against a key that did not sign it")
	}
}

// A proof is about one entry being in the log. It says nothing about whether
// the evidence attached to it is the evidence that entry recorded.
func TestARealProofAttachedToTheWrongEvidenceIsCaught(t *testing.T) {
	s, v := keys(t)
	controls := []assurance.Control{control("mfa", "acme-us")}
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	p, err := Build(engaged(), controls, evidence, logged(t, evidence),
		inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(v); err != nil {
		t.Fatal(err)
	}

	// The evidence is swapped for something that says more than the entry
	// recorded. The proof still resolves; the fields no longer agree.
	p.Items[0].Evidence.Source = "a person who says so"
	err = p.Verify(v)
	if err == nil {
		t.Fatal("a real proof attached to different evidence verified")
	}
	if !strings.Contains(err.Error(), "attached to a different act") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}

	// And a widened period is caught too, which is the version somebody
	// would actually try.
	p.Items[0].Evidence.Source = "connector"
	p.Items[0].Evidence.To = p.Items[0].Evidence.To.Add(30 * 24 * time.Hour)
	if err := p.Verify(v); err == nil {
		t.Fatal("evidence stretched past what the log recorded verified")
	}
}

func TestAnAlteredEntryFailsTheProof(t *testing.T) {
	s, v := keys(t)
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	p, err := Build(engaged(), []assurance.Control{control("mfa", "acme-us")},
		evidence, logged(t, evidence), inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	// Rewriting history. The entry is changed to say the control passed on a
	// different date; the leaf hash moves and the proof stops resolving.
	p.Items[0].Entry.Detail["ref"] = "audit:something-else"
	p.Items[0].Evidence.Ref = "audit:something-else"
	if err := p.Verify(v); err == nil {
		t.Fatal("a rewritten entry verified against the signed head")
	}
}

// A SOC 2 for the American company does not carry the German company's
// evidence.
func TestAPackageNeverCarriesAnotherCompanysEvidence(t *testing.T) {
	s, _ := keys(t)
	controls := []assurance.Control{control("mfa", "acme-us"),
		control("mfa-de", "acme-de")}
	evidence := []assurance.Evidence{
		ev("mfa", "acme-us", "audit:us", 0, 182),
		ev("mfa-de", "acme-de", "audit:de", 0, 182),
	}
	p, err := Build(engaged(), controls, evidence, logged(t, evidence),
		inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 1 {
		t.Fatalf("%d items; the other company's evidence is in the package",
			p.Count())
	}
	for _, c := range p.Controls {
		if c.Entity == "acme-de" {
			t.Error("another company's control is in the package")
		}
	}
	if out := p.Outside(inUS); len(out) != 0 {
		t.Errorf("the package carries %v", out)
	}
	// And the check catches one that does, whatever built it.
	p.Items = append(p.Items, Item{Evidence: evidence[1]})
	if out := p.Outside(inUS); len(out) != 1 {
		t.Errorf("a package carrying acme-de evidence reported %v", out)
	}
}

func TestEvidenceOutsideThePeriodIsNotInThePackage(t *testing.T) {
	s, _ := keys(t)
	controls := []assurance.Control{control("mfa", "acme-us")}
	old := ev("mfa", "acme-us", "audit:old", -400, -380)
	evidence := []assurance.Evidence{old,
		ev("mfa", "acme-us", "audit:now", 0, 182)}
	p, err := Build(engaged(), controls, evidence, logged(t, evidence),
		inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 1 || p.Items[0].Evidence.Ref != "audit:now" {
		t.Fatalf("the package carries %d items", p.Count())
	}
}

// A package whose completeness depends on this program is a package with no
// argument behind it.
func TestControlsWithNothingAreNamedRatherThanOmitted(t *testing.T) {
	s, _ := keys(t)
	controls := []assurance.Control{control("mfa", "acme-us"),
		control("pentest", "acme-us")}
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	p, err := Build(engaged(), controls, evidence, logged(t, evidence),
		inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Unevidenced) != 1 || p.Unevidenced[0] != "pentest" {
		t.Fatalf("unevidenced is %v", p.Unevidenced)
	}
	if !strings.Contains(p.Note, "named here rather than omitted") {
		t.Errorf("the note does not say so: %q", p.Note)
	}
	if len(p.Controls) != 2 {
		t.Error("a control with nothing behind it was left out entirely")
	}
}

// Either it was added outside the recorded path or the log has lost it, and
// both are things an auditor should be told.
func TestEvidenceWithNoAuditEntryStopsTheBuild(t *testing.T) {
	s, _ := keys(t)
	controls := []assurance.Control{control("mfa", "acme-us")}
	recorded := ev("mfa", "acme-us", "audit:1", 0, 91)
	unrecorded := ev("mfa", "acme-us", "audit:2", 91, 182)
	// Only the first goes into the log.
	events := logged(t, []assurance.Evidence{recorded})

	_, err := Build(engaged(), controls,
		[]assurance.Evidence{recorded, unrecorded}, events, inUS,
		signer{s}, now)
	if err == nil {
		t.Fatal("a package was built with evidence that nothing recorded")
	}
	if !strings.Contains(err.Error(), "audit:2") {
		t.Errorf("the error does not name it: %v", err)
	}
	if !strings.Contains(err.Error(), "completeness depends on this program") {
		t.Errorf("the error does not say why it matters: %v", err)
	}
}

func TestAClosedEngagementIssuesNothing(t *testing.T) {
	s, _ := keys(t)
	e := engaged()
	e.Until = now.Add(-24 * time.Hour)
	e.Opened = now.Add(-200 * 24 * time.Hour)
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	_, err := Build(e, []assurance.Control{control("mfa", "acme-us")},
		evidence, logged(t, evidence), inUS, signer{s}, now)
	if err == nil {
		t.Fatal("a closed engagement issued a package")
	}
	if !strings.Contains(err.Error(), "nobody agreed to") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if e.Open(now) {
		t.Error("a closed engagement reports itself open")
	}
}

func TestAnUnsignedPackageIsRefused(t *testing.T) {
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	_, err := Build(engaged(), []assurance.Control{control("mfa", "acme-us")},
		evidence, logged(t, evidence), inUS, nil, now)
	if err == nil {
		t.Fatal("a package was built with no signer")
	}
	if !strings.Contains(err.Error(), "folder of files") {
		t.Errorf("the refusal does not say what it would be: %v", err)
	}
}

// The complaint about auditor access in every one of these products is the
// access nobody revoked.
func TestAnEngagementThatNeverEndsIsRefused(t *testing.T) {
	good := engaged()
	for name, spoil := range map[string]func(*Engagement){
		"no end":      func(e *Engagement) { e.Until = time.Time{} },
		"no scope":    func(e *Engagement) { e.Scope = "" },
		"no person":   func(e *Engagement) { e.Auditor = "" },
		"no firm":     func(e *Engagement) { e.Firm = "" },
		"no reason":   func(e *Engagement) { e.Because = "" },
		"nobody":      func(e *Engagement) { e.By = "" },
		"a model":     func(e *Engagement) { e.Kind = audit.KindAI },
		"no period":   func(e *Engagement) { e.Period = assurance.Period{} },
		"backwards":   func(e *Engagement) { e.Until = e.Opened.Add(-time.Hour) },
		"three years": func(e *Engagement) { e.Until = e.Opened.Add(3 * 365 * 24 * time.Hour) },
	} {
		e := good
		spoil(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("an engagement with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary engagement was refused: %v", err)
	}
	if err := (Engagement{ID: "x", Firm: "f", Scope: "s", Period: period,
		Opened: now, Until: now.Add(time.Hour), By: "a",
		Because: "b"}).Validate(); err == nil {
		t.Error("an engagement naming a firm and no person was accepted")
	} else if !strings.Contains(err.Error(), "who looked") {
		t.Errorf("the refusal does not say why both are needed: %v", err)
	}
}

func TestIssuingIsRecorded(t *testing.T) {
	a := Access{Engagement: "soc2-2026", At: now, Head: "abc123",
		Items: 12, By: "rashik"}
	r := a.Record()
	if r.Action != "engagement.issued" {
		t.Errorf("the action is %q", r.Action)
	}
	if r.Detail["head"] != "abc123" || r.Detail["items"] != "12" {
		t.Errorf("the record is %v", r.Detail)
	}
	// The head identifies the package exactly, so two firms holding two
	// packages can be shown to hold the same one.
	if r.Detail["engagement"] != "soc2-2026" {
		t.Error("the record does not name the engagement")
	}
}

func TestTheNoteSaysWhatIsAndIsNotProved(t *testing.T) {
	s, _ := keys(t)
	evidence := []assurance.Evidence{ev("mfa", "acme-us", "audit:1", 0, 182)}
	p, err := Build(engaged(), []assurance.Control{control("mfa", "acme-us")},
		evidence, logged(t, evidence), inUS, signer{s}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"needs the published key and nothing from this organisation",
		"What it does not prove: that the log is complete",
		"no cryptography fixes that",
	} {
		if !strings.Contains(p.Note, want) {
			t.Errorf("the note does not say %q:\n%s", want, p.Note)
		}
	}
}
