// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package attest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)

func claim(id, says string, a Answer, backing ...string) Claim {
	c := Claim{
		ID: id, Says: says, Answer: a, Backing: backing,
		At: now.Add(-30 * 24 * time.Hour), By: "rashik",
		Kind: audit.KindHuman, Until: now.Add(300 * 24 * time.Hour),
	}
	if a == Partly {
		c.Detail = "everywhere except the two tools not behind SSO"
	}
	return c
}

func library(t *testing.T, claims ...Claim) *Library {
	t.Helper()
	l := NewLibrary()
	for _, c := range claims {
		if err := l.Add(c); err != nil {
			t.Fatalf("add %s: %v", c.ID, err)
		}
	}
	return l
}

func caiq(pairs ...[2]string) Questionnaire {
	q := Questionnaire{Name: "CAIQ v4.0.2", From: "Northwind Ltd"}
	for _, p := range pairs {
		q.Questions = append(q.Questions, Question{
			ID: p[0], Text: "does your organisation do the thing",
			Claim: p[1],
		})
	}
	return q
}

func open(entity, title string) finding.Finding {
	issuer, value, _ := strings.Cut(entity, ":")
	f := finding.Finding{
		Kind: finding.FromControl, Title: title, Source: "assurance",
		Entity:   telemetry.ID{Issuer: issuer, Value: value},
		Severity: telemetry.SeverityHigh, State: finding.Open, Seen: 1,
		First: now.Add(-10 * 24 * time.Hour), Last: now,
	}
	f.ID = finding.Key(f.Kind, f.Source, f.Entity)
	return f
}

// The feature. Every product scores an answer against the text of previous
// answers, which measures consistency rather than truth: a confident answer
// about a control that stopped working in March matches what was said last
// time, and last time is exactly what is now false.
func TestAnAnswerTheRegisterContradictsStopsTheQuestionnaire(t *testing.T) {
	l := library(t,
		claim("mfa", "MFA is enforced for all staff", Yes, "control:mfa"),
		claim("backups", "backups are taken nightly and restores tested",
			Yes, "control:backups"),
	)
	q := caiq([2]string{"IAM-03", "mfa"}, [2]string{"BCR-08", "backups"})

	// Nothing wrong yet.
	clean, err := Fill(q, l, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if !clean.Sendable() {
		t.Fatalf("a clean questionnaire was blocked: %v", clean.Concerns)
	}
	if !strings.Contains(clean.Why(), "nothing in the register contradicts") {
		t.Errorf("the summary is %q", clean.Why())
	}

	// The MFA control stopped operating in March, and the register says so.
	register := []finding.Finding{
		open("control:mfa", "mfa has 60 day(s) with nothing to show"),
	}
	blocked, err := Fill(q, l, register, now)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Sendable() {
		t.Fatal("a questionnaire contradicted by the register was sendable")
	}
	b := blocked.Blocking()
	if len(b) != 1 || b[0].Question != "IAM-03" {
		t.Fatalf("blocking is %v", b)
	}
	if !strings.Contains(b[0].What, "nothing to show") {
		t.Errorf("the concern does not quote the finding: %q", b[0].What)
	}
	if b[0].Finding == "" {
		t.Error("the concern does not name the register entry")
	}
	if !strings.Contains(blocked.Why(), "cannot be supported") {
		t.Errorf("the summary does not say why it is blocked: %q",
			blocked.Why())
	}
	// The other answer is untouched: one bad claim does not stop the rest
	// being answered, it stops the file going out.
	if blocked.Answered() != 2 {
		t.Errorf("%d answered", blocked.Answered())
	}
}

// A finding saying a control is broken does not contradict somebody having
// said the control is not in place.
func TestSayingNoIsNeverContradicted(t *testing.T) {
	l := library(t,
		claim("fedramp", "we do not hold a FedRAMP authorisation", No),
		claim("hsm", "we do not use a hardware security module", No),
	)
	q := caiq([2]string{"GRC-01", "fedramp"}, [2]string{"CEK-05", "hsm"})
	f, err := Fill(q, l, []finding.Finding{
		open("control:fedramp", "no evidence at all"),
		open("control:hsm", "no evidence at all"),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Sendable() {
		t.Fatalf("answering no was contradicted: %v", f.Blocking())
	}
}

func TestPartlyIsCheckedLikeAYes(t *testing.T) {
	l := library(t, claim("sso", "SSO is enforced on our SaaS estate",
		Partly, "control:sso"))
	q := caiq([2]string{"IAM-09", "sso"})
	f, err := Fill(q, l, []finding.Finding{
		open("control:sso", "sso has gaps in three companies"),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Sendable() {
		t.Fatal("a hedged answer escaped the check")
	}
}

// A generated answer here would be the model's reading of the question
// rather than this organisation's position.
func TestAnUnmappedQuestionIsLeftBlankRatherThanGuessed(t *testing.T) {
	l := library(t, claim("mfa", "MFA is enforced", Yes, "control:mfa"))
	q := caiq([2]string{"IAM-03", "mfa"}, [2]string{"AIS-07", ""})
	f, err := Fill(q, l, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Answered() != 1 {
		t.Fatalf("%d answered, want only the mapped one", f.Answered())
	}
	var unmapped bool
	for _, c := range f.Concerns {
		if c.Trouble == Unmapped && c.Question == "AIS-07" {
			unmapped = true
			if !strings.Contains(c.What, "left blank") {
				t.Errorf("the concern is %q", c.What)
			}
		}
	}
	if !unmapped {
		t.Error("the unmapped question was not reported")
	}
	// Unmapped does not stop the file: it is honest, not wrong.
	if !f.Sendable() {
		t.Error("a blank answer blocked the questionnaire")
	}
	if !strings.Contains(f.Why(), "left blank rather than guessed at") {
		t.Errorf("the summary is %q", f.Why())
	}
}

func TestAQuestionMappedToAClaimNobodyHoldsIsReported(t *testing.T) {
	l := library(t, claim("mfa", "MFA is enforced", Yes, "control:mfa"))
	q := caiq([2]string{"IAM-03", "sso-everywhere"})
	f, err := Fill(q, l, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Answered() != 0 {
		t.Error("a missing claim produced an answer")
	}
	if len(f.Concerns) != 1 || f.Concerns[0].Trouble != Missing {
		t.Fatalf("concerns are %v", f.Concerns)
	}
}

// An answer library with no expiry is a library of last year's answers.
func TestAClaimPastItsReviewDateIsReported(t *testing.T) {
	old := claim("mfa", "MFA is enforced", Yes, "control:mfa")
	old.At = now.Add(-400 * 24 * time.Hour)
	old.Until = now.Add(-35 * 24 * time.Hour)
	l := library(t, old)
	q := caiq([2]string{"IAM-03", "mfa"})

	f, err := Fill(q, l, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	var stale bool
	for _, c := range f.Concerns {
		if c.Trouble == Stale {
			stale = true
			if !strings.Contains(c.What, "still being sent") {
				t.Errorf("the concern is %q", c.What)
			}
		}
	}
	if !stale {
		t.Fatal("a claim a month past its review date was not reported")
	}
	// Stale is a warning about the process rather than a contradiction, so
	// it does not stop the file.
	if !f.Sendable() {
		t.Error("a stale answer blocked the questionnaire")
	}
	// And it is a finding, because it is a thing about this organisation
	// that somebody has to do.
	out := Findings(l, []Filled{f}, now)
	var found bool
	for _, item := range out {
		if strings.Contains(item.Title, "due for review") {
			found = true
		}
	}
	if !found {
		t.Error("a stale claim is not in the register")
	}
}

// A claim with nothing behind it is the one that gets read out in a
// deposition, and it is also the one nothing can check.
func TestAnAffirmativeClaimWithNoBackingIsRefused(t *testing.T) {
	bare := Claim{ID: "mfa", Says: "MFA is enforced", Answer: Yes,
		At: now, By: "rashik", Kind: audit.KindHuman,
		Until: now.Add(90 * 24 * time.Hour)}
	err := bare.Validate()
	if err == nil {
		t.Fatal("a yes with nothing behind it was accepted")
	}
	if !strings.Contains(err.Error(), "nothing can check") {
		t.Errorf("the refusal does not say the second reason: %v", err)
	}

	// Saying no needs no backing: there is nothing to support.
	no := bare
	no.Answer, no.Says = No, "we do not do this"
	if err := no.Validate(); err != nil {
		t.Fatalf("a plain no was refused: %v", err)
	}
}

func TestPartlyWithNoDetailIsAYesWearingAHedge(t *testing.T) {
	c := claim("sso", "SSO is enforced", Partly, "control:sso")
	c.Detail = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("partly with no detail was accepted")
	}
	if !strings.Contains(err.Error(), "wearing a hedge") {
		t.Errorf("the refusal is %v", err)
	}
}

func TestAModelMayDraftAnAnswerAndNotSignOne(t *testing.T) {
	c := claim("mfa", "MFA is enforced", Yes, "control:mfa")
	c.Kind = audit.KindAI
	err := c.Validate()
	if err == nil {
		t.Fatal("a model signed a representation made to a customer")
	}
	if !strings.Contains(err.Error(), "a person makes it") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
}

func TestAClaimThatNeverGoesStaleIsRefused(t *testing.T) {
	good := claim("mfa", "MFA is enforced", Yes, "control:mfa")
	for name, spoil := range map[string]func(*Claim){
		"no expiry":     func(c *Claim) { c.Until = time.Time{} },
		"expired first": func(c *Claim) { c.Until = c.At.Add(-time.Hour) },
		"three years": func(c *Claim) {
			c.Until = c.At.Add(3 * 365 * 24 * time.Hour)
		},
		"nobody":       func(c *Claim) { c.By = "" },
		"no assertion": func(c *Claim) { c.Says = "" },
		"no answer":    func(c *Claim) { c.Answer = "" },
		"backing with no kind": func(c *Claim) {
			c.Backing = []string{"mfa"}
		},
	} {
		c := good
		spoil(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("a claim with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary claim was refused: %v", err)
	}
}

func TestAQuestionnaireThatCannotBeReviewedIsRefused(t *testing.T) {
	for name, q := range map[string]Questionnaire{
		"no name":  {From: "Northwind", Questions: []Question{{ID: "a", Text: "t"}}},
		"no asker": {Name: "CAIQ", Questions: []Question{{ID: "a", Text: "t"}}},
		"nothing":  {Name: "CAIQ", From: "Northwind"},
		"no text":  {Name: "CAIQ", From: "Northwind", Questions: []Question{{ID: "a"}}},
		"no ref":   {Name: "CAIQ", From: "Northwind", Questions: []Question{{Text: "t"}}},
		"asked twice": {Name: "CAIQ", From: "Northwind", Questions: []Question{
			{ID: "a", Text: "t"}, {ID: "a", Text: "t"}}},
	} {
		if err := q.Validate(); err == nil {
			t.Errorf("a questionnaire with %s was accepted", name)
		}
	}
}

// A finding somebody has fixed does not contradict anything.
func TestAClosedFindingDoesNotBlock(t *testing.T) {
	l := library(t, claim("mfa", "MFA is enforced", Yes, "control:mfa"))
	q := caiq([2]string{"IAM-03", "mfa"})
	fixed := open("control:mfa", "mfa had gaps")
	fixed.State = finding.Fixed
	f, err := Fill(q, l, []finding.Finding{fixed}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Sendable() {
		t.Fatalf("a fixed finding blocked a questionnaire: %v", f.Blocking())
	}
}

// The useful number is not how many answers were generated. It is how many
// questions this organisation has decided its position on.
func TestCoverageIsWhatWeHaveDecidedNotWhatCouldBeGenerated(t *testing.T) {
	l := library(t, claim("mfa", "MFA is enforced", Yes, "control:mfa"))
	var pairs [][2]string
	for n := range 20 {
		mapped := ""
		if n < 3 {
			mapped = "mfa"
		}
		pairs = append(pairs, [2]string{fmt.Sprintf("Q-%02d", n), mapped})
	}
	answerable, total := Coverage(caiq(pairs...), l)
	if total != 20 {
		t.Fatalf("%d questions", total)
	}
	if answerable != 3 {
		t.Errorf("%d answerable, want the three that are mapped to a claim "+
			"the library holds", answerable)
	}
}

func TestSomebodyChangingTheirMindIsNotAConflict(t *testing.T) {
	old := claim("mfa", "MFA is enforced everywhere", Yes, "control:mfa")
	old.At = now.Add(-60 * 24 * time.Hour)
	fresh := claim("mfa", "MFA is enforced except on two legacy tools",
		Partly, "control:mfa")

	l := library(t, old, fresh)
	if l.Len() != 1 {
		t.Fatalf("%d claims for one identifier", l.Len())
	}
	got, _ := l.Get("mfa")
	if got.Answer != Partly {
		t.Errorf("the older claim won: %s", got.Answer)
	}
	// And the other way round: adding the old one after the new one does
	// not undo it.
	if err := l.Add(old); err != nil {
		t.Fatal(err)
	}
	got, _ = l.Get("mfa")
	if got.Answer != Partly {
		t.Error("re-adding an older claim overwrote a newer one")
	}
}

func TestAClaimReachesARealAuditLog(t *testing.T) {
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
	for _, a := range Answers() {
		c := claim("mfa-"+string(a), "something", a, "control:mfa")
		if a == No || a == NotApplicable {
			c.Backing = nil
		}
		if verr := c.Validate(); verr != nil {
			t.Fatalf("%s: %v", a, verr)
		}
		if _, aerr := log.Append(c.Record()); aerr != nil {
			t.Fatalf("%s: %v", a, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Answers()) {
		t.Fatalf("%d entries for %d answers", len(events), len(Answers()))
	}
}

// Thirteen wrong answers per CAIQ, at the accuracy every product advertises.
func TestTheBlockingCheckScalesToARealQuestionnaire(t *testing.T) {
	l := NewLibrary()
	var pairs [][2]string
	var register []finding.Finding
	for n := range 260 {
		id := fmt.Sprintf("c-%03d", n)
		if err := l.Add(claim(id, "we do the thing", Yes,
			"control:"+id)); err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, [2]string{fmt.Sprintf("Q-%03d", n), id})
		// Thirteen of them are contradicted by the register.
		if n%20 == 0 {
			register = append(register,
				open("control:"+id, "no evidence for the period"))
		}
	}
	f, err := Fill(caiq(pairs...), l, register, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Answered() != 260 {
		t.Fatalf("%d answered", f.Answered())
	}
	if len(f.Blocking()) != 13 {
		t.Fatalf("%d blocked, want the thirteen the register contradicts",
			len(f.Blocking()))
	}
	if f.Sendable() {
		t.Fatal("260 answers with 13 contradicted went out")
	}
	// The blocking ones sort first, so the person reviewing sees them.
	if !f.Concerns[0].Trouble.Blocking() {
		t.Error("a warning sorted above a contradiction")
	}
}

// Three missing days out of a hundred and eighty-two is a real finding and is
// not a reason to tell a customer nothing. A check that fires on everything is
// a check somebody turns off.
func TestASmallFindingCastsDoubtRatherThanStoppingTheFile(t *testing.T) {
	l := library(t, claim("mfa", "MFA is enforced", Yes, "control:mfa"))
	q := caiq([2]string{"IAM-03", "mfa"})

	small := open("control:mfa", "mfa has 3 day(s) with nothing to show")
	small.Severity = telemetry.SeverityLow
	f, err := Fill(q, l, []finding.Finding{small}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Sendable() {
		t.Fatalf("a three-day gap blocked a questionnaire: %v", f.Blocking())
	}
	if len(f.Concerns) != 1 || f.Concerns[0].Trouble != Doubtful {
		t.Fatalf("concerns are %v", f.Concerns)
	}
	if f.Concerns[0].Severity != telemetry.SeverityLow {
		t.Error("the concern does not carry what the reader needs to judge")
	}
	if !strings.Contains(f.Why(), "worth reading before this goes out") {
		t.Errorf("the summary is %q", f.Why())
	}

	// And the same finding at a serious severity does stop it.
	big := small
	big.Severity = telemetry.SeverityHigh
	blocked, err := Fill(q, l, []finding.Finding{big}, now)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Sendable() {
		t.Fatal("a high-severity finding did not stop the file")
	}
}
