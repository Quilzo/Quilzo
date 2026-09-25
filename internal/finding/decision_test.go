// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

func decided(to State, by string, at time.Time) Decision {
	return Decision{
		Finding: "f1", At: at, By: by, Kind: audit.KindHuman, To: to,
	}
}

func base() Finding {
	f := one(FromVulnerability, "sca", telemetry.SeverityHigh)
	f.ID = "f1"
	f.State = Open
	return f
}

// -- the state is the fold, not a column -------------------------------------

func TestTheStateIsWhatTheDecisionsAddUpTo(t *testing.T) {
	f := base()
	got := Apply(f, []Decision{
		decided(Triaged, "dana", now),
		decided(Fixed, "kit", now.Add(48*time.Hour)),
	})
	if got.State != Fixed {
		t.Errorf("the finding is %s", got.State)
	}
	// And the input is untouched: a projection that modified what it was
	// given would make replaying the log twice give different answers.
	if f.State != Open {
		t.Errorf("applying decisions mutated the input to %s", f.State)
	}
}

func TestOrderIsByTimeAndNotByArrival(t *testing.T) {
	// A log is appended to by several people and read back in whatever order
	// it happens to come out of storage.
	f := base()
	out := Apply(f, []Decision{
		decided(Fixed, "kit", now.Add(48*time.Hour)),
		decided(Triaged, "dana", now),
	})
	if out.State != Fixed {
		t.Errorf("out-of-order decisions produced %s", out.State)
	}
}

func TestReplayingTheSameLogTwiceAgrees(t *testing.T) {
	// Two decisions at the same instant. Without a deterministic tiebreak a
	// projection can disagree with itself, which is the one thing it must
	// never do.
	f := base()
	sameMoment := []Decision{
		decided(Fixed, "kit", now),
		decided(Triaged, "dana", now),
	}
	first := Apply(f, sameMoment).State
	for range 50 {
		if got := Apply(f, sameMoment).State; got != first {
			t.Fatalf("replaying one log gave %s then %s", first, got)
		}
	}
}

func TestOnlyDecisionsAboutThisFindingCount(t *testing.T) {
	f := base()
	other := decided(Fixed, "kit", now)
	other.Finding = "somethingelse"
	if got := Apply(f, []Decision{other}); got.State != Open {
		t.Errorf("a decision about another finding moved this one to %s",
			got.State)
	}
}

func TestAnAcceptanceDoesNotOutliveItself(t *testing.T) {
	// A finding accepted in March and re-opened in April must not still read
	// as accepted-until-June.
	f := base()
	accept := decided(Accepted, "dana", now)
	accept.Because = "not reachable from the internet"
	accept.Until = now.Add(90 * 24 * time.Hour)

	got := Apply(f, []Decision{accept})
	if got.Because == "" || got.Until.IsZero() {
		t.Fatal("the acceptance did not carry its justification")
	}
	got = Apply(f, []Decision{accept, decided(Open, "kit", now.Add(time.Hour))})
	if got.Because != "" || !got.Until.IsZero() {
		t.Errorf("a reopened finding still reads as accepted until %s "+
			"because %q", got.Until, got.Because)
	}
}

// -- what makes it evidence --------------------------------------------------

func TestADecisionNobodyMadeIsRefused(t *testing.T) {
	d := decided(Fixed, "", now)
	if err := d.Validate(); err == nil {
		t.Error("a decision with no author was accepted; accountability is " +
			"the thing being recorded")
	}
}

func TestAModelCannotCloseAFinding(t *testing.T) {
	// The rule the agent design already applies to publishing, arriving
	// where it matters more: a model that can close its own findings can
	// close the one that would have caught it.
	d := decided(Fixed, "assistant", now)
	d.Kind = audit.KindAI
	err := d.Validate()
	if err == nil {
		t.Fatal("a model closed a finding")
	}
	if !strings.Contains(err.Error(), "propose") {
		t.Errorf("the refusal does not say what a model may do: %v", err)
	}
	// Accepting is the same judgement and is refused the same way.
	d.To, d.Because, d.Until = Accepted, "looks fine", now.Add(time.Hour)
	if d.Validate() == nil {
		t.Error("a model accepted a risk")
	}
}

func TestAcceptingNeedsAReasonAnExpiryAndAFuture(t *testing.T) {
	d := decided(Accepted, "dana", now)
	if d.Validate() == nil {
		t.Error("accepted with no reason")
	}
	d.Because = "compensating control in place"
	if d.Validate() == nil {
		t.Error("accepted for ever")
	}
	d.Until = now.Add(-time.Hour)
	if d.Validate() == nil {
		t.Error("accepted until a moment that had already passed")
	}
	d.Until = now.Add(90 * 24 * time.Hour)
	if err := d.Validate(); err != nil {
		t.Errorf("a properly recorded acceptance was refused: %v", err)
	}
}

func TestAnInventedStateIsRefused(t *testing.T) {
	d := decided("wontfix", "dana", now)
	if d.Validate() == nil {
		t.Error("a state outside the lifecycle was accepted")
	}
}

// -- the audit entry ---------------------------------------------------------

func TestADecisionBecomesAnAuditEntry(t *testing.T) {
	d := decided(Accepted, "dana", now)
	d.Because = "not reachable"
	d.Until = now.Add(90 * 24 * time.Hour)

	r := d.Record()
	if r.Action != "finding.accepted" {
		t.Errorf("the action is %q", r.Action)
	}
	if r.Principal != "dana" || r.Kind != audit.KindHuman {
		t.Errorf("the actor is %s/%s", r.Principal, r.Kind)
	}
	// Accepting is recorded as a denial, not a success: somebody decided not
	// to fix something, and a log where that reads the same as fixing it is
	// one nobody can search for the interesting cases.
	if r.Outcome != audit.Denied {
		t.Errorf("accepting a risk is recorded as %s", r.Outcome)
	}
	if r.Detail["because"] != "not reachable" || r.Detail["until"] == "" {
		t.Errorf("the justification did not survive: %v", r.Detail)
	}
	if r.Detail["finding"] != "f1" {
		t.Errorf("the entry does not name the finding: %v", r.Detail)
	}
}

func TestTheAuditLogAcceptsTheEntry(t *testing.T) {
	// The detail keys are refused by audit if any looks like a credential,
	// and the whole record is refused rather than the key — so a name chosen
	// carelessly here means the decision happens and nothing records it.
	dir := t.TempDir()
	l, err := audit.New(audit.Options{
		Path: dir + "/audit.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []State{Triaged, Fixed, Stale, Open} {
		d := decided(to, "dana", now)
		if _, aerr := l.Append(d.Record()); aerr != nil {
			t.Errorf("%s was refused by the log: %v", to, aerr)
		}
	}
	accept := decided(Accepted, "dana", now)
	accept.Because, accept.Until = "compensating control", now.Add(time.Hour)
	if _, aerr := l.Append(accept.Record()); aerr != nil {
		t.Errorf("an acceptance was refused by the log: %v", aerr)
	}
}

// -- the sentence an auditor asks for ----------------------------------------

func TestTheHistoryReadsAsASentence(t *testing.T) {
	accept := decided(Accepted, "dana", now)
	accept.Because = "the component is not reachable"
	accept.Until = now.Add(60 * 24 * time.Hour)
	reaccept := decided(Accepted, "kit", now.Add(61*24*time.Hour))
	reaccept.Because = "same grounds, re-reviewed"
	reaccept.Until = now.Add(150 * 24 * time.Hour)

	got := Story("f1", []Decision{reaccept, accept})
	for _, want := range []string{"dana", "kit", "not reachable", "re-reviewed"} {
		if !strings.Contains(got, want) {
			t.Errorf("the story omits %q: %s", want, got)
		}
	}
	// Oldest first, because that is the order it happened in.
	if strings.Index(got, "dana") > strings.Index(got, "kit") {
		t.Errorf("the story is out of order: %s", got)
	}
}

func TestNobodyLookingIsDistinctFromReopening(t *testing.T) {
	// A finding nobody has examined and one somebody examined and returned
	// to Open are different situations, and only the log tells them apart.
	if Decided("f1", nil) {
		t.Error("an untouched finding reports a decision")
	}
	reopened := []Decision{
		decided(Triaged, "dana", now),
		decided(Open, "dana", now.Add(time.Hour)),
	}
	if !Decided("f1", reopened) {
		t.Error("a reopened finding reports no decision")
	}
	if got := Apply(base(), reopened).State; got != Open {
		t.Errorf("the reopened finding is %s", got)
	}
	if Story("f1", nil) != "nobody has looked at this" {
		t.Errorf("an empty history reads as %q", Story("f1", nil))
	}
}
