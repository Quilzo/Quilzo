package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func runFor(t *testing.T, m Manifest, actions ...Action) (Trace, *Session) {
	t.Helper()
	s := NewSession(m, nil)
	r := Runner{Decide: script(actions...), Perform: echoPerform}
	tr, err := r.Run(context.Background(), s, "do the thing")
	if err != nil {
		t.Fatal(err)
	}
	return tr, s
}

func readOnly(t *testing.T) Manifest {
	t.Helper()
	m, err := New(KindRetrieval, "support", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A receipt counts work and refusals separately, and names what was attempted.
//
// "It tried to publish" is a fact somebody can act on; "eleven refusals" is a
// number. A buyer paying per outcome is entitled to the first.
func TestAReceiptNamesWhatWasRefused(t *testing.T) {
	tr, s := runFor(t, readOnly(t),
		Action{Op: "read_page"},
		Action{Op: "publish"}, // not held
		Action{Op: "publish"}, // again
		Action{Op: "write_page"},
		Action{Say: "done"},
	)
	r := tr.Receipt(s)

	if r.Did != 1 {
		t.Errorf("did %d operations, want 1 — the finishing step is not work", r.Did)
	}
	if r.Refused != 3 {
		t.Errorf("refused %d, want 3", r.Refused)
	}
	// Distinct operations, not one line per attempt.
	if got := strings.Join(r.Attempted, ","); got != "publish,write_page" {
		t.Errorf("attempted %q, want publish,write_page", got)
	}
}

// An unfinished run produced no outcome, whatever it did on the way.
func TestAnUnfinishedRunIsNotBillable(t *testing.T) {
	m := Manifest{
		Name: "looper", Kind: KindTask, Purpose: "go round",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: 2, Tools: 1, Duration: Duration(time.Hour)},
	}
	// Spends the budget and never says it is done.
	tr, s := runFor(t, m,
		Action{Op: "read_page"}, Action{Op: "read_page"}, Action{Op: "read_page"})
	r := tr.Receipt(s)

	if r.Complete {
		t.Fatal("the run reported completion after exhausting its budget")
	}
	ok, why := r.Billable()
	if ok {
		t.Fatal("an unfinished run was billable; that is how consumption " +
			"billing earned its reputation")
	}
	if why == "" {
		t.Error("the refusal to bill says nothing about why")
	}
}

// A run that finished without doing anything has produced nothing to charge for.
func TestAnEmptyRunIsNotBillable(t *testing.T) {
	tr, s := runFor(t, readOnly(t), Action{Say: "nothing to do"})
	r := tr.Receipt(s)

	if !r.Complete {
		t.Fatal("the run did not complete")
	}
	if ok, _ := r.Billable(); ok {
		t.Error("a run that did no work was billable")
	}
}

// Refusals do not make a run unbillable.
//
// An agent that overreached and was stopped may still have done the work asked
// of it. Treating every refusal as a failed outcome would price the safety
// controls as defects.
func TestRefusalsDoNotVoidAnOtherwiseCompletedRun(t *testing.T) {
	tr, s := runFor(t, readOnly(t),
		Action{Op: "read_page"}, Action{Op: "publish"}, Action{Say: "done"})
	r := tr.Receipt(s)

	if ok, why := r.Billable(); !ok {
		t.Errorf("a completed run with one refusal was not billable: %s", why)
	}
	if r.Refused != 1 {
		t.Errorf("refused %d, want 1", r.Refused)
	}
}

// The same run produces the same bytes, and a different one does not.
//
// The receipt goes into a hash-chained log, so an unstable rendering would make
// the record evidence of nothing. It also carries no timestamp: the log stamps
// its own entries, and a second clock inside the payload would make two
// identical runs hash differently for a reason nobody cares about.
func TestAReceiptIsStableAndDistinguishing(t *testing.T) {
	tr, s := runFor(t, readOnly(t), Action{Op: "read_page"}, Action{Say: "done"})
	r := tr.Receipt(s)

	first := r.Fingerprint()
	for range 20 {
		if r.Fingerprint() != first {
			t.Fatal("the same receipt hashed two different ways")
		}
	}

	// A different outcome is a different fingerprint.
	tr2, s2 := runFor(t, readOnly(t),
		Action{Op: "read_page"}, Action{Op: "publish"}, Action{Say: "done"})
	if tr2.Receipt(s2).Fingerprint() == first {
		t.Error("a run with a refusal hashed the same as one without")
	}
}

// Every field an auditor would want is in the log payload.
func TestTheDetailCarriesWhatAnAuditorNeeds(t *testing.T) {
	tr, s := runFor(t, readOnly(t),
		Action{Op: "read_page"}, Action{Op: "publish"}, Action{Say: "done"})
	d := tr.Receipt(s).Detail()

	for _, k := range []string{
		"agent", "kind", "goal", "complete", "did", "refused", "tainted",
		"steps", "toolcalls", "attempted",
	} {
		if _, ok := d[k]; !ok {
			t.Errorf("the audit payload has no %q", k)
		}
	}
	if d["refused"] != "1" || d["attempted"] != "publish" {
		t.Errorf("the payload does not describe the refusal: %v", d)
	}
}

// Every run produces a receipt, however it ended.
//
// The runs worth recording most are the ones that ended badly — a buyer
// disputing a charge and an operator investigating a runaway are both asking
// about the runs that are missing. An outcome record that only exists on the
// happy path is a record of nothing.
func TestEveryRunIsRecordedHoweverItEnds(t *testing.T) {
	var got []Receipt
	keep := func(r Receipt) { got = append(got, r) }

	// A clean finish.
	s := NewSession(readOnly(t), nil)
	r := Runner{
		Decide:  script(Action{Op: "read_page"}, Action{Say: "done"}),
		Perform: echoPerform, Record: keep,
	}
	if _, err := r.Run(context.Background(), s, "g"); err != nil {
		t.Fatal(err)
	}

	// A model that cannot be reached.
	s2 := NewSession(readOnly(t), nil)
	broken := Runner{
		Decide: func(context.Context, string, []Observation) (Action, error) {
			return Action{}, errors.New("the model is down")
		},
		Perform: echoPerform, Record: keep,
	}
	if _, err := broken.Run(context.Background(), s2, "g"); err == nil {
		t.Fatal("a broken model returned no error")
	}

	// A cancelled run.
	s3 := NewSession(readOnly(t), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := Runner{
		Decide: script(Action{Op: "read_page"}), Perform: echoPerform, Record: keep,
	}
	if _, err := cancelled.Run(ctx, s3, "g"); err == nil {
		t.Fatal("a cancelled run returned no error")
	}

	if len(got) != 3 {
		t.Fatalf("recorded %d receipts, want 3 — a run that ended badly is "+
			"the one somebody will come asking about", len(got))
	}
	// And only the clean one is billable.
	billable := 0
	for _, rec := range got {
		if ok, _ := rec.Billable(); ok {
			billable++
		}
	}
	if billable != 1 {
		t.Errorf("%d receipts are billable, want 1", billable)
	}
}

// A runner that cannot start is recorded as well.
//
// It produces no work and no error anybody sees unless the caller checks, which
// is the kind of silence an outcome record exists to break.
func TestARunnerThatCannotStartIsStillRecorded(t *testing.T) {
	var got []Receipt
	s := NewSession(readOnly(t), nil)
	r := Runner{Record: func(rec Receipt) { got = append(got, rec) }}

	if _, err := r.Run(context.Background(), s, "g"); err == nil {
		t.Fatal("a runner with no Decide returned no error")
	}
	if len(got) != 1 {
		t.Fatalf("recorded %d receipts, want 1", len(got))
	}
	if ok, why := got[0].Billable(); ok {
		t.Error("a runner that never started produced a billable outcome")
	} else if why == "" {
		t.Error("the receipt does not say why there is nothing to bill")
	}
}

// Nobody metered and zero tokens are different facts.
//
// A local model costs nothing and reports nothing; a hosted run whose usage
// nobody wrote down also shows zero. Those are opposite situations, and an
// invoice built on the second would charge for work it has no record of — so
// the receipt omits the field rather than writing a zero that reads as a
// measurement.
func TestAnUnmeteredRunDoesNotReportZeroTokens(t *testing.T) {
	tr, s := runFor(t, readOnly(t), Action{Op: "read_page"}, Action{Say: "done"})
	r := tr.Receipt(s)

	if r.Spend.Metered {
		t.Error("a run nobody metered reported itself as metered")
	}
	if _, present := r.Detail()["tokens"]; present {
		t.Error("the audit payload carries a token count nobody measured")
	}
}

// A reported figure is carried through to the record.
func TestReportedTokensReachTheReceipt(t *testing.T) {
	s := NewSession(readOnly(t), nil)
	r := Runner{
		Decide: func(_ context.Context, _ string, seen []Observation) (Action, error) {
			// What a host does: read the usage off the provider's response.
			s.Tokens(1200)
			if len(seen) == 0 {
				return Action{Op: "read_page"}, nil
			}
			return Action{Say: "done"}, nil
		},
		Perform: echoPerform,
	}
	tr, err := r.Run(context.Background(), s, "g")
	if err != nil {
		t.Fatal(err)
	}
	rec := tr.Receipt(s)

	if !rec.Spend.Metered {
		t.Fatal("a run with reported usage is not marked metered")
	}
	if rec.Spend.Tokens != 2400 {
		t.Errorf("tokens are %d, want 2400 — the figures accumulate across "+
			"calls rather than keeping the last one", rec.Spend.Tokens)
	}
	if rec.Detail()["tokens"] != "2400" {
		t.Errorf("the audit payload says %q", rec.Detail()["tokens"])
	}
}

// Nonsense from a provider does not end a run.
//
// A billing field that can stop work is a billing field that will, on the day a
// provider ships a bad response.
func TestABadTokenFigureIsIgnoredRatherThanFatal(t *testing.T) {
	s := NewSession(readOnly(t), nil)
	s.Tokens(-5)
	s.Tokens(0)
	if s.TokensUsed() != 0 {
		t.Errorf("a negative report changed the total to %d", s.TokensUsed())
	}
	s.Tokens(10)
	if s.TokensUsed() != 10 {
		t.Errorf("a good report after a bad one gave %d", s.TokensUsed())
	}
}

// A step the manifest allowed and that then failed is not work done.
//
// Allowed means the manifest let it through, not that anything happened. The
// operation may have hit a store that refused it, a tool that was down, or an
// executor that does not implement it — and counting those as work bills for
// failures, which is the specific complaint behind unverifiable consumption
// invoices.
//
// Found by running an agent whose manifest had been widened to hold write_page
// against an executor that only reads: the write errored and the receipt
// reported it as an operation carried out.
func TestAnAllowedStepThatFailedIsNotWork(t *testing.T) {
	m := Manifest{
		Name: "halfworking", Kind: KindTask, Purpose: "try things",
		Capabilities: []string{"read_page", "write_page"},
		Autonomy:     AutonomyDraft,
		Budget:       Budget{Steps: 10, Tools: 2, Duration: Duration(time.Hour)},
	}
	s := NewSession(m, nil)
	r := Runner{
		Decide: script(
			Action{Op: "read_page"}, Action{Op: "write_page"}, Action{Say: "done"}),
		Perform: func(_ context.Context, a Action) (string, error) {
			if a.Op == "write_page" {
				return "", errors.New("this executor only reads")
			}
			return "ok", nil
		},
	}
	tr, err := r.Run(context.Background(), s, "g")
	if err != nil {
		t.Fatal(err)
	}
	rec := tr.Receipt(s)

	if rec.Did != 1 {
		t.Errorf("did %d, want 1 — the failed write is not work carried out", rec.Did)
	}
	if rec.Failed != 1 {
		t.Errorf("failed %d, want 1", rec.Failed)
	}
	if rec.Refused != 0 {
		t.Errorf("refused %d, want 0 — the manifest permitted it, so this is "+
			"a failure rather than a refusal and an incident report needs to "+
			"tell them apart", rec.Refused)
	}
	if rec.Detail()["failed"] != "1" {
		t.Errorf("the audit payload does not carry the failure: %v", rec.Detail())
	}
}
