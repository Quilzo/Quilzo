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
