// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/vault"
)

// A decision made alone is one only the person who was the only one
// eligible can make. Marked alone with others eligible, it was the person
// who raised a risk accepting it themselves, which is the rule an approval
// exists to keep: raiser and acceptor are two people unless there is one.
func TestARaiserCannotApproveAloneWhenOthersMay(t *testing.T) {
	raiser := dana.Subject
	alone := func(of int) *Approval {
		a := signedBy(raiser, raiser)
		a.Alone, a.Of, a.ReviewDue = true, of, 1_790_000_000+30*86_400
		return a
	}
	risk := Risk{Ref: "R-7", Title: "Payments outage", Owner: owner, Raised: raiser, Likelihood: 3, Impact: 4,
		Status: "accepted", Approval: alone(5)}
	b := newBench(t)
	if _, err := b.Put(dana, "a test's write", risk); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "only person eligible") {
		t.Fatalf("the raiser accepted their own risk alone with four others eligible: %v", err)
	}
	if b.Head() != "" {
		t.Fatal("the refused decision was written")
	}
	// A team of one is what alone is for, and it is recorded so.
	risk.Approval = alone(1)
	rc := mustPut(t, b, dana, risk)
	if row, ok := mustIndex(t, b).Find(KindRisk, rc.Written[0].ID); !ok || row.Flags&FlagAlone == 0 {
		t.Errorf("a decision made alone is not flagged in its row: %+v", row)
	}
}

// Only a person or a service writes the record. An actor whose kind was not
// said is not taken for a person: the rule that a model only proposes
// rested on the model saying it was one.
func TestOnlyAPersonOrAServiceWrites(t *testing.T) {
	for _, kind := range []audit.Kind{"", audit.KindUnknown, "robot"} {
		b := newBench(t)
		who := dana
		who.Kind = kind
		if _, err := b.Put(who, "a test's write", control("AC-01")); !errors.Is(err, ErrModel) {
			t.Errorf("an actor of kind %q wrote the record: %v", kind, err)
		}
		if b.Head() != "" {
			t.Errorf("an actor of kind %q moved the register's head", kind)
		}
		if len(b.log) != 1 || b.log[0].Outcome != audit.Denied {
			t.Errorf("the refusal of an actor of kind %q was recorded as %+v", kind, b.log)
		}
	}
}

// A proposal that could be made can be accepted: the line it was proposed
// with, carried into the commit that accepts it, is cut to fit rather than
// refused, which left a proposal nobody could ever accept.
func TestAProposalAcceptsWhateverItsReason(t *testing.T) {
	b := newBench(t)
	why := strings.Repeat("drafted from the quarterly access review ", 10)[:MaxLabel]
	why = strings.TrimSpace(why)
	if _, err := b.Propose(model, why, control("AC-02")); err != nil {
		t.Fatalf("a proposal with a reason of %d bytes: %v", len(why), err)
	}
	rc, err := b.Accept(lee, mustID(t, control("AC-02")), nil)
	if err != nil || rc.Commit == "" {
		t.Fatalf("accepting it was answered %+v, %v", rc, err)
	}
	if !strings.HasPrefix(rc.Why, "accepted: drafted from") || len(rc.Why) > MaxLabel {
		t.Errorf("the accepting commit says %q", rc.Why)
	}
}

// Deciding a proposal decides the one the person read. A newer proposal of
// the same record, made while they decided, is still waiting afterwards: it
// was taken off the ref as accepted when nobody had seen it.
func TestDecidingAProposalLeavesANewerOneWaiting(t *testing.T) {
	for _, decide := range []string{"accept", "reject"} {
		t.Run(decide, func(t *testing.T) {
			b := newBench(t)
			first := control("AC-04")
			if _, err := b.Propose(model, "the first draft", first); err != nil {
				t.Fatal(err)
			}
			id := mustID(t, first)
			second := first
			second.Title = "A second draft nobody has read"
			// The newer proposal lands while the decision is being made:
			// after the decision has read what waits, before it is taken
			// off the ref. The audit entry of the decision's write is that
			// moment for an acceptance; a rejection's gate is, for both.
			proposed := false
			propose := func() {
				if !proposed {
					proposed = true
					if _, err := b.Propose(model, "a second draft", second); err != nil {
						t.Errorf("the second proposal: %v", err)
					}
				}
			}
			decider := lee
			decider.May = func(act auth.Action, resource string) error {
				if act == auth.ActApprove {
					propose()
				}
				return nil
			}
			var err error
			if decide == "accept" {
				_, err = b.Accept(decider, id, nil)
			} else {
				err = b.Reject(decider, id)
			}
			if err != nil {
				t.Fatalf("%s: %v", decide, err)
			}
			left, err := b.Proposals()
			if err != nil {
				t.Fatal(err)
			}
			if len(left) != 1 || left[0].Record.(Control).Title != second.Title {
				t.Errorf("after the first draft was decided, what waits is %+v; the second draft is still to be decided", left)
			}
			if decide == "accept" {
				got, err := b.Get(id)
				if err != nil || got.Record.(Control).Title != first.Title {
					t.Errorf("the register holds %+v (%v); it holds the draft that was accepted", got.Record, err)
				}
			}
		})
	}
}

// Of two pieces of evidence about one control at one moment, a failure
// decides, whichever order the rows are in: a control is not passing because
// its passing row happened to sort after its failing one.
func TestOfTwoAtOneMomentAFailureDecides(t *testing.T) {
	b := newBench(t)
	c := control("AC-01")
	mustPut(t, b, dana, c)
	at := Time(1_790_000_000)
	var runs []TestRun
	for i, outcome := range []Outcome{Pass, Fail, Pass} {
		r := TestRun{Test: owner, Ran: at + Time(i), Outcome: outcome, Population: digest(10 + i), Size: 3,
			Snapshot: digest(20 + i)}
		if outcome == Fail {
			r.Failing = []ID{owner}
		}
		runs = append(runs, r)
	}
	// Three runs, two pieces of evidence at the same moment from the
	// first two, and the identifiers decide the order of the rows.
	var recs []Record
	for i := range runs[:2] {
		recs = append(recs, runs[i], Evidence{Control: mustID(t, c), Run: mustID(t, runs[i]), At: at,
			Outcome: runs[i].Outcome, Grade: GradeConnector})
	}
	mustPut(t, b, importer, recs...)
	if got := mustIndex(t, b).Coverage(); got.Failing != 1 || got.Passing != 0 {
		t.Errorf("a pass and a failure at one moment counted as %+v; the failure decides", got)
	}
	// And a third, a pass at the same moment, decides nothing either.
	mustPut(t, b, importer, runs[2], Evidence{Control: mustID(t, c), Run: mustID(t, runs[2]), At: at,
		Outcome: Pass, Grade: GradeConnector})
	if got := mustIndex(t, b).Coverage(); got.Failing != 1 || got.Passing != 0 {
		t.Errorf("two passes and a failure at one moment counted as %+v; the failure decides", got)
	}
}

func mustIndex(t testing.TB, b *bench) *Index {
	t.Helper()
	ix, err := b.Index()
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

// A store encrypted at rest keeps no part of the register in the clear.
// The index file beside the store held a row of every record, in plain
// bytes: who owns each risk, how likely and how bad, which incidents are
// privileged and when the organisation knew. For such a store the index is
// built from the sealed objects in each process and is not kept, and a
// file left from before the store was encrypted is removed.
func TestAnEncryptedStoresIndexIsNotKeptInTheClear(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	plain, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	b := newBench(t)
	b.Register = &Register{Store: plain, Audit: b.Audit, Now: b.Now}
	risk := Risk{Ref: "R-1", Title: "Payments outage", Owner: owner, Raised: owner, Likelihood: 4, Impact: 5, Status: "open"}
	mustPut(t, b, dana, risk)
	if _, err := b.Index(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.indexPath()); err != nil {
		t.Fatalf("a plaintext store keeps its index: %v", err)
	}

	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	enc := &bench{Register: &Register{Store: sealed.WithKeys(kr), Audit: b.Audit, Now: b.Now}, clock: b.clock}
	mustPut(t, enc, dana, control("AC-01"))
	ix, err := enc.Index()
	if err != nil {
		t.Fatal(err)
	}
	if len(ix.Rows(KindControl)) != 1 || len(ix.Rows(KindRisk)) != 1 {
		t.Errorf("the encrypted store's index holds %d controls and %d risks", len(ix.Rows(KindControl)), len(ix.Rows(KindRisk)))
	}
	if _, err := os.Stat(enc.indexPath()); !os.IsNotExist(err) {
		t.Errorf("an encrypted store keeps its index in the clear beside it (%v)", err)
	}
	id := mustID(t, risk).bytes()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(p, string(filepath.Separator)+"objects"+string(filepath.Separator)) {
			return nil
		}
		if body, _ := os.ReadFile(p); bytes.Contains(body, id[:]) {
			t.Errorf("%s holds a risk's identifier in the clear", p)
		}
		return nil
	})
}

// A person's proposal is decided by somebody the register can tell apart
// from them. The proposer is named by pseudonym, so a decider whose
// surface gave no pseudonym could be the proposer, and was let decide.
func TestAPersonsProposalIsNotDecidedBySomebodyWithoutAPseudonym(t *testing.T) {
	b := newBench(t)
	if _, err := b.Propose(dana, "dana's draft", control("AC-05")); err != nil {
		t.Fatal(err)
	}
	id := mustID(t, control("AC-05"))
	nameless := dana
	nameless.Subject = ""
	if _, err := b.Accept(nameless, id, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("a decider with no pseudonym accepted a person's proposal: %v", err)
	}
	if err := b.Reject(nameless, id); !errors.Is(err, ErrRefused) {
		t.Errorf("a decider with no pseudonym rejected a person's proposal: %v", err)
	}
	if b.Head() != "" {
		t.Error("the refused acceptance wrote the record")
	}
	if _, err := b.Accept(lee, id, nil); err != nil {
		t.Errorf("somebody else accepting it: %v", err)
	}
}

// Rejecting a proposal is a decision, recorded as one: while the audit log
// cannot take its entry, nothing is taken off the proposals ref.
func TestARejectionWaitsForTheAuditLog(t *testing.T) {
	b := newBench(t)
	if _, err := b.Propose(model, "a draft", control("AC-06")); err != nil {
		t.Fatal(err)
	}
	b.Ready = func() error { return errors.New("the log's disk is full") }
	if err := b.Reject(lee, mustID(t, control("AC-06"))); err == nil {
		t.Error("a rejection went ahead with the audit log unable to record it")
	}
	if left, _ := b.Proposals(); len(left) != 1 {
		t.Errorf("%d proposals wait after a rejection the log could not record", len(left))
	}
}
