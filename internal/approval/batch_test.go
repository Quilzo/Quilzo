// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// exceptions proposes n sixty-day exceptions, each needing one approver.
func (b *bench) exceptions(n int) []register.ID {
	b.t.Helper()
	starts := register.TimeOf(b.clock)
	var ids []register.ID
	for i := 0; i < n; i++ {
		ex := register.Exception{Ref: "EX-" + string(rune('A'+i)), About: "c0000000000000000000000000000001",
			Reason: register.Text("sha256:" + strings.Repeat("b", 64)), Owner: b.subject("owner"),
			Starts: starts, Expires: starts + 60*86400}
		ids = append(ids, b.propose("dana", ex))
	}
	return ids
}

// A batch is approved only once every item it chose for its approver has
// been opened, and its root is the root of what was shown: an item changed
// since is not approved by it.
func TestBatchRefusedUntilSampleOpened(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActApproveException))
	ids := b.exceptions(9)
	batch, err := b.m.StartBatch(b.person("ciso"), ids)
	if err != nil {
		t.Fatal(err)
	}
	if n := batch.Unopened(); n != 3 {
		t.Fatalf("a batch of nine chose %d to open, and the square root of nine is three", n)
	}
	var leaves []register.Digest
	for i, it := range batch.Items {
		if it.Record != ids[i] {
			t.Fatal("the batch is not in the order it was shown")
		}
		leaves = append(leaves, it.Surface)
	}
	if batch.Root != register.MerkleRoot(leaves) {
		t.Fatal("the batch's root is not the root of its items as shown")
	}
	approve := func() (*BatchOutcome, error) {
		return b.m.SignBatch(b.person("ciso"), batch.Root, b.proofFor("ciso", ForBatch, batch.Root))
	}
	if _, err := approve(); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "3 of the decisions") {
		t.Fatalf("a batch was approved with none of its sample opened: %v", err)
	}
	// Opening items it did not choose opens none of the sample.
	var sampled []register.ID
	for _, it := range batch.Items {
		if it.Sampled {
			sampled = append(sampled, it.Record)
		} else if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, it.Record); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range sampled[:2] {
		if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := approve(); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "1 of the decisions") {
		t.Fatalf("a batch was approved with one of its sample unopened: %v", err)
	}
	// Nobody else opens it for them.
	if _, _, err := b.m.OpenInBatch(b.person("cfo"), batch.Root, sampled[2]); !errors.Is(err, ErrRefused) {
		t.Fatalf("somebody else opened the approver's sample: %v", err)
	}
	if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, sampled[2]); err != nil {
		t.Fatal(err)
	}
	// A signature for one of its items is not a signature for the batch.
	if _, err := b.m.SignBatch(b.person("ciso"), batch.Root, b.proofFor("ciso", ForApproval, batch.Root)); err == nil {
		t.Fatal("an item's kind of signature approved the batch")
	}
	out, err := approve()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 9 {
		t.Fatalf("the batch approved %d of its nine", len(out.Items))
	}
	for _, id := range ids {
		e, err := b.reg.Get(id)
		if err != nil {
			t.Fatalf("%s was not written: %v", id, err)
		}
		if s := register.ApprovalOf(e.Record).Signers[0]; s.Batch != batch.Root || s.Assertion != out.Evidence {
			t.Errorf("%s does not name the batch it was approved in: %+v", id, s)
		}
	}
	bid, _ := register.IDOf(register.ApprovalBatch{Root: batch.Root, Approver: b.subject("ciso")})
	e, err := b.reg.Get(bid)
	if err != nil {
		t.Fatalf("the batch's record is not in the register: %v", err)
	}
	if rec := e.Record.(register.ApprovalBatch); len(rec.Items) != 9 || rec.Approver != b.subject("ciso") {
		t.Errorf("the batch's record does not hold what was approved: %+v", rec)
	}
}

// An item that changes after the batch was shown is not approved by the
// root that was signed, and the batch as a whole waits to be shown again.
func TestBatchRootCoversOnlyItemsAsShown(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActApproveException))
	ids := b.exceptions(2)
	batch, err := b.m.StartBatch(b.person("ciso"), ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range batch.Items {
		if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, it.Record); err != nil {
			t.Fatal(err)
		}
	}
	starts := register.TimeOf(b.clock)
	b.propose("dana", register.Exception{Ref: "EX-B", About: "c0000000000000000000000000000001",
		Reason: register.Text("sha256:" + strings.Repeat("c", 64)), Owner: b.subject("owner"), Starts: starts, Expires: starts + 30*86400})
	if _, err := b.m.SignBatch(b.person("ciso"), batch.Root, b.proofFor("ciso", ForBatch, batch.Root)); !errors.Is(err, ErrOtherSurface) {
		t.Fatalf("a batch whose item changed after it was shown was approved: %v", err)
	}
	if b.reg.Head() != "" {
		t.Fatal("the refused batch wrote something")
	}
}

// The time spent on each item is recorded, from opening it to opening the
// next or approving the batch, and the whole time from showing it.
func TestTimePerItemRecorded(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActApproveException))
	ids := b.exceptions(3)
	batch, err := b.m.StartBatch(b.person("ciso"), ids)
	if err != nil {
		t.Fatal(err)
	}
	spent := []time.Duration{40 * time.Second, 7 * time.Second, 95 * time.Second}
	for i, id := range ids {
		if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, id); err != nil {
			t.Fatal(err)
		}
		b.clock = b.clock.Add(spent[i])
	}
	// Back to the first for another look.
	if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, ids[0]); err != nil {
		t.Fatal(err)
	}
	b.clock = b.clock.Add(5 * time.Second)
	if _, err := b.m.SignBatch(b.person("ciso"), batch.Root, b.proofFor("ciso", ForBatch, batch.Root)); err != nil {
		t.Fatal(err)
	}
	bid, _ := register.IDOf(register.ApprovalBatch{Root: batch.Root, Approver: b.subject("ciso")})
	e, err := b.reg.Get(bid)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.Record.(register.ApprovalBatch)
	want := []int64{45, 7, 95}
	for i, it := range rec.Items {
		if it.Seconds != want[i] || !it.Opened {
			t.Errorf("item %d is recorded as looked at for %d seconds (opened %v), not %d", i, it.Seconds, it.Opened, want[i])
		}
	}
	if rec.Seconds != 147 {
		t.Errorf("the batch is recorded as taking %d seconds from being shown, not 147", rec.Seconds)
	}
}

// Two approvers may each batch the same decisions, as a decision that takes
// two people asks of them: each is shown the batch on their own, opens what
// it chose for them, and signs the same root, and the register keeps each
// one's batch beside the other's.
func TestTwoApproversBatchTheSameDecisions(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActApproveException), holds("cfo", auth.ActApproveException))
	starts := register.TimeOf(b.clock)
	var ids []register.ID
	for _, ref := range []string{"EX-LONG-1", "EX-LONG-2"} {
		// Longer than a quarter, so each takes two approvers.
		ids = append(ids, b.propose("dana", register.Exception{Ref: ref, About: "c0000000000000000000000000000001",
			Reason: register.Text("sha256:" + strings.Repeat("d", 64)), Owner: b.subject("owner"),
			Starts: starts, Expires: starts + 120*86400}))
	}
	first, err := b.m.StartBatch(b.person("ciso"), ids)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.m.StartBatch(b.person("cfo"), ids)
	if err != nil {
		t.Fatal(err)
	}
	if first.Root != second.Root {
		t.Fatal("the same decisions in the same order have two roots")
	}
	for _, who := range []string{"ciso", "cfo"} {
		for _, id := range ids {
			if _, _, err := b.m.OpenInBatch(b.person(who), first.Root, id); err != nil {
				t.Fatalf("%s could not open their own batch, shown beside somebody else's: %v", who, err)
			}
		}
		if _, err := b.m.SignBatch(b.person(who), first.Root, b.proofFor(who, ForBatch, first.Root)); err != nil {
			t.Fatalf("%s's batch was refused: %v", who, err)
		}
	}
	for _, id := range ids {
		e, err := b.reg.Get(id)
		if err != nil {
			t.Fatalf("%s was not written with its two approvals: %v", id, err)
		}
		ap := register.ApprovalOf(e.Record)
		if len(ap.Signers) != 2 || ap.Signers[0].Batch != first.Root || ap.Signers[1].Batch != first.Root {
			t.Errorf("%s does not hold both approvers' batches: %+v", id, ap.Signers)
		}
		for _, sg := range ap.Signers {
			ev, err := LoadEvidence(b.root, sg.Assertion)
			if err == nil {
				err = ev.Check()
			}
			if err != nil || ev.For != first.Root {
				t.Errorf("%s's evidence from %s does not check over the root: %v", id, sg.Subject, err)
			}
		}
	}
	for _, who := range []string{"ciso", "cfo"} {
		bid, _ := register.IDOf(register.ApprovalBatch{Root: first.Root, Approver: b.subject(who)})
		if _, err := b.reg.Get(bid); err != nil {
			t.Errorf("%s's batch is not in the register: %v", who, err)
		}
	}
}

// The sample is forced: showing the batch again, in the same order or
// another, or with a decision added, does not choose again until the items
// it chose are ones the approver does not have to open. Each showing chose
// afresh, so a decision somebody did not want to open was left out of the
// sample by asking for the batch until it was.
func TestABatchShownAgainKeepsItsSample(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActApproveException))
	ids := b.exceptions(10)
	first, err := b.m.StartBatch(b.person("ciso"), ids[:9])
	if err != nil {
		t.Fatal(err)
	}
	chosen := map[register.ID]bool{}
	for _, it := range first.Items {
		if it.Sampled {
			chosen[it.Record] = true
		}
	}
	reversed := make([]register.ID, 9)
	for i, id := range ids[:9] {
		reversed[8-i] = id
	}
	for n, again := range [][]register.ID{ids[:9], reversed, ids, ids[:9], reversed, ids, ids[:9], reversed} {
		batch, err := b.m.StartBatch(b.person("ciso"), again)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range batch.Items {
			if chosen[it.Record] && !it.Sampled {
				t.Fatalf("showing the batch again (%d) let %s, which it chose to be opened, go unopened", n+1, it.Record)
			}
		}
	}
	// Somebody else's batch of the same decisions chooses its own.
	b.access.Grant(holds("cfo", auth.ActApproveException))
	if _, err := b.m.StartBatch(b.person("cfo"), ids[:9]); err != nil {
		t.Fatal(err)
	}
	// Once the approver has opened what was chosen, the batch is theirs
	// to approve, and what it was chosen from is recorded as chosen.
	batch, err := b.m.StartBatch(b.person("ciso"), ids[:9])
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range batch.Items {
		if it.Sampled {
			if _, _, err := b.m.OpenInBatch(b.person("ciso"), batch.Root, it.Record); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := b.m.SignBatch(b.person("ciso"), batch.Root, b.proofFor("ciso", ForBatch, batch.Root))
	if err != nil || len(out.Items) != 9 {
		t.Fatalf("the batch was not approved once its sample was opened: %v", err)
	}
	bid, _ := register.IDOf(register.ApprovalBatch{Root: batch.Root, Approver: b.subject("ciso")})
	e, err := b.reg.Get(bid)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range e.Record.(register.ApprovalBatch).Items {
		if chosen[it.Record] && !(it.Sampled && it.Opened) {
			t.Errorf("the batch's record does not hold %s as a spot-check that was opened", it.Record)
		}
	}
}
