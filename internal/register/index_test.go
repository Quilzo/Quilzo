// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// The index that was added to, write by write, is the index a rebuild
// from the store makes.
func TestIndexIncrementalEqualsRebuild(t *testing.T) {
	b := newBench(t)
	recs, err := Probe{Observations: 300, Controls: 40, Rows: 400}.Records()
	if err != nil {
		t.Fatal(err)
	}
	// In uneven batches, with the index asked for between them, so every
	// one after the first is added to an index that already holds rows.
	for at, step := 0, 1; at < len(recs); step = step*3 + 1 {
		end := min(at+step, len(recs))
		mustPut(t, b, importer, recs[at:end]...)
		ix, err := b.Index()
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := b.Rebuild()
		if err != nil {
			t.Fatal(err)
		}
		if !ix.Equal(fresh) {
			t.Fatalf("after %d records the index added to is not the index rebuilt", end)
		}
		if at > 0 && ix.Reused == 0 {
			t.Errorf("after %d records nothing was carried over; every write re-read the whole register", end)
		}
		at = end
	}
	ix, _ := b.Index()
	if ix.Len() != len(recs) {
		t.Fatalf("the index holds %d rows of %d records", ix.Len(), len(recs))
	}

	// One record changed: its row changes, and almost nothing is read.
	changed := recs[4+300].(Control)
	changed.Title = "Renamed"
	mustPut(t, b, dana, changed)
	after, err := b.Index()
	if err != nil {
		t.Fatal(err)
	}
	if fresh, _ := b.Rebuild(); !after.Equal(fresh) {
		t.Fatal("after one change the index is not the index rebuilt")
	}
	if after.Read > 40 || after.Reused < len(recs)-40 {
		t.Errorf("one changed control read %d records and carried over %d of %d", after.Read, after.Reused, len(recs))
	}
	before, _ := ix.Find(KindControl, mustID(t, changed))
	now, ok := after.Find(KindControl, mustID(t, changed))
	if !ok || before.Sum == now.Sum || before.ID != now.ID {
		t.Errorf("the changed control's row went from %+v to %+v", before, now)
	}

	// A second process starts from the file the first left, and reads
	// nothing from the store.
	second := Open(b.Store)
	fromFile, err := second.Index()
	if err != nil {
		t.Fatal(err)
	}
	if !fromFile.Equal(after) || fromFile.Read != 0 || fromFile.Discarded != "" {
		t.Errorf("a second process read %d records and discarded its file for %q", fromFile.Read, fromFile.Discarded)
	}

	// A row says what its kind says it does.
	ev, _, _ := b.List(KindEvidence, 0, 1)
	e := ev[0].Record.(Evidence)
	row, _ := after.Find(KindEvidence, ev[0].ID)
	if idOf(row.About) != e.Control || idOf(row.Via) != e.Run || row.At != int64(e.At) ||
		row.State != ordinal(e.Outcome) || row.Grade != ordinal(e.Grade) || !strings.HasPrefix(ev[0].Object, fmt.Sprintf("%x", row.Sum)) {
		t.Errorf("the evidence %+v is indexed as %+v", e, row)
	}
}

// A damaged index file is found, said, and replaced by one built from the
// store.
func TestIndexDigestMismatchRebuilds(t *testing.T) {
	b := newBench(t)
	recs, _ := Probe{Observations: 50, Controls: 10, Rows: 100}.Records()
	mustPut(t, b, importer, recs...)
	good, err := b.Index()
	if err != nil {
		t.Fatal(err)
	}
	path := b.indexPath()
	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the index was not kept beside the store: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("the index file is %v; it is the store owner's alone", info.Mode().Perm())
	}

	for name, damage := range map[string]func([]byte) []byte{
		"one byte of a row changed": func(f []byte) []byte { f[len(f)/2] ^= 0x01; return f },
		"cut short":                 func(f []byte) []byte { return f[:len(f)-100] },
		"emptied":                   func([]byte) []byte { return nil },
		"another program's file":    func(f []byte) []byte { return append([]byte("not an index\n"), f...) },
		"a row changed and the digest left": func(f []byte) []byte {
			f[len(f)-40] ^= 0xff
			return f
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, damage(append([]byte(nil), whole...)), 0o600); err != nil {
				t.Fatal(err)
			}
			fresh := Open(b.Store)
			ix, err := fresh.Index()
			if err != nil {
				t.Fatalf("a damaged index stopped the register being read: %v", err)
			}
			if ix.Discarded == "" {
				t.Error("the damage was not noticed")
			}
			if !ix.Equal(good) || ix.Read != len(recs) || ix.Reused != 0 {
				t.Errorf("the index after the damage read %d and carried over %d of %d", ix.Read, ix.Reused, len(recs))
			}
			// And the file is whole again for the next process.
			if next, _ := Open(b.Store).Index(); next == nil || next.Discarded != "" || next.Read != 0 {
				t.Errorf("the rebuilt index was not written back: %+v", next)
			}
		})
	}
}

// A row is the size the design was costed at.
func TestARowIsEightyBytes(t *testing.T) {
	if got := unsafe.Sizeof(Row{}); got != rowMemory {
		t.Errorf("a row is %d bytes in memory; the index was costed at %d", got, rowMemory)
	}
	var b [rowDisk]byte
	in := Row{ID: ID("0123456789abcdef0123456789abcdef").bytes(), At: -5, N: 7, M: 1 << 31, State: 3, Grade: 250, Flags: FlagAlone | FlagPrivileged}
	in.Sum[7] = 9
	encodeRow(&b, &in)
	var out Row
	decodeRow(&out, b[:])
	if in != out {
		t.Errorf("a row written as %+v was read as %+v", in, out)
	}
}

// What is proposed is nowhere a figure is drawn from.
func TestPostureIgnoresProposals(t *testing.T) {
	b := newBench(t)
	c := control("AC-01")
	mustPut(t, b, dana, c)
	run := TestRun{Test: owner, Ran: 1_790_000_000, Outcome: Pass, Population: digest(1), Size: 10, Snapshot: digest(2)}
	passing := Evidence{Control: mustID(t, c), Run: mustID(t, run), At: run.Ran, Outcome: Pass, Grade: GradeConnector}
	mustPut(t, b, importer, run, passing)
	before, _ := b.Index()
	head := b.Head()
	want := Coverage{Controls: 1, Passing: 1, NeverFailed: 1, Latest: run.Ran}
	if got := before.Coverage(); got != want {
		t.Fatalf("coverage is %+v", got)
	}

	// A model proposes a newer failure, a second control and a risk.
	later := run
	later.Ran, later.Outcome, later.Failing = run.Ran+3600, Fail, []ID{owner}
	failing := Evidence{Control: mustID(t, c), Run: mustID(t, later), At: later.Ran, Outcome: Fail, Grade: GradeConnector}
	rc, err := b.Propose(model, "a draft from the control tester", later, failing, control("AC-02"),
		Risk{Ref: "R-1", Title: "T", Owner: owner, Raised: owner, Likelihood: 5, Impact: 5, Status: "open"})
	if err != nil || rc.Ref != ProposalsRef || len(rc.Written) != 4 {
		t.Fatalf("the proposal was answered %+v, %v", rc, err)
	}
	if b.Head() != head {
		t.Fatal("a proposal moved the register's head")
	}
	after, _ := b.Index()
	if !after.Equal(before) || after.Coverage() != want {
		t.Errorf("a proposal changed the index or the coverage: %+v", after.Coverage())
	}
	if fresh, _ := b.Rebuild(); fresh.Coverage() != want {
		t.Errorf("a rebuild counted a proposal: %+v", fresh.Coverage())
	}
	for _, rec := range []Record{failing, control("AC-02")} {
		if _, err := b.Get(mustID(t, rec)); !errors.Is(err, ErrNotFound) {
			t.Errorf("a proposed %s is read from the register: %v", rec.Kind(), err)
		}
	}
	if list, total, _ := b.List(KindControl, 0, 0); total != 1 || len(list) != 1 {
		t.Errorf("a proposed control is listed: %d of %d", len(list), total)
	}
	if n, _ := b.Counts(); n[KindRisk] != 0 || n[KindEvidence] != 1 {
		t.Errorf("a proposal was counted: %v", n)
	}
	if e := b.log[len(b.log)-1]; e.Action != ProposeAction || e.Kind != audit.KindAI || e.Model != "an-agent" {
		t.Errorf("the proposal was recorded as %+v", e)
	}

	// What a model extracted is not evidence either, on either ref.
	x := Extracted{Raw: digest(7), Field: "opinion", Value: TextValue("unqualified"), Quote: Text(digest(8)),
		Start: 10, End: 40, Route: "local", Span: "verified"}
	mustPut(t, b, importer, x)
	if got, _ := b.Index(); got.Coverage() != want {
		t.Errorf("an extracted value changed coverage: %+v", got.Coverage())
	}
}

// A person decides a proposal, and only then is it in the record.
func TestAProposalIsDecidedByAPerson(t *testing.T) {
	b := newBench(t)
	scope := Scope{Name: "group", Title: "The group", Domains: []Domain{"identity", "cloud"},
		// A proposer cannot approve its own proposal: whatever it sends
		// here is replaced by the accepter's.
		Approval: signedBy(owner, "a0000000000000000000000000000009")}
	if _, err := b.Propose(model, "a draft scope", scope, control("AC-02")); err != nil {
		t.Fatal(err)
	}
	b.clock.forward(time.Minute)
	if _, err := b.Propose(dana, "dana's draft", control("AC-03")); err != nil {
		t.Fatal(err)
	}
	waiting, err := b.Proposals()
	if err != nil || len(waiting) != 3 {
		t.Fatalf("%d proposals are waiting (%v)", len(waiting), err)
	}
	if waiting[2].Subject != dana.Subject || waiting[2].Agent != "" || waiting[0].Agent != "control-tester" || waiting[0].Why != "a draft scope" {
		t.Errorf("the proposals say who proposed them as %+v", waiting)
	}
	scopeID, c2, c3 := mustID(t, scope), mustID(t, control("AC-02")), mustID(t, control("AC-03"))

	// Not by a model, not by a service, not by whoever proposed it, and
	// not by somebody without the permission.
	if _, err := b.Accept(model, c2, nil); !errors.Is(err, ErrModel) {
		t.Errorf("a model accepting a proposal was answered %v", err)
	}
	if err := b.Reject(importer, c2); !errors.Is(err, ErrModel) {
		t.Errorf("a service rejecting a proposal was answered %v", err)
	}
	if _, err := b.Accept(dana, c3, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("dana accepting her own proposal was answered %v", err)
	}
	noApprove := lee
	noApprove.May = func(act auth.Action, resource string) error {
		if act == auth.ActApprove {
			return deny(act, resource)
		}
		return nil
	}
	if _, err := b.Accept(noApprove, c2, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("somebody who may not approve was answered %v", err)
	}
	if b.Head() != "" {
		t.Fatal("a refused decision wrote the record")
	}

	// A decision is accepted with the accepter's approval, never the
	// proposer's.
	if _, err := b.Accept(lee, scopeID, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("a scope accepted with no approval was answered %v", err)
	}
	mine := signedBy(owner, lee.Subject)
	waited := scope
	waited.Approval = nil
	mine.Surface = shown(t, b, waited)
	rc, err := b.Accept(lee, scopeID, mine)
	if err != nil || rc.Ref != Ref || len(rc.Written) != 1 {
		t.Fatalf("accepting the scope was answered %+v, %v", rc, err)
	}
	got, err := b.Get(scopeID)
	if err != nil || got.Record.(Scope).Approval.Signers[0].Subject != lee.Subject {
		t.Errorf("the accepted scope is %+v (%v)", got.Record, err)
	}
	// An approver who holds approve and not edit accepts all the same:
	// approving is what was asked.
	approveOnly := lee
	approveOnly.May = func(act auth.Action, resource string) error {
		if act != auth.ActApprove {
			return deny(act, resource)
		}
		return nil
	}
	if _, err := b.Accept(approveOnly, c3, nil); err != nil {
		t.Errorf("an approver without edit could not accept: %v", err)
	}
	if err := b.Reject(lee, c2); err != nil {
		t.Fatal(err)
	}
	if left, _ := b.Proposals(); len(left) != 0 {
		t.Errorf("%d proposals are still waiting after each was decided", len(left))
	}
	if _, err := b.Get(c2); !errors.Is(err, ErrNotFound) {
		t.Error("a rejected proposal is in the record")
	}
	if err := b.Reject(lee, c2); !errors.Is(err, ErrNotFound) {
		t.Errorf("deciding a proposal twice was answered %v", err)
	}
	var decided []string
	for _, e := range b.log {
		if e.Action == DecideAction && e.Outcome == audit.Success {
			decided = append(decided, e.Detail["decision"])
		}
	}
	if strings.Join(decided, " ") != "accepted accepted rejected" {
		t.Errorf("the decisions were recorded as %v", decided)
	}
}
