package store

import (
	"fmt"
	"testing"
	"time"
)

// What a durable commit costs, and where the cost actually is.
//
// A bare fsync on this filesystem is 2.5ms, and the same write without one is
// 18µs — a factor of a hundred and forty. A commit touches a blob, the trees
// along its path, the directories, and the ref, so about six of them: roughly
// the 14ms a single-record commit was measured at.
//
// The hypothesis that group commit would fix this was wrong, and the
// measurement said so: deferring the flushes changed when they happened and
// not how many, so it came out a shade slower. The fsync before the rename
// cannot be dropped either — that is what makes the rename atomic, and without
// it a crash leaves a partial file under the final name, which is corruption
// rather than absence.
//
// So the floor is per *commit*, not per record. Which makes the lever obvious
// once it is stated: put more records in each commit. PutNested already takes
// a batch, so this is a matter of using it rather than of building anything.
func TestTheFsyncFloorIsPerCommitNotPerRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("measures disk behaviour")
	}
	rate := func(perCommit int) float64 {
		s := newStore(t)
		const total = 2000
		start := time.Now()
		base := ""
		for written := 0; written < total; written += perCommit {
			var changes []Change
			for i := written; i < written+perCommit && i < total; i++ {
				changes = append(changes, Change{
					Path: fmt.Sprintf("data/t/%02x/%02x/r%d",
						i%256, (i/256)%256, i),
					Value: map[string]any{"n": i},
				})
			}
			next, err := s.PutNested(base, changes)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetRef("live", next); err != nil {
				t.Fatal(err)
			}
			base = next
		}
		return total / time.Since(start).Seconds()
	}

	one, batched := rate(1), rate(500)
	t.Logf("  one record per commit: %.0f records/sec", one)
	t.Logf("  500 per commit:        %.0f records/sec  (%.0fx)",
		batched, batched/one)

	// Three times, not the hundred a per-commit fsync floor would predict.
	//
	// Measured rather than assumed, and the number says where the cost really
	// is: batching amortises the *tree and ref* writes across the records in a
	// commit, and does nothing about the one fsync each object still pays.
	// Five hundred records in a commit is five hundred object flushes however
	// they are grouped.
	//
	// Dropping those is a real option — it is what git does by default, and
	// this store can detect the damage because an object's name is the hash of
	// its content, so `scrivet verify` finds a partial write rather than
	// trusting it. That is a durability trade with a security argument
	// attached and it deserves its own change, not a footnote in this one.
	if batched < one*2 {
		t.Errorf("batching gained only %.1fx; the tree and ref writes are "+
			"supposed to amortise across the records in a commit", batched/one)
	}
}

// -- the ordering that must hold ---------------------------------------------

// Everything a ref reaches must be durable before the ref is. Reverse it and a
// crash leaves a ref pointing at an object that is not there, which verifies
// as broken rather than as incomplete — much worse than losing an object
// nothing points at.
func TestARefIsNeverDurableBeforeWhatItReaches(t *testing.T) {
	s := newStore(t)
	base, err := s.PutNested("", []Change{
		{Path: "data/t/aa/bb/r1", Value: map[string]any{"n": 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Objects are pending at this point, by design.
	s.mu.Lock()
	pendingBefore := len(s.pending)
	s.mu.Unlock()
	if pendingBefore == 0 {
		t.Fatal("nothing was deferred, so group commit is not happening")
	}

	if err := s.SetRef("live", base); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	pendingAfter := len(s.pending)
	s.mu.Unlock()
	if pendingAfter != 0 {
		t.Errorf("%d objects were still unflushed after a ref moved to them",
			pendingAfter)
	}
}

// Both modes must produce identical stores. Durability is about when bytes
// reach the disk, never about which bytes.
func TestDurabilityDoesNotChangeWhatIsStored(t *testing.T) {
	ids := map[Durability]string{}
	for _, d := range []Durability{SyncEach, SyncOnCommit} {
		s := newStore(t)
		s.SetDurability(d)
		oid, err := s.PutNested("", []Change{
			{Path: "data/t/aa/bb/r1", Value: map[string]any{"n": 1}},
			{Path: "pages/index", Value: map[string]any{"title": "Home"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetRef("live", oid); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetNested(oid)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("%v produced %d entries", d, len(got))
		}
		ids[d] = oid
	}
	if ids[SyncEach] != ids[SyncOnCommit] {
		t.Errorf("the two modes produced different trees: %s vs %s",
			ids[SyncEach], ids[SyncOnCommit])
	}
}

// Flushing twice, or with nothing pending, must be harmless — a caller should
// not have to track whether it already did.
func TestFlushIsIdempotent(t *testing.T) {
	s := newStore(t)
	if err := s.Flush(); err != nil {
		t.Fatalf("flushing an untouched store failed: %v", err)
	}
	if _, err := s.PutBlob(map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Flush(); err != nil {
			t.Fatalf("flush %d failed: %v", i, err)
		}
	}
}
