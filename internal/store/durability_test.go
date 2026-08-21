package store

import (
	"fmt"
	"os"
	"testing"
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
	// Counted, not timed.
	//
	// This used to write two thousand records two ways and assert that the
	// batched run was at least twice as fast. The claim in the name is about
	// how many fsyncs happen, and a throughput ratio is a poor instrument for
	// it: on a loaded machine both runs slow down unevenly and the ratio
	// wobbles. It failed at 1.9x in a full-suite run and passed three times in
	// a row on its own, which is the worst kind of test — one that teaches
	// people to re-run rather than to read.
	//
	// So it counts the flushes directly. That is deterministic, it is what the
	// comment above always said the measurement was about, and it runs in
	// milliseconds rather than a minute.
	syncs := func(perCommit int) (allFlushes, fileFlushes int) {
		s := newStore(t)

		// Files and directories counted apart.
		//
		// Both go through the seam, and a single total cannot tell them apart:
		// a sabotage that routed the per-object flush around syncFile left the
		// directory flushes counting and the total still looked healthy. The
		// invariant worth asserting is that every object written was flushed
		// through here, and that is a statement about regular files.
		var nFiles, nDirs int
		restore := syncFile
		syncFile = func(f *os.File) error {
			if st, err := f.Stat(); err == nil && st.IsDir() {
				nDirs++
			} else {
				nFiles++
			}
			return restore(f)
		}
		defer func() { syncFile = restore }()

		const total = 200
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
		return nFiles + nDirs, nFiles
	}

	one, oneFiles := syncs(1)
	batched, batchedFiles := syncs(200)
	t.Logf("  one record per commit: %d fsync(s) (%d on files) for 200 records",
		one, oneFiles)
	t.Logf("  200 per commit:        %d fsync(s) (%d on files) for 200 records",
		batched, batchedFiles)

	// Tied to the work, not merely non-zero.
	//
	// A "> 0" check passed a sabotage that routed the per-object flush around
	// the seam: the directory flushes still counted, so the number stayed
	// large and the ratio still held. Two hundred records cannot be committed
	// one at a time with fewer than two hundred object flushes, so anything
	// below that means a sync path is no longer going through syncFile and
	// this test is measuring a fraction of the truth.
	const records = 200
	if oneFiles < records {
		t.Fatalf("counted %d file flushes for %d records committed one at a "+
			"time. Every record is a distinct object and every object is "+
			"flushed, so a path is bypassing syncFile and this test is "+
			"measuring a fraction of the truth", oneFiles, records)
	}
	if batchedFiles < records {
		t.Fatalf("counted %d file flushes in the batched run for %d records; "+
			"batching changes when objects are flushed, never whether",
			batchedFiles, records)
	}

	// The point: batching amortises the tree and ref writes across the records
	// in a commit. It does nothing about the one flush each object still pays,
	// so the gain is a factor of a few and not the hundred a naive reading of
	// "fsync is slow" would predict.
	//
	// Dropping the per-object flush is a real option — it is what git does by
	// default, and this store can detect the damage because an object's name
	// is the hash of its content, so `quilzo verify` finds a partial write
	// rather than trusting it. That is a durability trade with a security
	// argument attached and it deserves its own change.
	if batched >= one {
		t.Errorf("batching cost %d flushes against %d unbatched; the tree and "+
			"ref writes are supposed to amortise across the records in a "+
			"commit", batched, one)
	}
	if ratio := float64(one) / float64(batched); ratio < 2 {
		t.Errorf("batching saved only %.1fx the flushes (%d -> %d)",
			ratio, one, batched)
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
