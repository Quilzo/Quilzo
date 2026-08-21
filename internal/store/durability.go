package store

import (
	"os"
	"path/filepath"
)

// syncFile is the one place this package flushes to disk.
//
// A variable rather than a direct f.Sync() call, so a test can count the
// flushes instead of timing them. That distinction matters here: the claim
// this package makes is that the durability floor is per *commit* and not per
// record, which is a statement about how many fsyncs happen. It was being
// checked by measuring throughput and asserting a ratio, and a throughput
// ratio on a loaded machine is a coin toss -- it failed in a full-suite run
// and passed three times in a row on its own.
//
// Production behaviour is unchanged: this is f.Sync().
var syncFile = func(f *os.File) error { return f.Sync() }

// Group commit: one flush per commit rather than one per object.
//
// Every object write ended with fsync, and a nested write touches about six
// objects — a blob, the trees along its path, and the ref — so a single edit
// paid six round trips to the disk. That was the whole of the 14.5ms left
// after the tree work: not computation, but waiting.
//
// The fix is the one every database uses, and content-addressing makes it
// unusually easy to argue for. Objects are immutable and named by the hash of
// what is in them, so an object that reached the disk without being flushed,
// whose ref never became durable either, is garbage that nothing points at.
// It is not corruption. The only ordering that has to hold is:
//
//	everything a ref reaches is durable *before* the ref is.
//
// Which is exactly what Flush and SetRef do between them. Break that order and
// a crash leaves a ref pointing at an object that is not there — a store that
// verifies as broken rather than as incomplete, which is much worse than the
// few objects group commit risks losing.
//
// This is git's model too: loose objects are not fsynced by default, because
// an unreferenced one costs nothing.

// Durability chooses how hard the store works to survive a power cut.
type Durability int

const (
	// SyncOnCommit flushes every object once, before the ref that reaches
	// them moves. The default: one flush per commit rather than per object.
	SyncOnCommit Durability = iota
	// SyncEach flushes every object as it is written. Slower by the number of
	// objects a commit touches, and stricter in exactly one case — a crash
	// between two objects of the same commit leaves the earlier ones durable.
	// Since neither is reachable without the ref, that difference does not
	// change what a reader can observe; it is offered for operators whose
	// storage or auditors require it rather than because it is safer.
	SyncEach
)

// SetDurability changes the mode. Not concurrency-safe with writes in flight,
// which is why it is set at open time and not adjusted afterwards.
func (s *Store) SetDurability(d Durability) { s.durability = d }

// Flush makes every object written since the last flush durable.
//
// Files first, then the directories that name them. Both are needed: fsyncing
// a file guarantees its contents, and only fsyncing its directory guarantees
// that the name pointing at those contents survives. A rename that is not
// durable leaves the object under a temporary name, which is the same as it
// not being there.
func (s *Store) Flush() error {
	s.mu.Lock()
	pending := s.pending
	s.pending = nil
	s.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}
	dirs := map[string]bool{}
	for path := range pending {
		f, err := os.Open(path)
		if err != nil {
			// Written and then removed, or never created because the object
			// already existed. Neither is a failure: the invariant is about
			// what a ref can reach, and an object that is not there was not
			// written by this commit.
			continue
		}
		err = syncFile(f)
		f.Close()
		if err != nil {
			return err
		}
		dirs[filepath.Dir(path)] = true
	}
	for dir := range dirs {
		d, err := os.Open(dir)
		if err != nil {
			continue
		}
		err = syncFile(d)
		d.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
