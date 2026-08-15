package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// A ref moves by compare-and-swap, holding a lock that other processes see.
//
// The mutex on Store is not enough, and the reason is worth stating because it
// determines the shape of everything here. Publishing, saving a draft and
// rolling back all read a ref, decide something from what they read, and then
// write. Between the read and the write another writer can land, and the
// second write silently discards the first — the lost update that If-Match,
// --based-on and the four-eyes review all exist to prevent, defeated
// underneath all three by the store not offering the operation they assume it
// has.
//
// It has to be a file lock rather than a mutex because the CLI, the admin
// interface and the content API are three processes against one store, which
// is a normal way to run this. A mutex makes each process internally
// consistent and leaves them inconsistent with each other, which is the worst
// of the options: it passes a concurrency test and fails in deployment.
//
// flock is released by the kernel when the descriptor closes, including when
// the process dies, so a crash mid-write cannot leave the store wedged.

func (s *Store) lockFile() (*os.File, error) {
	path := filepath.Join(s.root, "refs.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the ref lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot lock refs: %w", err)
	}
	return f, nil
}

func (s *Store) unlock(f *os.File) {
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

// WithRefLock runs fn with every ref in this store held exclusively.
//
// For callers that must read a ref, decide, and write, all without another
// writer landing in between. GetRef and SetRef inside fn are safe; calling
// WithRefLock inside fn is not, because flock on a second descriptor in the
// same process does not block on the first — it would deadlock in another
// process and silently succeed here, which is the worse failure.
func (s *Store) WithRefLock(fn func() error) error {
	f, err := s.lockFile()
	if err != nil {
		return err
	}
	defer s.unlock(f)
	return fn()
}

// CompareAndSwapRef points name at next, but only if it currently points at
// prev. An empty prev means the ref must not exist yet.
//
// The error says what it found, not merely that it failed, because the caller
// has to tell "somebody else wrote" from "the store is broken" and they need
// different responses.
func (s *Store) CompareAndSwapRef(name, prev, next string) error {
	f, err := s.lockFile()
	if err != nil {
		return err
	}
	defer s.unlock(f)

	if got := s.GetRef(name); got != prev {
		return &RefMoved{Ref: name, Expected: prev, Found: got}
	}
	return s.SetRef(name, next)
}

// RefMoved reports a compare-and-swap that found something other than what the
// caller expected.
type RefMoved struct {
	Ref      string
	Expected string
	Found    string
}

func (e *RefMoved) Error() string {
	short := func(s string) string {
		if s == "" {
			return "nothing"
		}
		if len(s) > 12 {
			return s[:12]
		}
		return s
	}
	return fmt.Sprintf("%s moved while this write was in flight: expected %s, "+
		"found %s", e.Ref, short(e.Expected), short(e.Found))
}
