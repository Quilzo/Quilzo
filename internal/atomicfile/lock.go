// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// Lock takes an exclusive lock on path for a read-decide-write sequence
// across processes, and returns what releases it.
//
// The lock belongs to an open descriptor (flock, or LockFileEx on Windows),
// so the kernel releases it when the holder closes it or dies. There is no
// lock file to go stale, no age after which another process may take it
// over, and so no moment at which two processes both hold it: the race the
// create-exclusive lock file it replaces had, where two processes found it
// stale together and one deleted the other's live lock.
//
// A lock another process holds is waited for as the WaitPolicy says.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the lock %s: %w", path, err)
	}
	if err := lockWaiting(f, path); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot take the lock %s: %w", path, err)
	}
	return func() {
		unlockFile(f)
		f.Close()
	}, nil
}

// LockFile takes the same exclusive lock on a file the caller has opened
// itself, waiting for it as Lock does, and UnlockFile lets it go.
//
// They are for a caller that keeps the descriptor, as the store's ref lock
// does. The store had its own copy of the two system calls, line for line,
// and a fix to one copy (the byte range Windows locks, a retry when the
// call is interrupted) would have reached the other only by somebody
// remembering it. One lock means one place to get it right.
func LockFile(f *os.File) error { return lockWaiting(f, f.Name()) }

// UnlockFile releases what LockFile took. Closing the file releases it too.
func UnlockFile(f *os.File) { unlockFile(f) }

// WaitPolicy is how a lock another process holds is waited for.
//
// It waited without a word and without end. A quilzo stopped with Ctrl-Z in
// another terminal, or stuck on a hung network disk, holds the store's lock
// for as long as it is stopped, and every write behind it hung silently: a
// cron job queued up invisibly, and a person at the terminal could not tell
// a hang from a slow command. So the wait can be said, and bounded.
//
// The zero policy is the old wait, silent and for as long as it takes,
// which is right for a server: its dispatchers hold their locks for as long
// as they run, so a second server on the store waits its turn.
type WaitPolicy struct {
	// Notice is told the lock's path, once, when the wait has gone on for
	// NoticeAfter.
	Notice func(path string)
	// Patience is how long to wait before giving up with a HeldError;
	// zero waits for as long as it takes.
	Patience time.Duration
}

// NoticeAfter is how long a wait goes on before it is said: long enough
// that two writers taking turns are not announced, short enough that a
// person is told before they wonder.
const NoticeAfter = time.Second

var waitPolicy atomic.Pointer[WaitPolicy]

// SetWaitPolicy sets how every lock this process takes is waited for.
func SetWaitPolicy(p WaitPolicy) { waitPolicy.Store(&p) }

// HeldError is a lock that another process held for longer than the
// policy's patience.
type HeldError struct {
	Path   string
	Waited time.Duration
}

func (e *HeldError) Error() string {
	return fmt.Sprintf("another process has held %s for %s; if a quilzo is stopped (Ctrl-Z) or stuck, "+
		"end it and try again, or wait longer with QUILZO_LOCK_WAIT", e.Path, e.Waited)
}

// lockWaiting takes the lock at once if it is free, and otherwise waits
// for it as the policy says, trying again with a growing pause between
// tries: a lock taken without blocking is the only kind a wait can be
// given up on.
func lockWaiting(f *os.File, path string) error {
	free, err := tryLock(f)
	if err != nil || free {
		return err
	}
	p := WaitPolicy{}
	if set := waitPolicy.Load(); set != nil {
		p = *set
	}
	if p.Notice == nil && p.Patience <= 0 {
		return lockExclusive(f)
	}
	start := time.Now()
	noticed := p.Notice == nil
	for pause := 5 * time.Millisecond; ; pause = min(2*pause, 200*time.Millisecond) {
		waited := time.Since(start)
		if !noticed && waited >= NoticeAfter {
			p.Notice(path)
			noticed = true
			if p.Patience <= 0 {
				return lockExclusive(f)
			}
		}
		if p.Patience > 0 && waited >= p.Patience {
			return &HeldError{Path: path, Waited: p.Patience}
		}
		time.Sleep(pause)
		if free, err := tryLock(f); err != nil || free {
			return err
		}
	}
}
