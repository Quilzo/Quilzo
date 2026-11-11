// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"fmt"
	"os"
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
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the lock %s: %w", path, err)
	}
	if err := lockExclusive(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot take the lock %s: %w", path, err)
	}
	return func() {
		unlockFile(f)
		f.Close()
	}, nil
}

// LockFile takes the same exclusive lock on a file the caller has opened
// itself, blocking until it has it, and UnlockFile lets it go.
//
// They are for a caller that keeps the descriptor, as the store's ref lock
// does. The store had its own copy of the two system calls, line for line,
// and a fix to one copy (the byte range Windows locks, a retry when the
// call is interrupted) would have reached the other only by somebody
// remembering it. One lock means one place to get it right.
func LockFile(f *os.File) error { return lockExclusive(f) }

// UnlockFile releases what LockFile took. Closing the file releases it too.
func UnlockFile(f *os.File) { unlockFile(f) }
