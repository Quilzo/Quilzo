// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
