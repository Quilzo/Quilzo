// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package atomicfile

import (
	"errors"
	"os"
	"syscall"
)

// Whole-descriptor advisory locking, the POSIX way.
//
// flock is released by the kernel when the descriptor closes, including when
// the process dies, so a crash mid-write cannot leave the store wedged. That
// property is what the ref lock relies on, and it is why the Windows version
// beside this one had to be written carefully rather than approximated: the
// two APIs differ in exactly that respect.
func lockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// tryLock takes the lock if nobody holds it, and reports whether it did.
func tryLock(f *os.File) (bool, error) {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, syscall.EWOULDBLOCK):
			return false, nil
		case !errors.Is(err, syscall.EINTR):
			return false, err
		}
	}
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
