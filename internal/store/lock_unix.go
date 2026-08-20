//go:build !windows

package store

import (
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

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
