//go:build windows

package store

import (
	"os"
	"syscall"
	"unsafe"
)

// The ref lock on Windows, which is a different shape from flock.
//
// # Why this exists rather than a build that skips the lock
//
// The store takes an exclusive lock around the read-decide-write sequence that
// moves a ref. Without it two concurrent writers both read the same parent
// commit and one edit disappears — silently, with no error and no conflict.
// A Windows build without the lock would lose writes rather than fail to
// build, which is the worse of the two.
//
// # LockFileEx, and the two differences that matter
//
// flock locks a whole descriptor; LockFileEx locks a byte range. So this locks
// the same one byte every time — the range is arbitrary, but it has to be the
// same arbitrary range in every process or two writers lock different bytes
// and both proceed.
//
// The second difference is the one to be careful about: flock is released by
// the kernel when the descriptor closes, including on a crash, so a dead
// process cannot wedge the store. Windows also releases file locks when the
// handle closes and when the process terminates, which is the property relied
// on here — but it is worth stating, because the natural assumption is that a
// Windows lock is a lease that can outlive its owner. It is not.
//
// # No dependency
//
// golang.org/x/sys/windows has these calls. This project's whole argument is
// that it has no require block, so kernel32 is reached through the standard
// library's lazy-DLL loading instead. It is more code and it is the same
// syscall.

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	procLockFile = kernel32.NewProc("LockFileEx")
	procUnlock   = kernel32.NewProc("UnlockFileEx")
)

const (
	// Block until the lock is available, which is what flock's LOCK_EX does.
	// The alternative — failing immediately — would turn contention into an
	// error that callers would then have to retry, and a retry loop around a
	// lock is a lock nobody is holding correctly.
	lockfileExclusiveLock = 0x00000002
)

// overlapped is the OVERLAPPED structure LockFileEx takes. Declared here
// because the standard library's syscall.Overlapped is available on Windows
// and this is the same layout; using the stdlib type keeps the unsafe.Pointer
// conversion to one that Go already blesses.
func lockExclusive(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procLockFile.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock),
		0, // reserved, must be zero
		1, // bytes to lock, low word
		0, // bytes to lock, high word
		uintptr(unsafe.Pointer(&ol)),
	)
	if r == 0 {
		return err
	}
	return nil
}

func unlockFile(f *os.File) {
	var ol syscall.Overlapped
	_, _, _ = procUnlock.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
}
