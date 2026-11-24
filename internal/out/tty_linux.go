// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package out

import (
	"os"
	"syscall"
	"unsafe"
)

// isTTY asks the kernel whether f is a terminal, as isatty(3) does: a
// terminal answers TCGETS with its settings, and any other device refuses.
// Through SyscallConn, so asking does not put the file in blocking mode.
func isTTY(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	tty := false
	_ = rc.Control(func(fd uintptr) {
		var t syscall.Termios
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
		tty = errno == 0
	})
	return tty
}
