// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package out

import (
	"os"
	"syscall"
)

// isTTY is whether f is a console. The NUL device is a character device as
// a console is, and only a console has a console mode to read.
func isTTY(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	tty := false
	_ = rc.Control(func(fd uintptr) {
		var mode uint32
		tty = syscall.GetConsoleMode(syscall.Handle(fd), &mode) == nil
	})
	return tty
}
