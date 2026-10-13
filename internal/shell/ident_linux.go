// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"io/fs"
	"syscall"
)

// ident is a file's inode and status-change time: a command can set a
// file's modification time back, and cannot set these.
func ident(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)<<20 ^ uint64(st.Ctim.Nano())
	}
	return 0
}
