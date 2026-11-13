// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package logd

import (
	"fmt"
	"io/fs"
	"syscall"
)

// Who owns the log, asked the POSIX way.
//
// The check that matters: if the account running the CMS also owns the log
// file, it can rewrite the log directly and the socket in front of it is a
// formality that account can bypass. That is a uid comparison, and uid is a
// POSIX concept — see owner_windows.go for what is said instead where there
// is no such number.
func checkOwner(info fs.FileInfo, logPath string, cmsUID int) (bool, string) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, "this platform does not report file ownership"
	}
	if int(st.Uid) == cmsUID {
		return false, fmt.Sprintf(
			"%s is owned by the same account that runs the CMS (uid %d), so "+
				"that account can rewrite it directly and the socket is a "+
				"formality it can bypass", logPath, cmsUID)
	}
	return true, fmt.Sprintf(
		"%s is owned by uid %d, which is not the account running the CMS",
		logPath, st.Uid)
}

// keyHeldByOthers says why the key info describes may be in hands other
// than uid's: another account owns it, or its mode lets others read it.
// Empty when it is uid's alone.
func keyHeldByOthers(info fs.FileInfo, path string, uid int) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("this platform does not report who owns %s", path)
	}
	if int(st.Uid) != uid {
		return fmt.Sprintf("%s belongs to uid %d, not this account (uid %d), and the account that "+
			"made a key may have kept a copy of it", path, st.Uid, uid)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("%s can be read by accounts other than this one (mode %04o), and any of "+
			"them may have kept a copy of it", path, perm)
	}
	return ""
}
