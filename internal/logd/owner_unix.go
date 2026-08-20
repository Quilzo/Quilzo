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
