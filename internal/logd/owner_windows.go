//go:build windows

package logd

import (
	"fmt"
	"io/fs"
)

// Windows has no uid, so the question this asks cannot be answered the same
// way.
//
// It is answered honestly instead: unknown, and said out loud. The alternative
// — returning true because nothing contradicted it — would report a separation
// of duties that nobody has established, which is the failure mode this whole
// check exists to prevent. Windows expresses the same idea through ACLs and
// SIDs, and reading those properly is a different piece of work from renaming
// a field.
func checkOwner(_ fs.FileInfo, logPath string, _ int) (bool, string) {
	return false, fmt.Sprintf(
		"this build cannot tell who owns %s: Windows expresses ownership "+
			"through ACLs rather than a uid, and reporting separation of "+
			"duties that has not been checked would be worse than saying so",
		logPath)
}
