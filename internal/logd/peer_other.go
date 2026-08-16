//go:build !linux

package logd

import (
	"fmt"
	"net"
)

// peerUID has no portable answer, so this one refuses.
//
// The separation this package provides rests on knowing which account
// connected, and knowing it from the kernel rather than from the client. On a
// platform where that cannot be asked, the honest answer is that the guarantee
// is unavailable — not a uid of -1 that a caller might compare against
// something and let through.
//
// Failing closed here means the log writer does not run on macOS. That is the
// correct outcome: it is a production separation-of-duty control for a Linux
// server, and a version of it that cannot identify its callers would be the
// appearance of the control without the control. Everything else in the
// program builds and runs, which is what makes a Mac usable for development.
func peerUID(conn net.Conn) (int, error) {
	return -1, fmt.Errorf(
		"the identity of a socket's peer can only be read from the kernel on " +
			"Linux, and this control is worth nothing without it; run the log " +
			"writer on the Linux host that keeps the log")
}
