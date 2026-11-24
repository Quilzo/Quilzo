// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package logd

import (
	"fmt"
	"net"
)

// peerCreds has no portable answer, so this one refuses.
//
// The separation this package provides rests on knowing which account
// connected, and knowing it from the kernel rather than from the client. On a
// platform where that cannot be asked, the honest answer is that the guarantee
// is unavailable — not a uid of -1 that a caller might compare against
// something and let through.
//
// Failing closed here means a writer told which accounts may submit
// (--allow-uid) refuses every connection on macOS, because it cannot tell
// them from any other (Server.handle), and so does one told which may ask
// for a signature (--sign-uid, --sign-gid); without a list the account does
// not matter, and it runs as it does anywhere. That is the correct outcome:
// it is a production separation-of-duty control for a Linux server, and a
// version of it that cannot identify its callers would be the appearance of
// the control without the control. Everything else in the program builds
// and runs, which is what makes a Mac usable for development.
func peerCreds(conn net.Conn) (uid, gid int, err error) {
	return -1, -1, fmt.Errorf(
		"the identity of a socket's peer can only be read from the kernel on " +
			"Linux, and this control is worth nothing without it; run the log " +
			"writer on the Linux host that keeps the log")
}
