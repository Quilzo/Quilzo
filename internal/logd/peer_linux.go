// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logd

import (
	"fmt"
	"net"
	"syscall"
)

// peerCreds reads the connecting account from the kernel: its uid, and the
// group it connected as.
//
// Asked of the kernel rather than of the client, which is the entire point: a
// uid a client tells you is a claim, and a uid SO_PEERCRED returns is a fact
// the client cannot influence. The group is the one the process ran as when
// it connected, which an account with no privilege cannot change to another
// it is merely a member of; that is what lets the writer tell the public
// site from the admin where both are one uid (Server.SignGID).
//
// Linux only, and split into its own file for that reason. It used to sit in
// the package's main file with no build tag, so the whole program failed to
// compile for macOS — which nobody noticed until a release was cross-compiled
// for the first time.
func peerCreds(conn net.Conn) (uid, gid int, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, -1, fmt.Errorf("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return -1, -1, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return -1, -1, err
	}
	if credErr != nil {
		return -1, -1, credErr
	}
	return int(cred.Uid), int(cred.Gid), nil
}
