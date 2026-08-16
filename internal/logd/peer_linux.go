//go:build linux

package logd

import (
	"fmt"
	"net"
	"syscall"
)

// peerUID reads the connecting account from the kernel.
//
// Asked of the kernel rather than of the client, which is the entire point: a
// uid a client tells you is a claim, and a uid SO_PEERCRED returns is a fact
// the client cannot influence.
//
// Linux only, and split into its own file for that reason. It used to sit in
// the package's main file with no build tag, so the whole program failed to
// compile for macOS — which nobody noticed until a release was cross-compiled
// for the first time.
func peerUID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
