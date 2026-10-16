// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentbox

import (
	"io"
	"net"
	"strings"
)

// systemReads are what any program needs to start: the system's libraries
// and programs, and what a C library reads from /etc.
var systemReads = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"}

// EveryBoxReads says whether a path lies where every box can read it. A file
// kept there — an evaluator's cases, a key — is readable by any program a
// box runs, whatever that box was meant to see. The path should be
// absolute with its links resolved.
func EveryBoxReads(path string) bool {
	for _, dir := range systemReads {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

// forward joins each connection to a port in the box to the service's
// socket outside.
func forward(ln net.Listener, socket string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			u, err := net.Dial("unix", socket)
			if err != nil {
				return
			}
			defer u.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(u, c); closeWrite(u); done <- struct{}{} }()
			go func() { _, _ = io.Copy(c, u); closeWrite(c); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}
