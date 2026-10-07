// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"io"
	"net"
)

// systemReads are what any program needs to start: the system's libraries
// and programs, and what a C library reads from /etc.
var systemReads = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"}

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
