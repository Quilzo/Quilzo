// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"strings"
	"testing"
)

// What every confined program reads of /etc is what a C library and the
// common runtimes read there, and none of the host's credentials.
//
// The whole of /etc was granted, to the agent box and to extensions alike,
// and a confined program reads it as the account that started it: as root,
// /etc/shadow.
func TestTheSystemReadsLeaveTheHostsCredentialsOut(t *testing.T) {
	for _, p := range []string{"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/sudoers", "/etc/sudoers.d/admins",
		"/etc/ssh/ssh_host_ed25519_key", "/etc/ssl/private/site.key", "/etc/pki/tls/private/site.key",
		"/etc/credstore/token", "/etc/krb5.keytab", "/etc/security/opasswd", "/etc/environment"} {
		if SystemReadCovers(p) {
			t.Errorf("every confined program may read %s", p)
		}
	}
	for _, p := range []string{"/etc/ld.so.cache", "/etc/resolv.conf", "/etc/passwd", "/etc/ssl/certs/ca.pem",
		"/etc/java-21-openjdk/security/java.security", "/etc/python3.12/sitecustomize.py", "/usr/lib/libc.so.6"} {
		if !SystemReadCovers(p) {
			t.Errorf("a confined program may not read %s, which a runtime reads to start", p)
		}
	}
	for _, p := range append(SystemReads(), SystemReadsHere()...) {
		if p == "/etc" || strings.Contains(p, "*") {
			t.Errorf("the system reads name %q", p)
		}
	}
}
