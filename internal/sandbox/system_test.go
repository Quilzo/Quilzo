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

// A runtime's settings are read whichever version of it a box has, here or
// in the image of a sandbox somewhere else.
//
// The settings of the runtimes that keep them under a version (Java's
// security file, Python's, ImageMagick's) were named by a pattern, and the
// pattern was expanded on this machine. A policy another machine enforces,
// OpenShell's, then named this machine's versions and not the image's, so a
// program in an image with another Java than this machine's could not read
// its security file, which the whole of /etc had let it read. And Fedora's
// and RHEL's Java keep that file under /etc/java, which nothing named.
func TestARuntimesSettingsAreReadWhicheverVersionItIs(t *testing.T) {
	named := map[string]bool{}
	for _, p := range SystemReads() {
		named[p] = true
	}
	for _, p := range []string{"/etc/java-8-openjdk", "/etc/java-17-openjdk", "/etc/java-25-openjdk",
		"/etc/python3", "/etc/python3.9", "/etc/python3.14", "/etc/ImageMagick-6", "/etc/ImageMagick-7"} {
		if !named[p] {
			t.Errorf("a policy for another machine does not name %s", p)
		}
	}
	if !SystemReadCovers("/etc/java/java-17-openjdk/java-17-openjdk-17.0.9.0.9-3.fc39.x86_64/conf/security/java.security") {
		t.Error("Java's security file where Fedora keeps it is not read")
	}
}
