// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// systemReads are what a confined program reads to start and to run: the
// system's libraries and programs, and of /etc what a C library and the
// common runtimes read there, never the directory itself.
//
// The whole of /etc was granted so that a C library could start, and a
// confined program's /etc is the host's, read as the account that started
// it. Quilzo run as root, which is how an init system starts a single
// binary unless told otherwise, let an agent holding shell_run and the
// program head read /etc/shadow, and let an extension read it too. So /etc
// is named file by file: an allow-list, for the reason Rules gives, since a
// file a runtime turns out to need is a bug report and a credential store
// nobody thought to leave out is not.
//
// A name with a * in it is a pattern for the versions a runtime keeps its
// settings under, expanded where it runs.
var systemReads = []string{
	"/usr", "/lib", "/lib64", "/bin", "/sbin",
	// The dynamic loader's cache and what it is built from.
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.preload",
	// Names: the accounts and groups (never their passwords), hosts, the
	// resolver, services and protocols.
	"/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/host.conf", "/etc/hostname",
	"/etc/resolv.conf", "/etc/gai.conf", "/etc/services", "/etc/protocols", "/etc/networks", "/etc/netconfig",
	"/etc/rpc",
	// Time and language.
	"/etc/localtime", "/etc/timezone", "/etc/locale.alias", "/etc/locale.conf", "/etc/default/locale",
	// The certificates a TLS client trusts and its libraries' settings,
	// and not the private keys kept beside them.
	"/etc/ssl/certs", "/etc/ssl/cert.pem", "/etc/ssl/openssl.cnf", "/etc/ca-certificates",
	"/etc/ca-certificates.conf", "/etc/pki/tls/certs", "/etc/pki/tls/cert.pem", "/etc/pki/tls/openssl.cnf",
	"/etc/pki/ca-trust", "/etc/crypto-policies", "/etc/gnutls",
	// What the system is, what kind a file is, and the links Debian's
	// alternatives make to the programs under /usr.
	"/etc/os-release", "/etc/lsb-release", "/etc/debian_version", "/etc/alpine-release", "/etc/redhat-release",
	"/etc/system-release", "/etc/mime.types", "/etc/magic", "/etc/magic.mime", "/etc/alternatives",
	"/etc/gitconfig",
	// Fonts and terminals, and the runtimes' own settings: a browser draws
	// text, and Java starts no TLS without its security file.
	"/etc/fonts", "/etc/terminfo", "/etc/chromium", "/etc/chromium.d", "/etc/java-*", "/etc/python3*",
	"/etc/perl", "/etc/ImageMagick-*",
}

// SystemReads are the system paths every confined program may read, as
// named, each pattern expanded on this machine: for a policy another
// machine enforces, which has its own idea of which of them exist.
func SystemReads() []string {
	var out []string
	for _, p := range systemReads {
		if !strings.Contains(p, "*") {
			out = append(out, p)
			continue
		}
		matches, _ := filepath.Glob(p)
		out = append(out, matches...)
	}
	return out
}

// SystemReadsHere are SystemReads less what this machine does not have, as
// a ruleset enforced here needs them: Landlock opens every path it is
// given, and one that is not there fails the whole ruleset.
func SystemReadsHere() []string {
	var out []string
	for _, p := range SystemReads() {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// SystemReadCovers reports whether a path lies where SystemReads grants
// reading it. The path should be absolute with its links resolved.
func SystemReadCovers(path string) bool {
	for _, p := range systemReads {
		if strings.Contains(p, "*") {
			if ok, _ := filepath.Match(p, path); ok {
				return true
			}
			// Beneath a directory a pattern names.
			for dir := filepath.Dir(path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
				if ok, _ := filepath.Match(p, dir); ok {
					return true
				}
			}
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
