// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"runtime/debug"
)

// moduleVersion is the version a binary reports: the one a release build
// set, or else the tag Go recorded when it built a tagged module
// (`go install …@v0.3.0`), or else "dev".
//
// Only a tag counts. Since Go 1.24 a build from a working tree records a
// pseudo-version too -- v0.0.0-20261103073633-ad6e16568ba5+dirty -- and that
// names a commit, possibly with uncommitted changes on top, not a release:
// the bill of materials and the site report both treat "dev" as "not a
// release" (internal/compliance/sbom.go, internal/sitereport), and a
// pseudo-version must keep meaning that.
//
// ldflags is the variable as the linker left it: anything but "dev" was set
// on purpose and wins. read is debug.ReadBuildInfo, a parameter so a test
// can be a `go install` without running one.
func moduleVersion(ldflags string, read func() (*debug.BuildInfo, bool)) string {
	if ldflags != "dev" {
		return ldflags
	}
	if bi, ok := read(); ok && bi != nil && isReleaseTag(bi.Main.Version) {
		return bi.Main.Version
	}
	return ldflags
}

var (
	releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
	// A pseudo-version's tail: a UTC timestamp and twelve hex digits of
	// commit, after a hyphen or a dot (golang.org/ref/mod#pseudo-versions).
	pseudoTail = regexp.MustCompile(`[-.]\d{14}-[0-9a-f]{12}$`)
)

func isReleaseTag(v string) bool {
	return releaseTag.MatchString(v) && !pseudoTail.MatchString(v)
}
