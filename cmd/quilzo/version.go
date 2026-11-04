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
// ldflags is the variable as the linker left it: anything but "dev" or
// nothing was set on purpose and wins. read is debug.ReadBuildInfo, a parameter so a test
// can be a `go install` without running one.
func moduleVersion(ldflags string, read func() (*debug.BuildInfo, bool)) string {
	// Empty is what `--build-arg VERSION=` with nothing after it makes of
	// -X main.version=, and a binary that answers "quilzo " to --version has
	// no version rather than an empty one.
	if ldflags != "dev" && ldflags != "" {
		return ldflags
	}
	if bi, ok := read(); ok && bi != nil && isReleaseTag(bi.Main.Version) {
		return bi.Main.Version
	}
	return "dev"
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

// selfIdentity is what `quilzo self verify` knows this build by: its
// version, and for a build with none, the commit it was built from.
//
// "dev" alone names no build. Every build from a working tree says it, so
// the next one had other bytes under the same name and was reported as this
// one rebuilt or patched in place: self verify exited 1 on every upgrade
// between two of them. A clean commit names a build as a version does, and
// two builds of it differ only by being built differently. Uncommitted
// changes name nothing, and neither does a build with no commit recorded --
// an image is one, because .git is not in its context -- so those stay
// "dev", which Verify does not compare.
func selfIdentity(v string, read func() (*debug.BuildInfo, bool)) string {
	if v != "dev" {
		return v
	}
	bi, ok := read()
	if !ok || bi == nil {
		return v
	}
	rev, modified := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev == "" || modified {
		return v
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return v + "+" + rev
}
