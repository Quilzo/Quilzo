// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime/debug"
	"testing"
)

// A binary from `go install …@v0.3.0` says v0.3.0. It said "dev": the
// version came only from -ldflags, which `go install` does not pass, while
// the module version was in the binary's own build information.
func TestAGoInstalledBinaryKnowsItsVersion(t *testing.T) {
	installed := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Path: "github.com/quilzo/quilzo", Version: "v0.3.0"}}, true
	}
	working := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Path: "github.com/quilzo/quilzo", Version: "(devel)"}}, true
	}
	none := func() (*debug.BuildInfo, bool) { return nil, false }
	tagged := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "github.com/quilzo/quilzo", Version: v}}, true
		}
	}

	for _, c := range []struct {
		name, ldflags string
		read          func() (*debug.BuildInfo, bool)
		want          string
	}{
		{"go install of a tag", "dev", installed, "v0.3.0"},
		{"a release build's flag wins", "v0.3.1", installed, "v0.3.1"},
		{"a working tree says dev, not (devel)", "dev", working, "dev"},
		{"no build information", "dev", none, "dev"},
		{"a release candidate tag", "dev", tagged("v0.3.0-rc.1"), "v0.3.0-rc.1"},
		{"a working tree's pseudo-version is not a release", "dev", tagged("v0.0.0-20261103073633-ad6e16568ba5+dirty"), "dev"},
		{"a clean pseudo-version is not a release", "dev", tagged("v0.0.0-20261103073633-ad6e16568ba5"), "dev"},
		{"a pseudo-version after a tag is not a release", "dev", tagged("v0.3.1-0.20261103073633-ad6e16568ba5"), "dev"},
		// `--build-arg VERSION=` with nothing after it reaches the linker as
		// -X main.version= and set the version to nothing at all.
		{"an empty flag is no version", "", working, "dev"},
		{"an empty flag leaves a go install its tag", "", installed, "v0.3.0"},
	} {
		if got := moduleVersion(c.ldflags, c.read); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Finding STACK-F9. Two builds from working trees both say "dev", so
// `quilzo self verify` took the second for the first patched in place and
// exited 1 on every upgrade. A build that records a clean commit is known
// by it; one that records none, or uncommitted changes, is known by nothing.
func TestSelfVerifyKnowsADevBuildByItsCommit(t *testing.T) {
	built := func(settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "github.com/quilzo/quilzo", Version: "(devel)"},
				Settings: settings}, true
		}
	}
	rev := debug.BuildSetting{Key: "vcs.revision", Value: "ad6e16568ba5c0ffee0123456789abcdef012345"}
	clean := debug.BuildSetting{Key: "vcs.modified", Value: "false"}
	dirty := debug.BuildSetting{Key: "vcs.modified", Value: "true"}
	for _, c := range []struct {
		name, version string
		read          func() (*debug.BuildInfo, bool)
		want          string
	}{
		{"a release is its version", "v0.3.0", built(rev, clean), "v0.3.0"},
		{"a clean working tree is its commit", "dev", built(rev, clean), "dev+ad6e16568ba5"},
		{"uncommitted changes are no commit", "dev", built(rev, dirty), "dev"},
		{"an image built without .git records none", "dev", built(), "dev"},
		{"no build information", "dev", func() (*debug.BuildInfo, bool) { return nil, false }, "dev"},
	} {
		if got := selfIdentity(c.version, c.read); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
