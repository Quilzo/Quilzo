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
	} {
		if got := moduleVersion(c.ldflags, c.read); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
