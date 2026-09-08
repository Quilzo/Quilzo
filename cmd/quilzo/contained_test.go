// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The exporter refuses to write outside the directory it was given.
//
// This is the second of two independent checks. The store now validates a tree
// a peer hands it, so a poisoned name should not reach here at all — and that
// is exactly the reasoning that produced the defect. `quilzo ipfs write` had
// this check with a comment saying page names are validated on write "so this
// cannot currently escape", and Store.PutRaw then turned out to validate
// nothing. A consumer that can verify an invariant in three lines should not
// be relying on it.
//
// Kept as a unit test on the join rather than an end-to-end one, because with
// both fixes in place the end-to-end path is unreachable — which is the
// intended state and a poor place to test from.
func TestTheExporterWillNotWriteOutsideItsDirectory(t *testing.T) {
	const dir = "/tmp/out"
	for _, name := range []string{
		"content/../../../../tmp/pwned.md",
		"../escape.md",
		"..",
		"a/../../b.md",
	} {
		if got, err := containedPath(dir, name); err == nil {
			t.Errorf("%q was accepted and would be written to %q", name, got)
		}
	}
}

// Ordinary names still resolve, including nested ones.
func TestTheExporterWritesOrdinaryNames(t *testing.T) {
	const dir = "/tmp/out"
	for _, name := range []string{
		"content/about.md",
		"index.md",
		"content/products/thing.md",
		"content/a..b.md", // dots inside a name are not a traversal
	} {
		got, err := containedPath(dir, name)
		if err != nil {
			t.Errorf("%q was refused: %v", name, err)
			continue
		}
		if !strings.HasPrefix(got, dir+string(filepath.Separator)) {
			t.Errorf("%q resolved to %q, which is outside %q", name, got, dir)
		}
	}
}
