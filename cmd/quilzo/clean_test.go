// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Running the tests does not write into the source tree.
//
// A command whose path flag defaults to a relative directory writes into the
// working directory, and for a test the working directory is the package
// directory. `quilzo demo` defaults --templates to "templates", so a test
// calling it without that flag leaves cmd/quilzo/templates/page.html and
// site.css behind.
//
// They were then committed, because .gitignore anchors /templates/ at the
// repository root — deliberately, its comment says so: "templates, which is
// also the name of a directory a package could [have]" — and `git add -A`
// takes anything one directory down.
//
// Nothing failed. The tests passed, the build was fine, and two files nobody
// meant to ship went in with a commit about something else entirely, which is
// exactly the shape of mistake that gets through review.
//
// # Why TestMain and not a test
//
// The first version of this was an ordinary test, and it did not work. Go runs
// test files in alphabetical order, so clean_test.go ran before the test that
// made the mess and reported a clean tree. It would have caught it on the
// *next* run, which is a guard that tells you about yesterday.
//
// TestMain runs after everything, which is the only place this can be checked
// at all.
func TestMain(m *testing.M) {
	before := looseEntries()
	code := m.Run()

	if left := newEntries(before, looseEntries()); len(left) > 0 {
		fmt.Fprintf(os.Stderr,
			"\nthe tests left %s in cmd/quilzo:\n  %s\n"+
				"A path flag defaulted to a relative directory, and the working "+
				"directory of a test is the package directory. Pass the flag "+
				"somewhere disposable (t.TempDir()), and delete what is listed "+
				"above — .gitignore anchors /templates/ at the repository root, "+
				"so `git add -A` will otherwise commit it.\n",
			count(len(left), "unexpected entry"), strings.Join(left, "\n  "))
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// looseEntries is everything in the package directory that is not source.
func looseEntries() map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			switch filepath.Ext(e.Name()) {
			case ".go", ".md":
				continue
			}
		}
		out[e.Name()] = true
	}
	return out
}

// newEntries is what appeared while the tests ran.
//
// A difference rather than an absolute list, so a directory somebody has for
// their own reasons — a scratch checkout, an editor's cache — is not reported
// as something the suite created.
func newEntries(before, after map[string]bool) []string {
	var out []string
	for name := range after {
		if !before[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// The ignore rule that let this through is anchored on purpose.
//
// Widening /templates/ to templates/ would hide the next occurrence rather
// than prevent it, and would also ignore a real templates package if anybody
// writes one. The fix is that tests do not write there; this records why the
// other fix was not taken, so somebody does not "helpfully" widen it later.
func TestTheTemplatesIgnoreRuleStaysAnchored(t *testing.T) {
	body, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Skip("no .gitignore from here")
	}
	text := string(body)
	if !strings.Contains(text, "\n/templates/") {
		t.Error("/templates/ is no longer anchored to the repository root. " +
			"Unanchored, it would also ignore a templates directory inside a " +
			"package — including one a test wrote by accident, which is the " +
			"thing TestTheTestsDoNotWriteIntoTheSourceTree exists to report " +
			"rather than hide")
	}
}
