// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No subcommand declares a flag the global pass already handles.
//
// --token was read globally and removed nowhere. The authorisation check
// picked it out of the raw arguments and then handed the same arguments to the
// subcommand's own flag set, which rejected an undeclared flag. Seven of
// eighty-one flag sets declared it, so `publish --token X` worked and
// `add --token X` exited 1 with "flag provided but not defined: -token".
//
// The command that mattered most was the one printing the advice: every
// refusal in this program ends "Present one with --token, ~/.quilzo/token, or
// QUILZO_TOKEN", and for `quilzo add` on an access-controlled store the first
// of those three could not be done at all.
//
// A redeclared global is the shape of that bug: two mechanisms for one flag,
// where the local one shadows the global and only for some commands.
func TestNoSubcommandRedeclaresAGlobalFlag(t *testing.T) {
	globals := []string{"token", "root", "json"}
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Skip("no sources found")
	}

	decl := regexp.MustCompile(`fs\.(?:String|Bool|Int|Duration)\("([a-z-]+)"`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			continue
		}
		name := filepath.Base(f)
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			for _, g := range globals {
				if m[1] != g {
					continue
				}
				t.Errorf("%s declares --%s on a subcommand flag set, which "+
					"the global pass in main already strips. Two mechanisms "+
					"for one flag is how --token came to work on seven "+
					"commands and fail on the rest", name, g)
			}
		}
	}
}

// The global pass strips what it reads.
//
// Reading a flag without removing it is the precise defect: the value reached
// the code that wanted it and the flag reached the flag set that did not know
// it. Both spellings, because --token=X and --token X are the same request.
func TestTheGlobalPassRemovesWhatItReads(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	b, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil {
		t.Skip("no main.go")
	}
	src := string(b)
	for _, want := range []string{
		`args[i] == "--token"`,
		`strings.CutPrefix(args[i], "--token=")`,
		`args[i] == "--root"`,
		`strings.CutPrefix(args[i], "--root=")`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the global flag pass does not handle %s, so that "+
				"spelling reaches a subcommand flag set that may not "+
				"declare it", want)
		}
	}
}
