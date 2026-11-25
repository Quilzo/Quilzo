// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// The security modules' commands keep the command line's contract where
// the tests of every registered command (modules_test.go) do not ask: in
// the words each reads for itself.

// A word no record can be called is a misused command line, 2, in every
// module's command that takes an identifier, and an identifier nothing has
// is still not found, 4.
//
// The built-in commands refuse an id of the wrong shape as the command
// line's mistake (`agent receipt ab`, `feature approve ab`, `auditlog show
// ab`), and so does `quilzo evidence show ab`, and the agent interface,
// where register_show refuses the same word as an argument. The commands
// beside them looked the word up: `register show ab` said "no such record
// in the register: "ab" is not a record's identifier" and exited 4, as
// `register history`, the approvals' show, check, reject, approve and
// review, and the programme's approve, run, explain and replay did, so a
// script told "not found" went looking for a record a typo had named. And
// `population show ""` exited 4 where `population count ""` exits 2.
func TestAWordNoRecordCanBeCalledIsMisusedInEveryModule(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	const nothing = "00000000000000000000000000000000"
	for _, line := range [][]string{
		{"register", "show", "ID"},
		{"register", "history", "ID"},
		{"approval", "show", "ID"},
		{"approval", "check", "ID"},
		{"approval", "reject", "ID"},
		{"approval", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"approval", "review", "ID", "upheld", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"control", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"control", "run", "ID"},
		{"control", "explain", "ID"},
		{"control", "replay", "ID"},
		{"requirement", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"soa", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
	} {
		for word, want := range map[string]int{
			"ab": out.ExitUsage, "": out.ExitUsage, "not an id at all": out.ExitUsage,
			strings.ToUpper("abcdefabcdefabcdefabcdefabcdefab"): out.ExitUsage,
			nothing: out.ExitNotFound,
		} {
			typed := append([]string{}, line...)
			for i, a := range typed {
				if a == "ID" {
					typed[i] = word
				}
			}
			if _, e, code := cliRun(t, root, "", typed...); code != want {
				t.Errorf("`quilzo %s` exited %d, want %d (%s): %s", strings.Join(typed, " "), code, want,
					out.Describe(want), firstLines(e, 2))
			}
		}
	}
	if _, e, code := cliRun(t, root, "", "population", "show", ""); code != out.ExitUsage {
		t.Errorf("`quilzo population show \"\"` exited %d, want %d: %s", code, out.ExitUsage, firstLines(e, 2))
	}
	if _, e, code := cliRun(t, root, "", "population", "show", "nobody"); code != out.ExitNotFound {
		t.Errorf("`quilzo population show nobody` exited %d, want %d: %s", code, out.ExitNotFound, firstLines(e, 2))
	}
}
