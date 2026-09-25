// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// A file name before a flag silently disabled every flag.
//
// Go's flag package stops at the first non-flag argument. `quilzo canary
// watch events.jsonl --canaries burn.jsonl` therefore parsed no flags, read
// the default register, and reported a detection where the register the
// operator named would have said the touch was expected. Nothing errored. The
// output was indistinguishable from a correct run, which is why this is a
// test and not a comment.
func TestAFileNameBeforeAFlagDoesNotDisableTheFlags(t *testing.T) {
	for _, args := range [][]string{
		{"events.jsonl", "--canaries", "burn.jsonl"},
		{"--canaries", "burn.jsonl", "events.jsonl"},
		{"--canaries=burn.jsonl", "events.jsonl"},
	} {
		fs := flag.NewFlagSet("watch", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		register := fs.String("canaries", "canaries.jsonl", "")
		rest, err := eventFileArgs(fs, args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if *register != "burn.jsonl" {
			t.Errorf("%v parsed the register as %q", args, *register)
		}
		if len(rest) != 1 || rest[0] != "events.jsonl" {
			t.Errorf("%v left the file as %v", args, rest)
		}
	}
}

func TestNoFileMeansStandardInput(t *testing.T) {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	top := fs.Int("top", 20, "")
	rest, err := eventFileArgs(fs, []string{"--top", "3"})
	if err != nil {
		t.Fatal(err)
	}
	if *top != 3 {
		t.Errorf("--top parsed as %d", *top)
	}
	if len(rest) != 0 {
		t.Errorf("invented a file name: %v", rest)
	}
}

func TestAnUnknownFlagIsStillRefused(t *testing.T) {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("canaries", "canaries.jsonl", "")
	_, err := eventFileArgs(fs, []string{"events.jsonl", "--canarys", "x"})
	if err == nil {
		t.Fatal("a misspelled flag was accepted, which is how a run reads " +
			"the wrong register and looks clean")
	}
	if !strings.Contains(err.Error(), "canarys") {
		t.Errorf("the refusal does not name the flag: %v", err)
	}
}
