// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// shownLog writes records to a fresh store's log the way every command does,
// and returns the store.
func shownLog(t *testing.T, records ...audit.Record) string {
	t.Helper()
	root := t.TempDir()
	l, err := openAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// editEntry rewrites one entry of the log in place, as somebody with the
// file in front of them would.
func editEntry(t *testing.T, root string, seq int64, edit func(e map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i, line := range lines {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if int64(e["seq"].(float64)) != seq {
			continue
		}
		edit(e)
		out, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		lines[i] = string(out)
	}
	if err := os.WriteFile(auditPath(root), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func published(resource string) audit.Record {
	return audit.Record{Action: "publish", Resource: resource, Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true}
}

// showing runs `auditlog show` with the words a person reads, and reports a
// panic as a failure of the test rather than of the whole binary.
func showing(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	var panicked any
	got, err := humanOutput(t, func() (err error) {
		defer func() { panicked = recover() }()
		return cmdAuditLog(root, append([]string{"show"}, args...))
	})
	if panicked != nil {
		t.Fatalf("auditlog show %v panicked: %v\n%s", args, panicked, got)
	}
	return got, err
}

// A doctored log is shown with its warning, entry by entry, and a doctored
// timestamp is one of the things it can carry. `show` cut every timestamp to
// nineteen characters, and an entry whose "at" had been shortened to a date
// stopped the listing with a Go stack trace just after the warning that the
// chain was broken: the reader the warning was for saw a crash instead of the
// entries.
func TestShowListsAnEntryWhoseTimeWasShortened(t *testing.T) {
	root := shownLog(t, published("/a"), published("/b"), published("/c"), published("/d"))
	editEntry(t, root, 2, func(e map[string]any) { e["at"] = "2026-11-10" })
	editEntry(t, root, 3, func(e map[string]any) { e["at"] = "" })

	got, err := showing(t, root, "--limit", "4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "the chain is broken") {
		t.Errorf("the doctored log was shown without its warning:\n%s", got)
	}
	for _, want := range []string{"2026-11-10", "/a", "/b", "/c", "/d"} {
		if !strings.Contains(got, want) {
			t.Errorf("the listing does not show %q:\n%s", want, got)
		}
	}
}

// redraw is what somebody holding a decoy token put in the path they asked
// for: clear this line, go up one, clear that, and print a green "all quiet".
const redraw = "\x1b[2K\x1b[1A\x1b[2K\x1b[32mall quiet\x1b[0m"

// controlIn names the first control character in s that is not a line break
// or a tab, or says nothing.
func controlIn(s string) string {
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return strconv.QuoteRune(r)
		}
	}
	return ""
}

// What the log holds was written by whoever the log is about, and some of
// them are the people it exists to catch. A decoy is presented by an
// outsider, and the path they ask for is recorded as they sent it, so a path
// carrying escape sequences reached the operator's terminal raw from
// `auditlog show` and erased its own line and the one above it. Every field
// shown comes from the file, a doctored entry's included: one that could
// clear the line above could clear the warning that the chain is broken.
func TestShowPrintsNoControlCharacterFromTheLog(t *testing.T) {
	root := shownLog(t,
		audit.Record{Action: "shield.decoy-touched", Resource: "/api/v1/pages" + redraw,
			Outcome: audit.Denied, Principal: "visitor", Kind: audit.KindUnknown},
		audit.Record{Action: "publish\u009b2K", Resource: "/x\r\nquilzo: all quiet",
			Outcome: audit.Success, Principal: "helper", Kind: audit.KindAI,
			Model: "m\x1b]0;owned\x07", Verified: true},
		published("/c"),
	)
	got, err := showing(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if c := controlIn(got); c != "" {
		t.Errorf("auditlog show printed the control character %s from the log:\n%q", c, got)
	}
	if strings.Contains(got, "\nquilzo: all quiet") {
		t.Errorf("a resource started a line of its own:\n%s", got)
	}
	if !strings.Contains(got, "all quiet") || !strings.Contains(got, "/api/v1/pages") {
		t.Errorf("the entry is not shown at all:\n%s", got)
	}

	// Doctored: the warning that comes first cannot be erased by what
	// follows it.
	editEntry(t, root, 3, func(e map[string]any) {
		e["outcome"] = "success\x1b[5A\x1b[J"
		e["at"] = "2026-11-10T09:00:00\x1b[2K"
	})
	got, err = showing(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "the chain is broken") {
		t.Fatalf("the doctored log was shown without its warning:\n%s", got)
	}
	if c := controlIn(got); c != "" {
		t.Errorf("auditlog show printed the control character %s from a doctored entry:\n%q", c, got)
	}
}

// `quilzo agents` reads the same log and prints what a model was refused,
// where, and why, and a model's name and the resource it asked for are what
// it was given or chose.
func TestAgentsPrintsNoControlCharacterFromTheLog(t *testing.T) {
	root := shownLog(t, audit.Record{Action: "edit" + redraw, Resource: "/p" + redraw,
		Outcome: audit.Denied, Principal: "helper", Kind: audit.KindAI,
		Model: "m\x1b]0;owned\x07", Verified: true,
		Detail: map[string]string{"reason": "no\x1b[1A\x1b[2Kgood"}})
	got, _ := humanOutput(t, func() error { return cmdAgents(root, nil) })
	if !strings.Contains(got, "/p") {
		t.Fatalf("the refusal is not shown:\n%s", got)
	}
	if c := controlIn(got); c != "" {
		t.Errorf("quilzo agents printed the control character %s from the log:\n%q", c, got)
	}
}
