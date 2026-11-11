// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
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
