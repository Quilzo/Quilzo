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

// The help is a contract: `auditlog show SEQ` is one entry, in full, and
// `auditlog export -o FILE` is the whole log in a file. Both arguments were
// read by nothing. `show 3` printed the last twenty-five entries as though
// one of them were entry 3, and `export -o archive.jsonl` wrote the whole
// log to the terminal, made no file and exited 0, so a script shipping the
// archive it had just written shipped nothing. Run through the dispatcher,
// as main runs them, so a help line and its dispatch cannot drift apart.
func TestShowSeqAndExportToAFileDoWhatTheHelpSays(t *testing.T) {
	second := published("/b")
	second.Detail = map[string]string{"commit": "c0ffee", "note": "line\x1b[2K"}
	root := shownLog(t, published("/a"), second, published("/c"))

	got, err := showing(t, root, "2")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"entry 2", "/b", "commit", "c0ffee", "hash", "prev"} {
		if !strings.Contains(got, want) {
			t.Errorf("show 2 does not show %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "/a") || strings.Contains(got, "/c") {
		t.Errorf("show 2 showed other entries:\n%s", got)
	}
	if c := controlIn(got); c != "" {
		t.Errorf("show 2 printed the control character %s from a detail:\n%q", c, got)
	}
	if _, err := showing(t, root, "9"); err == nil || !strings.Contains(err.Error(), "no entry 9") {
		t.Errorf("show of an entry that is not there: %v", err)
	}

	// The log as it is stored when it is exported: the export leaves its
	// own record after it (auditlog.export), as every export of the log does.
	stored, rerr := os.ReadFile(auditPath(root))
	file := t.TempDir() + "/archive.jsonl"
	_, read := captureStdout(t)
	err = cmdAuditLog(root, []string{"export", "-o", file})
	printed := read()
	if err != nil {
		t.Fatal(err)
	}
	written, ferr := os.ReadFile(file)
	if rerr != nil || ferr != nil {
		t.Fatalf("export -o made no file: %v %v", rerr, ferr)
	}
	if string(written) != string(stored) {
		t.Errorf("the file is not the log as it is stored:\n%s\nwant:\n%s", written, stored)
	}
	if strings.Contains(printed, `"seq"`) {
		t.Errorf("export -o printed the log as well:\n%s", printed)
	}
	if info, err := os.Stat(file); err == nil && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("the export is readable by others: %v", info.Mode())
	}

	// What neither takes is refused, rather than ignored with success.
	for _, args := range [][]string{
		{"show", "2", "3"}, {"show", "two"}, {"show", "--limit", "-1"}, {"export", "archive.jsonl"},
	} {
		var panicked any
		func() {
			defer func() { panicked = recover() }()
			_, err = humanOutput(t, func() error { return cmdAuditLog(root, args) })
		}()
		if panicked != nil || err == nil {
			t.Errorf("auditlog %v was not refused: %v %v", args, err, panicked)
		}
	}
}

// `auditlog verify` names the head it checked the log against, and when it
// was saved, from the heads file beside the log, which whoever can rewrite
// the log can rewrite too: a time in it carrying escape sequences reached
// the terminal raw, below the line saying the chain is intact. The problem
// lines, and the audit log screen's line for the same head, mark them.
func TestVerifyPrintsNoControlCharacterFromTheSavedHeads(t *testing.T) {
	root := shownLog(t, published("/a"), published("/b"))
	for i := 0; i < 2; i++ {
		if _, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head", "--save"}) }); err != nil {
			t.Fatal(err)
		}
		f := &headFile{}
		if err := loadJSON(headsPath(root), f); err != nil || len(f.Heads) != i+1 {
			t.Fatalf("%d heads saved: %v", len(f.Heads), err)
		}
		for j := range f.Heads {
			f.Heads[j].At = "2026-11-10T09:00:00Z" + redraw
		}
		if err := saveJSON(headsPath(root), f); err != nil {
			t.Fatal(err)
		}
		got, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
		if err != nil || !strings.Contains(got, "chain intact") || !strings.Contains(got, "all quiet") {
			t.Fatalf("verify against %d head(s): %v\n%s", i+1, err, got)
		}
		if c := controlIn(got); c != "" {
			t.Errorf("verify against %d head(s) printed the control character %s from the heads file:\n%q", i+1, c, got)
		}
	}
}
