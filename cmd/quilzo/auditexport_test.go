// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
)

// exportStore is a store with something in its log to export, and the log
// as it stood before anything exported it.
func exportStore(t *testing.T) (string, []byte) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	w = out.New(false)
	t.Cleanup(func() { w = old })
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"/index", "/about"} {
		record(root, audit.Record{Action: "publish", Resource: page, Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman})
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var stored bytes.Buffer
	if err := audit.Export(events, &stored); err != nil {
		t.Fatal(err)
	}
	return root, stored.Bytes()
}

// exportRecords are the records the log holds of being exported.
func exportRecords(t *testing.T, root string) []audit.Event {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range events {
		if audit.Canonical(e.Action) == "auditlog.export" {
			out = append(out, e)
		}
	}
	return out
}

// Every export of the whole audit log is recorded, under one name and with
// the same detail, whichever command made it.
//
// `quilzo siem` recorded auditlog.export with the format, how many events,
// their range and whether identifiers were asked for. `quilzo auditlog
// export` wrote the same log out, as it is stored, and recorded nothing, so
// the one bulk export an auditor's job can run left no trace of having run.
func TestEveryAuditLogExportIsRecordedWithTheSameDetail(t *testing.T) {
	root, _ := exportStore(t)
	dir := t.TempDir()
	if err := cmdAuditLog(root, []string{"export", "-o", filepath.Join(dir, "raw.jsonl")}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSiem(root, []string{"jsonl", "-o", filepath.Join(dir, "siem.jsonl")}); err != nil {
		t.Fatal(err)
	}
	got := exportRecords(t, root)
	if len(got) != 2 {
		t.Fatalf("two exports left %d auditlog.export record(s)", len(got))
	}
	raw, sm := got[0], got[1]
	if keys, want := slices.Sorted(maps.Keys(raw.Detail)), slices.Sorted(maps.Keys(sm.Detail)); !slices.Equal(keys, want) {
		t.Errorf("auditlog export recorded %v, and siem %v", keys, want)
	}
	if raw.Detail["format"] != "raw" || raw.Detail["identifiers_requested"] != "false" {
		t.Errorf("auditlog export recorded %v", raw.Detail)
	}
	// The two entries the store was made with, and then those and the
	// record of the first export.
	if raw.Detail["events"] != "2" || raw.Detail["range"] != "1-2" ||
		sm.Detail["events"] != "3" || sm.Detail["range"] != "1-3" {
		t.Errorf("the log exported twice was recorded as %v and %v", raw.Detail, sm.Detail)
	}
}

// `quilzo auditlog export -o FILE`, as the help gives it, writes FILE.
//
// The flag was never read: the log went to the terminal, the command
// exited 0, and the file somebody believed they had written did not exist.
// Without -o the log is written to standard output exactly as before.
func TestAuditLogExportWritesTheFileTheHelpNames(t *testing.T) {
	root, stored := exportStore(t)
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	_, done := captureStdout(t)
	err := cmdAuditLog(root, []string{"export", "-o", file})
	if printed := done(); err != nil || printed != "" {
		t.Fatalf("auditlog export -o: %v, and printed %d byte(s)", err, len(printed))
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("auditlog export -o wrote no file: %v", err)
	}
	if !bytes.Equal(b, stored) {
		t.Error("the file is not the log as it is stored")
	}
	if fi, err := os.Stat(file); err == nil && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the export is readable by others: %v", fi.Mode().Perm())
	}

	root, stored = exportStore(t)
	_, done = captureStdout(t)
	err = cmdAuditLog(root, []string{"export"})
	if printed := done(); err != nil || printed != string(stored) {
		t.Fatalf("auditlog export to standard output: %v, and printed %q", err, printed)
	}
}

// A flag or an argument auditlog export does not take is refused, rather
// than the whole log printed anyway.
func TestAuditLogExportRefusesWhatItDoesNotTake(t *testing.T) {
	root, _ := exportStore(t)
	for _, args := range [][]string{{"export", "--bogus"}, {"export", "audit.jsonl"}} {
		_, done := captureStdout(t)
		err := cmdAuditLog(root, args)
		printed := done()
		if err == nil {
			t.Errorf("auditlog %v was not refused", args)
		}
		if printed != "" {
			t.Errorf("auditlog %v printed the log", args)
		}
	}
	if n := len(exportRecords(t, root)); n != 0 {
		t.Errorf("a refused export was recorded as %d export(s)", n)
	}
}

// `quilzo auditlog export` and `quilzo siem jsonl` are one export of a log
// that verifies: the same bytes, over the same events.
//
// They were two exporters, each with a serializer of its own, and only one
// of them recorded what it wrote.
func TestAuditlogExportAndSiemJSONLinesWriteTheSameBytes(t *testing.T) {
	root, stored := exportStore(t)
	dir := t.TempDir()
	raw, sm := filepath.Join(dir, "raw.jsonl"), filepath.Join(dir, "siem.jsonl")
	if err := cmdAuditLog(root, []string{"export", "-o", raw}); err != nil {
		t.Fatal(err)
	}
	// The events the first export wrote, without the record of it.
	if err := cmdSiem(root, []string{"jsonl", "--until", "2", "-o", sm}); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(sm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, stored) || !bytes.Equal(a, b) {
		t.Errorf("auditlog export and siem jsonl wrote different bytes:\n%s\n%s", a, b)
	}
}
