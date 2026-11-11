// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
)

// auditedStore is a store whose log holds n records.
func auditedStore(t *testing.T, n int) string {
	t.Helper()
	root := t.TempDir()
	putRecords(t, root, n)
	return root
}

func putRecords(t *testing.T, root string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := recordE(root, audit.Record{Action: "publish", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
}

// tearLog leaves the line a writer that died part way through a record
// leaves.
func tearLog(t *testing.T, root string) {
	t.Helper()
	f, err := os.OpenFile(auditPath(root), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"seq":2,"at":"2026-10`); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// jsonAnswer runs a command under --json and returns the document it wrote.
func jsonAnswer(t *testing.T, run func() error) (map[string]any, error) {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	var b bytes.Buffer
	w = &out.Writer{Mode: out.JSON, Out: &b, Err: io.Discard}
	err := run()
	w = old
	doc := map[string]any{}
	if jerr := json.Unmarshal(b.Bytes(), &doc); jerr != nil {
		t.Fatalf("under --json it wrote %q: %v (and returned %v)", b.String(), jerr, err)
	}
	return doc, err
}

// A line a crash left unfinished is reported as that, and every entry after
// it is still verified, shown, exported and signed for. Reading stopped at
// the line: verify called it tampering at "entry 0" of a log one entry long,
// and show, both exports and every head stopped there for good.
func TestATornLineIsReportedAsAnUnfinishedWriteAndHidesNothing(t *testing.T) {
	root := auditedStore(t, 1)
	tearLog(t, root)
	putRecords(t, root, 2)

	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	var blocked errBlocked
	if !errors.As(err, &blocked) {
		t.Errorf("an unfinished write is not a finding: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "tampered") {
		t.Errorf("an unfinished write is reported as tampering: %v\n%s", err, human)
	}
	if !strings.Contains(human, "3 entries") || !strings.Contains(human+errString(err), "unfinished") {
		t.Errorf("verify said:\n%s%v", human, err)
	}
	doc, _ := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if doc["entries"] != float64(3) || doc["intact"] != false {
		t.Errorf("verify --json: %v", doc)
	}

	// Posture reads the entries too, and a crash is not a broken chain.
	st := Observe(root, t.TempDir(), posture.ServerFacts{})
	if !st.AuditRead || len(st.Audit) != 3 {
		t.Errorf("posture read %d entries (read %v)", len(st.Audit), st.AuditRead)
	}
	if f := scanFinding(st, "audit.chain-broken"); f != nil {
		t.Errorf("posture calls an unfinished write a broken chain: %s", f.Detail)
	}

	doc, err = jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"show"}) })
	if entries, _ := doc["entries"].([]any); err != nil || len(entries) != 3 || doc["intact"] != false {
		t.Errorf("show --json: %d entries, intact %v: %v", len(entries), doc["intact"], err)
	}

	_, done := captureStdout(t)
	err = cmdAuditLog(root, []string{"export"})
	exported := done()
	if err != nil || strings.Count(exported, "\n") != 3 {
		t.Errorf("auditlog export: %v\n%s", err, exported)
	}

	jsonl := filepath.Join(t.TempDir(), "siem.jsonl")
	if err := cmdSiem(root, []string{"jsonl", "-o", jsonl}); err != nil {
		t.Errorf("siem export: %v", err)
	} else if b, _ := os.ReadFile(jsonl); bytes.Count(b, []byte("\n")) != 3 {
		t.Errorf("siem export wrote:\n%s", b)
	}

	if doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head"}) }); err != nil || doc["size"] == nil {
		t.Errorf("auditlog head: %v %v", doc, err)
	}
}

// A line in the log that is not an entry, and that no write cut short, is
// reported as what it is everywhere the log is reported on, while every
// entry around it is still read. Posture stopped at it and checked nothing
// about the log, so a line of anything added to the log took the chain's
// own finding away.
func TestALineThatIsNotAnEntryIsABreakEverywhere(t *testing.T) {
	root := auditedStore(t, 2)
	f, err := os.OpenFile(auditPath(root), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{not an entry}\n")
	f.Close()

	st := Observe(root, t.TempDir(), posture.ServerFacts{})
	if !st.AuditRead || len(st.Audit) != 2 {
		t.Errorf("posture read %d entries (read %v)", len(st.Audit), st.AuditRead)
	}
	if f := scanFinding(st, "audit.chain-broken"); f == nil || !strings.Contains(f.Detail, "not an entry") {
		t.Errorf("posture does not report the line: %+v", f)
	}

	_, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Errorf("verify: %v", err)
	}
}

// scanFinding is the finding a scan of st makes under rule, or nil.
func scanFinding(st posture.State, rule string) *posture.Finding {
	rep := posture.Scan(st, nil)
	for i := range rep.Findings {
		if rep.Findings[i].Rule == rule {
			return &rep.Findings[i]
		}
	}
	return nil
}
