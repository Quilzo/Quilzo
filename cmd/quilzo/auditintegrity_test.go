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

// keepLines cuts the log back to its first n lines, as somebody removing
// the newest entries from its end leaves it.
func keepLines(t *testing.T, root string, n int) {
	t.Helper()
	b, err := os.ReadFile(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	if err := os.WriteFile(auditPath(root), []byte(strings.Join(lines[:n], "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Entries removed from the end of the log are found against the head saved
// beside it. What is left is a shorter chain that verifies, and the next
// write takes the first number removed and links to what is left, so not
// even a gap shows: verify said nothing was removed, "including by an
// administrator", with a saved head covering more than the log held.
func TestEntriesRemovedFromTheEndAreFoundAgainstTheSavedHead(t *testing.T) {
	root := auditedStore(t, 4)
	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if err != nil || !strings.Contains(human, "no head is saved") || strings.Contains(human, "including by an administrator") {
		t.Errorf("with no head saved, verify said:\n%s%v", human, err)
	}
	if doc, _ := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify"}) }); doc["intact"] != true || doc["head"] != nil {
		t.Errorf("verify --json with no head saved: %v", doc)
	}

	if _, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head", "--save"}) }); err != nil {
		t.Fatal(err)
	}
	putRecords(t, root, 2)
	human, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if err != nil || !strings.Contains(human, "extends the head saved at 4 entries") {
		t.Errorf("a log that grew from its saved head: %v\n%s", err, human)
	}

	// The three newest removed: one of them the head covers.
	keepLines(t, root, 3)
	var blocked errBlocked
	human, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "intact") || !strings.Contains(human, "shrunk") {
		t.Errorf("a log cut back behind its saved head: %v\n%s", err, human)
	}
	doc, _ := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if head, _ := doc["head"].(map[string]any); doc["intact"] != false || head["size"] != float64(4) {
		t.Errorf("verify --json: %v", doc)
	}
	if f := scanFinding(Observe(root, t.TempDir(), posture.ServerFacts{}), "audit.chain-broken"); f == nil || !strings.Contains(f.Detail, "shrunk") {
		t.Errorf("posture: %+v", f)
	}

	// The next write fills the number back in, and the log is the head's
	// size again, with another entry where the head's last one was.
	putRecords(t, root, 1)
	human, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "intact") || !strings.Contains(human, "NOT an append-only extension") {
		t.Errorf("a log rewritten behind its saved head: %v\n%s", err, human)
	}
}

// exportHead writes the signed head `auditlog head --json` answers to a
// file, as somebody keeping it off the machine does.
func exportHead(t *testing.T, root string) string {
	t.Helper()
	doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head"}) })
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "head.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A head kept off the machine is checked against the log. verify-head said
// "verified" for a head the log, cut back since, no longer held, and
// consistency read only the heads saved beside the log, so the one kept
// elsewhere, which is the one that counts, could not be checked at all: a
// head file named to it was dropped without a word.
func TestAHeadKeptElsewhereIsCheckedAgainstTheLog(t *testing.T) {
	root := auditedStore(t, 4)
	head := exportHead(t, root)
	putRecords(t, root, 2)

	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) })
	if err != nil || !strings.Contains(human, "verified") || !strings.Contains(human, "still extends it") {
		t.Errorf("a head the log grew from: %v\n%s", err, human)
	}
	doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) })
	if err != nil || doc["verified"] != true || doc["consistent"] != true || doc["log_size"] != float64(6) {
		t.Errorf("verify-head --json: %v %v", doc, err)
	}
	for _, args := range [][]string{{"consistency", head}, {"consistency", "--head", head}, {"consistency", "--head", head, "--since", "4"}} {
		if human, err := humanOutput(t, func() error { return cmdAuditLog(root, args) }); err != nil || !strings.Contains(human, "4 → 6") {
			t.Errorf("%v: %v\n%s", args, err, human)
		}
	}

	keepLines(t, root, 3)
	var blocked errBlocked
	human, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "verified") || !strings.Contains(errString(err), "shrunk") {
		t.Errorf("a head the log no longer holds: %v\n%s", err, human)
	}
	doc, err = jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) })
	if !errors.As(err, &blocked) || doc["verified"] != false || doc["consistent"] != false || doc["signed"] != true {
		t.Errorf("verify-head --json: %v %v", doc, err)
	}
	for _, args := range [][]string{{"consistency", head}, {"consistency", "--head", head}} {
		if _, err := humanOutput(t, func() error { return cmdAuditLog(root, args) }); !errors.As(err, &blocked) || !strings.Contains(errString(err), "shrunk") {
			t.Errorf("%v: %v", args, err)
		}
	}

	// A head of another size than --since, or a second file, is refused
	// rather than one of them dropped.
	for _, args := range [][]string{{"consistency", "--head", head, "--since", "3"}, {"consistency", head, head}} {
		if _, err := humanOutput(t, func() error { return cmdAuditLog(root, args) }); err == nil || errors.As(err, &blocked) {
			t.Errorf("%v: %v", args, err)
		}
	}

	// Somebody holding the head and the keys but not the log checks the
	// signatures, and is told what is left to check.
	elsewhere := t.TempDir()
	human, err = humanOutput(t, func() error {
		return cmdAuditLog(elsewhere, []string{"verify-head", head, "--keys", headKeysPath(root)})
	})
	if err != nil || !strings.Contains(human, "consistency --head") {
		t.Errorf("without the log: %v\n%s", err, human)
	}
	doc, _ = jsonAnswer(t, func() error {
		return cmdAuditLog(elsewhere, []string{"verify-head", head, "--keys", headKeysPath(root)})
	})
	if doc["verified"] != true || doc["consistent"] != nil {
		t.Errorf("verify-head --json without the log: %v", doc)
	}
}
