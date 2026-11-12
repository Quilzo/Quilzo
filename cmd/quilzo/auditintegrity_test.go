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

	// Every entry, the record the export above left of itself among them
	// (auditlog.export).
	jsonl := filepath.Join(t.TempDir(), "siem.jsonl")
	if err := cmdSiem(root, []string{"jsonl", "-o", jsonl}); err != nil {
		t.Errorf("siem export: %v", err)
	} else if b, _ := os.ReadFile(jsonl); bytes.Count(b, []byte("\n")) != 4 ||
		!bytes.Contains(b, []byte(`"action":"auditlog.export"`)) {
		t.Errorf("siem export wrote:\n%s", b)
	}

	if doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head"}) }); err != nil || doc["size"] == nil {
		t.Errorf("auditlog head: %v %v", doc, err)
	}
}

// A crash with nothing written after it leaves the line it cut short last
// in the log, still open. That is a crash as well, not tampering, and it
// blanks nothing: verify says so and still finds it, the log still extends
// the head saved before it, and every view and export has every entry.
func TestATornLastLineIsACrashAndBlanksNothing(t *testing.T) {
	root := auditedStore(t, 3)
	if _, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head", "--save"}) }); err != nil {
		t.Fatal(err)
	}
	head := exportHead(t, root)
	tearLog(t, root)

	var blocked errBlocked
	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if !errors.As(err, &blocked) || strings.Contains(errString(err), "tampered") ||
		!strings.Contains(human+errString(err), "unfinished") || strings.Contains(human, "intact") {
		t.Errorf("verify: %v\n%s", err, human)
	}
	doc, _ := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if hd, _ := doc["head"].(map[string]any); doc["entries"] != float64(3) || doc["intact"] != false ||
		doc["unfinished"] != float64(1) || hd["size"] != float64(3) {
		t.Errorf("verify --json: %v", doc)
	}
	doc, err = jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"show"}) })
	if entries, _ := doc["entries"].([]any); err != nil || len(entries) != 3 || doc["intact"] != false {
		t.Errorf("show --json: %d entries, intact %v: %v", len(entries), doc["intact"], err)
	}
	if f := scanFinding(Observe(root, t.TempDir(), posture.ServerFacts{}), "audit.chain-broken"); f != nil {
		t.Errorf("posture calls a crash a broken chain: %s", f.Detail)
	}
	if doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) }); err != nil || doc["verified"] != true {
		t.Errorf("verify-head of a head the log still holds: %v %v", doc, err)
	}
	if _, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"consistency"}) }); err != nil {
		t.Errorf("consistency: %v", err)
	}
	_, done := captureStdout(t)
	err = cmdAuditLog(root, []string{"export"})
	if exported := done(); err != nil || strings.Count(exported, "\n") != 3 {
		t.Errorf("auditlog export: %v\n%s", err, exported)
	}
}

// An export holds every entry, and says where its summary goes which lines
// of the log it left out: they are not entries, and the system it goes to
// cannot tell that anything was there. The export stopped at the first, so
// nothing after a crash could be exported; passed over without a word, a
// line somebody added would leave no trace in what the SIEM holds.
func TestAnExportSaysWhichLinesItLeftOut(t *testing.T) {
	root := auditedStore(t, 1)
	tearLog(t, root)
	putRecords(t, root, 1)
	old := w
	t.Cleanup(func() { w = old })
	var errs bytes.Buffer
	w = &out.Writer{Mode: out.Human, Out: io.Discard, Err: &errs}

	_, done := captureStdout(t)
	err := cmdAuditLog(root, []string{"export"})
	exported := done()
	if err != nil || strings.Count(exported, "\n") != 2 || !strings.Contains(errs.String(), "line 2") ||
		!strings.Contains(errs.String(), "not in this export") {
		t.Errorf("auditlog export: %v\n%s\nsaid: %s", err, exported, errs.String())
	}

	errs.Reset()
	jsonl := filepath.Join(t.TempDir(), "siem.jsonl")
	if err := cmdSiem(root, []string{"jsonl", "-o", jsonl}); err != nil || !strings.Contains(errs.String(), "not in this export") {
		t.Errorf("siem export: %v\nsaid: %s", err, errs.String())
	}

	// A log with nothing else in it says nothing more.
	clean := auditedStore(t, 2)
	errs.Reset()
	_, done = captureStdout(t)
	err = cmdAuditLog(clean, []string{"export"})
	done()
	if err != nil || errs.Len() != 0 {
		t.Errorf("a whole log: %v, said %q", err, errs.String())
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
	// show says what verify does: it showed a log cut back as intact.
	if doc, _ := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"show"}) }); doc["intact"] != false {
		t.Errorf("show --json of a log cut back behind its saved head: %v", doc)
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

// consistency with no head named checks the log against the largest head
// saved beside it, as verify does. It took the newest, and a head saved
// after entries were removed from the end covers fewer than one saved
// before them, so saving one then made consistency call the log consistent.
func TestConsistencyChecksTheLargestSavedHead(t *testing.T) {
	root := auditedStore(t, 4)
	save := func() {
		t.Helper()
		if _, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head", "--save"}) }); err != nil {
			t.Fatal(err)
		}
	}
	save()
	keepLines(t, root, 3)
	save()
	putRecords(t, root, 1)

	var blocked errBlocked
	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"consistency"}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "consistent") ||
		!strings.Contains(errString(err), "NOT an append-only extension of the head at 4") {
		t.Errorf("against the heads saved before and after entries were removed: %v\n%s", err, human)
	}
	// A size named is still the head of that size.
	if human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"consistency", "--since", "3"}) }); err != nil ||
		!strings.Contains(human, "3 → 4") {
		t.Errorf("--since 3: %v\n%s", err, human)
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

// Every head saved beside the log is checked, not the largest alone. A log
// cut back and grown again past its largest head extends the next head
// saved, `auditlog anchor` or `head --save` as routinely as anything,
// because that head was taken from the log as it was left: verify, posture
// and consistency then called the log intact, with the head saved before
// the cut, which shows it, beside the log.
func TestAHeadSavedAfterACutDoesNotHideIt(t *testing.T) {
	root := auditedStore(t, 4)
	save := func() {
		t.Helper()
		if _, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head", "--save"}) }); err != nil {
			t.Fatal(err)
		}
	}
	save()
	putRecords(t, root, 1)
	save()
	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if err != nil || !strings.Contains(human, "each of the 2 heads saved beside it, the largest\n  at 5 entries") {
		t.Errorf("a log that grew from both its heads: %v\n%s", err, human)
	}

	keepLines(t, root, 3)
	putRecords(t, root, 3)
	save()

	var blocked errBlocked
	human, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "intact") ||
		!strings.Contains(human, "NOT an append-only extension of the head at 4") {
		t.Errorf("verify: %v\n%s", err, human)
	}
	doc, _ := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify"}) })
	if head, _ := doc["head"].(map[string]any); doc["intact"] != false || head["size"] != float64(6) {
		t.Errorf("verify --json: %v", doc)
	}
	doc, _ = jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"show"}) })
	if entries, _ := doc["entries"].([]any); doc["intact"] != false || len(entries) != 6 {
		t.Errorf("show --json: %v", doc)
	}
	if human, _ := humanOutput(t, func() error { return cmdAuditLog(root, []string{"show"}) }); !strings.Contains(human, "head at 4") {
		t.Errorf("show:\n%s", human)
	}
	if f := scanFinding(Observe(root, t.TempDir(), posture.ServerFacts{}), "audit.chain-broken"); f == nil ||
		!strings.Contains(f.Detail, "head at 4") {
		t.Errorf("posture: %+v", f)
	}
	human, err = humanOutput(t, func() error { return cmdAuditLog(root, []string{"consistency"}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "consistent") ||
		!strings.Contains(errString(err), "head at 4") {
		t.Errorf("consistency: %v\n%s", err, human)
	}
	// A size named is still the heads of that size alone.
	if human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"consistency", "--since", "6"}) }); err != nil ||
		!strings.Contains(human, "6 → 6") {
		t.Errorf("--since 6: %v\n%s", err, human)
	}
	// Cut back and grown again to the very size of a head saved before:
	// the head of that size saved after the cut does not stand in for it.
	keepLines(t, root, 3)
	putRecords(t, root, 1)
	save()
	if _, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"consistency", "--since", "4"}) }); !errors.As(err, &blocked) ||
		!strings.Contains(errString(err), "head at 4") {
		t.Errorf("--since 4 with two heads of 4 entries: %v", err)
	}
}

// A head is not verified against a log that has been removed altogether.
// The log's directory still holds what a log leaves beside it, and
// verify-head took the missing file for somebody holding a head with no log
// at all: it checked the signatures alone and said "verified".
func TestAHeadIsNotVerifiedOnceTheLogIsGone(t *testing.T) {
	root := auditedStore(t, 3)
	head := exportHead(t, root)
	if err := os.Remove(auditPath(root)); err != nil {
		t.Fatal(err)
	}
	var blocked errBlocked
	human, err := humanOutput(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) })
	if !errors.As(err, &blocked) || strings.Contains(human, "verified") || !strings.Contains(human, "does NOT contain it") {
		t.Errorf("verify-head: %v\n%s", err, human)
	}
	doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"verify-head", head}) })
	if !errors.As(err, &blocked) || doc["verified"] != false || doc["consistent"] != false || doc["log_size"] != float64(0) {
		t.Errorf("verify-head --json: %v %v", doc, err)
	}
}

// `auditlog show SEQ` and `auditlog export -o` read past a line a crash left
// unfinished as the listing and the export to standard output do: the entry
// after it is shown, under the notice that a write was left unfinished and
// not that the chain is broken, and the file holds every entry and nothing
// else, with the line it left out named.
func TestShowSeqAndExportToAFileReadPastATornLine(t *testing.T) {
	root := auditedStore(t, 1)
	tearLog(t, root)
	putRecords(t, root, 2)

	got, err := showing(t, root, "3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "entry 3") || !strings.Contains(got, "left unfinished") ||
		strings.Contains(got, "chain is broken") {
		t.Errorf("show 3 after a torn line:\n%s", got)
	}
	doc, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"show", "3"}) })
	if entry, _ := doc["entry"].(map[string]any); err != nil || entry["seq"] != float64(3) || doc["intact"] != false {
		t.Errorf("show 3 --json: %v %v", doc, err)
	}

	old := w
	t.Cleanup(func() { w = old })
	var errs bytes.Buffer
	w = &out.Writer{Mode: out.Human, Out: io.Discard, Err: &errs}
	file := filepath.Join(t.TempDir(), "archive.jsonl")
	err = cmdAuditLog(root, []string{"export", "-o", file})
	w = old
	written, ferr := os.ReadFile(file)
	if err != nil || ferr != nil || bytes.Count(written, []byte("\n")) != 3 || bytes.Contains(written, []byte(`"at":"2026-10`+"\n")) {
		t.Errorf("export -o after a torn line: %v %v\n%s", err, ferr, written)
	}
	if !strings.Contains(errs.String(), "line 2") || !strings.Contains(errs.String(), "not in this export") {
		t.Errorf("export -o does not say which line it left out: %s", errs.String())
	}
}

// `auditlog show SEQ` checks the log against the heads saved beside it, as
// the listing does: an entry of a log cut back behind its head is shown
// under the warning that the chain does not hold.
func TestShowSeqChecksTheSavedHeads(t *testing.T) {
	root := auditedStore(t, 4)
	if _, err := jsonAnswer(t, func() error { return cmdAuditLog(root, []string{"head", "--save"}) }); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	if err := os.WriteFile(auditPath(root), []byte(strings.Join(lines[:2], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := showing(t, root, "2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "entry 2") || !strings.Contains(got, "chain is broken") || !strings.Contains(got, "shrunk") {
		t.Errorf("show 2 of a log cut back behind its head:\n%s", got)
	}
}
