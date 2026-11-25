// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/register"
)

// A log that gives one key in two spellings a case-insensitive reader takes
// for the same key is refused. Go decodes such a log into its structures by
// the last of the two, and every other reader of the sealed file reads the
// one spelled as the format spells it: a SARIF log whose "Results" is empty
// after "results" lists three findings was read here as a clean scan.
func TestCaseVariantKeysRefused(t *testing.T) {
	for _, key := range []string{"Results", "RESULTS", "reſults"} { // ſ folds to s
		log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},` +
			`"versionControlProvenance":[{"repositoryUri":"https://github.com/example/payments-api"}],` +
			`"results":[{"ruleId":"r1","level":"error","message":{"text":"exec"}}],"` + key + `":[]}]}`
		b, err := Read(Input{Format: FormatSARIF, Body: []byte(log)})
		if !errors.Is(err, ErrUnreadable) {
			f := map[string]register.Observation{}
			if b != nil {
				f = factsOf(t, b)
			}
			t.Errorf("a log giving results as %q too is read, with %q findings: %v", key,
				value(f["https://github.com/example/payments-api code.findings"]), err)
		}
	}

	// The same of a signed envelope: the payload a pinned key signed is
	// spelled one way, and another payload the other.
	seed := sha256.Sum256([]byte("a fixed seed for a test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var env map[string]any
	if err := json.Unmarshal(signed(t, func(m []byte) []byte { return ed25519.Sign(priv, m) }, ""), &env); err != nil {
		t.Fatal(err)
	}
	other, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{"name": "something-else.tar.gz"}}, "predicateType": "https://example.com/p"})
	body := `{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString(other) +
		`","Payload":"` + env["payload"].(string) + `","signatures":` + mustJSON(t, env["signatures"]) + `}`
	_, err := Read(Input{Format: FormatDSSE, Body: []byte(body), Keys: []register.PinnedKey{pinned(t, "build", priv.Public())}})
	if !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "twice") {
		t.Errorf("an envelope with two payloads is read: %v", err)
	}

	// A document read as JSON, and not into a structure, is read by every
	// reader by its exact keys, and two keys of different case are two.
	if err := checkJSON([]byte(`{"status_code":"PASS","Status_Code":"FAIL"}`), false); err != nil {
		t.Errorf("a generic document with keys of two cases is refused: %v", err)
	}
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Two keys of one object that come out as one heading, once each is made a
// label, are refused: which of the two a column read depended on the order
// a map was walked in, so the same file read a fact as true one time and
// false the next, and the one read could be the key a person did not see.
func TestTableKeysThatReadAlikeRefused(t *testing.T) {
	m := &register.ColumnMap{Name: "laptops-json", Makes: "Observation", Format: "json",
		Columns: []register.MapColumn{{Field: "about", Column: "Serial", Asset: "device"}},
		Facts:   []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}}}
	for _, key := range []string{`Encrypted `, `Encrypted​`, `Encrypted\t`} {
		body := `[{"Serial":"C1","Encrypted":"true","` + key + `":"false"}]`
		for range 8 {
			if _, err := Read(Input{Format: FormatJSON, Body: []byte(body), Map: m}); !errors.Is(err, ErrUnreadable) {
				t.Fatalf("an object giving %q and %q is read: %v", "Encrypted", key, err)
			}
		}
	}
}

// A signed file is verified against the keys in the register, whatever
// keys the caller hands over: a key nobody pinned does not make a file
// signed by being passed in.
func TestIngestReadsOnlyPinnedKeys(t *testing.T) {
	w := newWorld(t, false)
	seed := sha256.Sum256([]byte("a fixed seed for a test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	body := signed(t, func(m []byte) []byte { return ed25519.Sign(priv, m) }, "")
	in := Input{Format: FormatDSSE, Body: body, Keys: []register.PinnedKey{pinned(t, "brought-along", priv.Public())}}
	res, err := w.g.Ingest(person, "", in)
	if !errors.Is(err, ErrUnpinned) {
		grade := register.Grade("")
		if res.Batch != nil {
			grade = res.Batch.Grade
		}
		t.Fatalf("a file signed by a key nobody pinned was read, graded %q: %v", grade, err)
	}
	if len(observations(t, w.reg)) != 0 {
		t.Error("a file signed by a key nobody pinned wrote facts")
	}
	key := pinned(t, "build", priv.Public())
	if _, err := w.reg.Put(person, "a key, pinned", key); err != nil {
		t.Fatal(err)
	}
	if res, err := w.g.Ingest(person, "", Input{Format: FormatDSSE, Body: body}); err != nil || res.Batch.Raw.Signer != "build" {
		t.Fatalf("a file signed by a pinned key, with no keys handed over, reads as %v", err)
	}
}

// A pinned key whose fingerprint is not that of its key verifies nothing:
// the fingerprint is what the person who pinned it checked.
func TestPinnedKeyHeldToItsFingerprint(t *testing.T) {
	seed := sha256.Sum256([]byte("a fixed seed for a test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	key := pinned(t, "build", priv.Public())
	key.Fingerprint = register.Digest("sha256:" + strings.Repeat("0", 64))
	body := signed(t, func(m []byte) []byte { return ed25519.Sign(priv, m) }, "")
	if _, err := Read(Input{Format: FormatDSSE, Body: body, Keys: []register.PinnedKey{key}}); !errors.Is(err, ErrUnpinned) ||
		!strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("a key whose fingerprint is another's verified the file: %v", err)
	}
}

// What is written is what the person was shown: an import that says which
// reading a person saw writes nothing when the file reads otherwise now,
// as it does when its column map was changed in between.
func TestImportWritesWhatWasPreviewed(t *testing.T) {
	w := newWorld(t, false)
	m := laptopMap()
	w.confirm(t, m)
	shown, err := Read(Input{Format: FormatCSV, Body: []byte(laptops), Map: m, By: person.Kind})
	if err != nil {
		t.Fatal(err)
	}
	changed := laptopMap()
	changed.Facts = []register.MapFact{{Fact: "disk.encrypted", Column: "Owner"}, {Fact: "owner.label", Column: "Encrypted"}}
	w.confirm(t, changed)
	_, err = w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: changed, Shown: shown.Raw.Yield})
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("a file that reads otherwise than it was shown was written: %v", err)
	}
	if len(observations(t, w.reg)) != 0 {
		t.Fatal("facts nobody was shown were written")
	}
	w.confirm(t, m)
	if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: m, Shown: shown.Raw.Yield}); err != nil {
		t.Fatalf("the file as it was shown is refused: %v", err)
	}
}

// A map handed to an import that is not the one a person confirmed, under
// the same name, is refused: the confirmed map is what reads the table.
func TestUnconfirmedMapRefused(t *testing.T) {
	w := newWorld(t, false)
	w.confirm(t, laptopMap())
	other := laptopMap()
	other.Facts = other.Facts[:1]
	if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: other}); !errors.Is(err, ErrNoMap) ||
		!strings.Contains(err.Error(), "differs") {
		t.Fatalf("a map other than the confirmed one read the table: %v", err)
	}
}

// Nothing is sealed while the audit log cannot record the import: the raw
// store stays empty, and nothing is written.
func TestNothingSealedWhileTheAuditLogCannotRecord(t *testing.T) {
	w := newWorld(t, false)
	w.confirm(t, laptopMap())
	w.reg.Ready = func() error { return errors.New("the audit log's disk is full") }
	if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()}); err == nil ||
		!strings.Contains(err.Error(), "audit log") {
		t.Fatalf("an import the audit log could not record went ahead: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.g.Raw.Dir(), "raw")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file was sealed for an import that could not be recorded: %v", err)
	}
}

// A cell that begins with spaces and then a formula is kept without the
// spaces, so it is a formula as it is kept, and marked as one; and a cell
// that says NaN or +Inf is text, not a number no fact may hold, which
// refused the whole file.
func TestCellsAsTheyAreKept(t *testing.T) {
	body := []byte("Serial,Encrypted\nC1,\"  =HYPERLINK(\"\"http://198.51.100.7/\"\",\"\"yes\"\")\"\nC2,NaN\nC3,+Inf\n")
	m := laptopMap()
	m.Facts = []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}}
	m.Columns[0].Name = ""
	b, err := Read(Input{Format: FormatCSV, Body: body, Map: m})
	if err != nil {
		t.Fatal(err)
	}
	f := factsOf(t, b)
	if o := f["C1 disk.encrypted"]; o.Taint != "formula" || !strings.HasPrefix(value(o), "=HYPERLINK") {
		t.Errorf("a formula after spaces reads %q tainted %q", value(o), o.Taint)
	}
	for _, serial := range []string{"C2", "C3"} {
		o := f[serial+" disk.encrypted"]
		if _, text := o.Value.Value().(string); !text {
			t.Errorf("%s reads %v, which is not text", serial, o.Value.Value())
		}
	}
}

// A table does not say who decided, who read a policy, who stated how a
// control stood, or what a metric was. A Decision, an Acknowledgement and a
// MetricValue are never changed once written, and are made by what they
// record: a table read into one would stand for good, naming a decider or
// a reader who never acted, or a figure nothing computed. A statement read
// from a table is the person's who brings the file, and a column naming
// somebody else as its maker is refused.
func TestMapRefusesWhatATableCannotSay(t *testing.T) {
	for kind, field := range map[string]string{"Decision": "title", "Acknowledgement": "at", "MetricValue": "at"} {
		m := register.ColumnMap{Name: "x", Makes: kind, Format: "csv",
			Columns: []register.MapColumn{{Field: field, Column: "When"}}}
		if err := register.Validate(m); err == nil {
			t.Errorf("a map that reads a table into %s records is accepted", kind)
		}
	}
	forged := register.ColumnMap{Name: "statements", Makes: "Evidence", Format: "json",
		Columns: []register.MapColumn{{Field: "control", Column: "control", Of: "Control"}, {Field: "outcome", Column: "result"},
			{Field: "at", Column: "checked"}, {Field: "attested", Column: "by", ID: true}}}
	if err := register.Validate(forged); err == nil || !strings.Contains(err.Error(), "attested") {
		t.Errorf("a map that reads who stated it from a column is accepted: %v", err)
	}

	w := newWorld(t, false)
	body := []byte(`[{"control":"AC-01","result":"pass","checked":"2026-11-01","by":"d00000000000000000000000000000ff"}]`)
	m := &register.ColumnMap{Name: "statements", Makes: "Evidence", Format: "json",
		Columns: []register.MapColumn{{Field: "control", Column: "control", Of: "Control"}, {Field: "outcome", Column: "result"},
			{Field: "at", Column: "checked"}}}
	w.ingest(t, person, Input{Format: FormatJSON, Body: body, Map: m})
	entries, _, err := w.reg.List(register.KindEvidence, 0, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("%d evidence records, %v", len(entries), err)
	}
	if ev := entries[0].Record.(register.Evidence); ev.Attested != person.Subject {
		t.Errorf("a statement brought by %s is attested by %s", person.Subject, ev.Attested)
	}
	// Read again to be checked, the file yields what it did: the person
	// it was read as is kept with its seal.
	if checks, err := w.g.Verify(); err != nil || len(checks) != 1 || !checks[0].OK() || checks[0].Replay != "same" {
		t.Errorf("the statements' file does not check: %+v, %v", checks, err)
	}
	nameless := person
	nameless.Subject = ""
	w2 := newWorld(t, false)
	w2.confirm(t, m)
	if _, err := w2.g.Ingest(nameless, "", Input{Format: FormatJSON, Body: body, Map: m}); !errors.Is(err, ErrUnreadable) ||
		!strings.Contains(err.Error(), "pseudonym") {
		t.Errorf("a statement brought by somebody the surface names by no pseudonym is read: %v", err)
	}
}

// Filling the raw store is a write, and is recorded as one: a file sealed
// for the first time is an entry in the audit log naming who brought it,
// whether or not it could be read after, and a file sealed again is not.
// A file that could not be read, or a preview nobody confirmed, left bytes
// kept for thirteen months that no record anywhere said who had put there.
func TestEverySealIsRecorded(t *testing.T) {
	w := newWorld(t, false)
	junk := []byte("Serial,Hostname\n\"unterminated\n")
	w.confirm(t, laptopMap())
	if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: junk, Map: laptopMap()}); err == nil {
		t.Fatal("a broken CSV was read")
	}
	seals := func() []audit.Record {
		var out []audit.Record
		for _, r := range w.audited {
			if r.Action == SealAction {
				out = append(out, r)
			}
		}
		return out
	}
	if s := seals(); len(s) != 1 || s[0].Principal != person.Name || s[0].Detail["digest"] != string(digestOf(junk)) {
		t.Fatalf("sealing a file that could not be read is recorded as %+v", s)
	}
	w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})
	w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})
	if s := seals(); len(s) != 2 {
		t.Errorf("two files sealed, one of them twice, are %d entries", len(s))
	}
	if _, err := w.g.Seal(register.Actor{Name: "crew", Kind: audit.KindAI, May: allow}, []byte("x")); !errors.Is(err, register.ErrModel) {
		t.Errorf("a model sealed a file: %v", err)
	}
	w.reg.Audit = nil
	if _, err := w.g.Seal(person, []byte("unrecorded")); err == nil {
		t.Error("a file was sealed with no audit log to record it in")
	}
	if _, err := w.g.Raw.Meta(digestOf([]byte("unrecorded"))); !errors.Is(err, ErrNotHeld) {
		t.Errorf("a file was sealed with no audit log to record it in: %v", err)
	}
}
