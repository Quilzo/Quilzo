// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
)

// calendarAnswer is what a calendar answers a digest with: a pending proof
// that commits to it and names the calendar to ask again.
func calendarAnswer(calendar string) []byte {
	b := append([]byte{0xf0, 8}, "12345678"...) // append eight bytes
	b = append(b, 0x08, 0x00)                   // SHA-256, then an attestation
	b = append(b, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e)
	uri := append([]byte{byte(len(calendar))}, calendar...)
	return append(append(b, byte(len(uri))), uri...)
}

// fakeCalendars stands in for the public calendars.
type fakeCalendars struct{}

func (fakeCalendars) Post(_ context.Context, url string, _ []byte) ([]byte, error) {
	return calendarAnswer(strings.TrimSuffix(url, "/digest")), nil
}

func (fakeCalendars) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("404")
}

// `anchor status` and the proof's description said "ots verify anchor.ots",
// and nothing wrote that file: a proof is kept as the calendar's bytes in
// anchors.json, with no header, which the client cannot read. `anchor
// export` writes each proof as the standard file.
func TestAnAnchorIsExportedAsTheFileTheOtsClientReads(t *testing.T) {
	root, live := publishedStore(t)
	proof := anchor.Proof{Digest: live, Calendar: anchor.Calendars[0],
		Body: calendarAnswer(anchor.Calendars[0]), State: anchor.Pending,
		Kind: anchor.Publication, SubmittedAt: "2026-11-01T10:00:00Z"}
	d, _ := hex.DecodeString(live)
	if _, err := anchor.Walk(d, proof.Body); err != nil {
		t.Fatalf("the test's proof does not commit to its digest: %v", err)
	}
	if err := saveJSON(anchorPath(root), &anchorFile{Proofs: []anchor.Proof{proof}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := cmdAnchor(root, []string{"export", "--dir", dir}); err != nil {
		t.Fatalf("no proof can be written for the ots client: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.ots"))
	if len(files) != 1 {
		t.Fatalf("%d .ots files for one proof", len(files))
	}
	got, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	want, err := anchor.File(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || !bytes.HasPrefix(got, []byte("\x00OpenTimestamps\x00\x00Proof\x00")) {
		t.Fatalf("%s is not the detached timestamp of the proof", files[0])
	}
}

// `auditlog anchor` appends the log head's proofs to the same file as a
// publication's, and nothing told them apart: the Integrity screen listed
// every log head as evidence of when something was published. A record
// kept before proofs said which is read as before, a publication, unless
// its digest is a log head the store saved.
func TestALogHeadAnchorIsNotShownAsAPublication(t *testing.T) {
	root, live := publishedStore(t)
	head := strings.Repeat("cd", 32)
	if err := saveJSON(headsPath(root), &headFile{Heads: []audit.Head{{Size: 3, Root: head,
		At: "2026-11-01T09:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(anchorPath(root), &anchorFile{Proofs: []anchor.Proof{
		{Digest: head, Calendar: anchor.Calendars[0], State: anchor.Pending, SubmittedAt: "2026-11-01T09:01:00Z"},
		{Digest: live, Calendar: anchor.Calendars[0], State: anchor.Pending, SubmittedAt: "2026-11-01T10:01:00Z"},
	}}); err != nil {
		t.Fatal(err)
	}

	rows, err := evidenceRows(root)
	if err != nil {
		t.Fatal(err)
	}
	kind := map[string]string{}
	for _, r := range rows {
		kind[r.Subject] = r.Kind
	}
	if kind[live] != "anchor" {
		t.Errorf("a publication's anchor is shown as %q", kind[live])
	}
	if kind[head] == "anchor" || !strings.Contains(kind[head], "log") {
		t.Errorf("the audit log's head is shown as %q, which reads as a publication", kind[head])
	}

	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := anchorStatus(root); err != nil {
		t.Fatal(err)
	}
	var file anchorFile
	if err := json.Unmarshal(buf.Bytes(), &file); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	for _, p := range file.Proofs {
		want := map[string]string{head: anchor.LogHead, live: anchor.Publication}[p.Digest]
		if p.Kind != want {
			t.Errorf("anchor status says %s is %q, not %q", short(p.Digest), p.Kind, want)
		}
	}
}

// A proof is kept with what it is about from the moment it is written.
func TestEachAnchorIsKeptWithWhatItIsAbout(t *testing.T) {
	root, live := publishedStore(t)
	saved := anchorCalendars
	anchorCalendars = func() anchor.Submitter { return fakeCalendars{} }
	t.Cleanup(func() { anchorCalendars = saved })

	record(root, audit.Record{Action: "test.entry", Resource: "/", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true})
	if err := anchorSubmit(root, nil); err != nil {
		t.Fatal(err)
	}
	if err := auditAnchor(root); err != nil {
		t.Fatal(err)
	}
	file, err := loadAnchors(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, logs := 0, 0
	for _, p := range file.Proofs {
		switch {
		case p.Digest == live && p.Kind == anchor.Publication:
			pub++
		case p.Digest != live && p.Kind == anchor.LogHead:
			logs++
		default:
			t.Errorf("%s is kept as %q", short(p.Digest), p.Kind)
		}
	}
	if pub == 0 || logs == 0 {
		t.Errorf("%d publication and %d log-head proofs kept", pub, logs)
	}
}

// A file is named by the proof's kind, digest and calendar, and one digest
// can have two proofs from one calendar: the same log head anchored twice
// before anything was written between. The second was written over the
// first, and both were listed under the one name, so one proof never left.
func TestEveryProofIsExportedToAFileOfItsOwn(t *testing.T) {
	root, _ := publishedStore(t)
	head := strings.Repeat("cd", 32)
	if err := saveJSON(headsPath(root), &headFile{Heads: []audit.Head{{Size: 3, Root: head,
		At: "2026-11-01T09:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	first := calendarAnswer(anchor.Calendars[0])
	second := append([]byte{0xf0, 8}, "87654321"...) // another nonce, the same calendar
	second = append(second, first[10:]...)
	d, _ := hex.DecodeString(head)
	for _, body := range [][]byte{first, second} {
		if _, err := anchor.Walk(d, body); err != nil {
			t.Fatalf("the test's proof does not commit to its digest: %v", err)
		}
	}
	if err := saveJSON(anchorPath(root), &anchorFile{Proofs: []anchor.Proof{
		{Digest: head, Calendar: anchor.Calendars[0], Body: first, State: anchor.Pending,
			Kind: anchor.LogHead, SubmittedAt: "2026-11-01T09:01:00Z"},
		{Digest: head, Calendar: anchor.Calendars[0], Body: second, State: anchor.Pending,
			Kind: anchor.LogHead, SubmittedAt: "2026-11-01T09:02:00Z"},
	}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := cmdAnchor(root, []string{"export", "--dir", dir}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.ots"))
	if len(files) != 2 {
		t.Fatalf("%d .ots files for two proofs: %v", len(files), files)
	}
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(b)] = true
	}
	if len(seen) != 2 {
		t.Error("two proofs were exported as the same file")
	}
}
