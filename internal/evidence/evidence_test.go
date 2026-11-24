// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/vault"
)

// clock is a fake clock a test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

var day0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

// world is a register on a store of its own, an ingester for it on a fake
// clock, and the audit entries it wrote.
type world struct {
	reg     *register.Register
	g       *Ingester
	clock   *clock
	audited []audit.Record
}

func newWorld(t testing.TB, encrypted bool) *world {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		kr, err := vault.NewKeyring("k1", day0)
		if err != nil {
			t.Fatal(err)
		}
		s.WithKeys(kr)
	}
	w := &world{reg: register.Open(s), clock: &clock{t: day0}}
	w.reg.Audit = func(r audit.Record) error { w.audited = append(w.audited, r); return nil }
	w.reg.Now = w.clock.now
	w.g = New(w.reg)
	w.g.Now = w.clock.now
	return w
}

func allow(auth.Action, string) error { return nil }

var (
	person  = register.Actor{Name: "priya", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, Verified: true, May: allow}
	service = register.Actor{Name: "nightly-export", Kind: audit.KindService, Verified: true, May: allow}
)

// laptops is a person's own list of laptops, and the map they confirmed for
// it: the serial names the laptop, and two columns are facts about it.
const laptops = "Serial,Hostname,Encrypted,Owner\nC02X1,mac-01,true,ann\nC02X2,mac-02,false,bob\nC02X3,mac-03,true,cat\n"

func laptopMap() *register.ColumnMap {
	return &register.ColumnMap{Name: "laptops", Makes: "Observation", Format: "csv",
		Columns: []register.MapColumn{{Field: "about", Column: "Serial", Asset: "device", Name: "Hostname"}},
		Facts:   []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}, {Fact: "owner.label", Column: "Owner"}}}
}

func (w *world) ingest(t testing.TB, by register.Actor, in Input) Result {
	t.Helper()
	if in.Map != nil {
		w.confirm(t, in.Map)
	}
	res, err := w.g.Ingest(by, "", in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// confirm puts a column map in the register, as the person who looked at
// what it reads.
func (w *world) confirm(t testing.TB, m *register.ColumnMap) {
	t.Helper()
	if _, err := w.reg.Put(person, "a column map, confirmed", *m); err != nil {
		t.Fatal(err)
	}
}

func observations(t testing.TB, reg *register.Register) []register.Observation {
	t.Helper()
	entries, _, err := reg.List(register.KindObservation, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []register.Observation
	for _, e := range entries {
		out = append(out, e.Record.(register.Observation))
	}
	return out
}

// A file is sealed in the raw evidence store under its SHA-256 before it
// is read; every fact it yields names that digest; the bytes read back are
// the bytes received; on an encrypted store they are not in the clear; and
// a file that cannot be read is sealed all the same, which is the order.
func TestImportSealsRawByHash(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		w := newWorld(t, encrypted)
		body := []byte(laptops)
		sum := sha256.Sum256(body)
		want := register.Digest("sha256:" + hex.EncodeToString(sum[:]))

		res := w.ingest(t, person, Input{Format: FormatCSV, Body: body, Map: laptopMap()})
		if res.Batch.Digest != want || res.Sealed.Digest != want || res.Batch.Raw.Digest != want {
			t.Fatalf("the file is sealed as %s and read as %s, not %s", res.Sealed.Digest, res.Batch.Digest, want)
		}
		got, err := w.g.Raw.Open(want)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("the sealed bytes read back as %q, %v", got, err)
		}
		obs := observations(t, w.reg)
		if len(obs) != 6 {
			t.Fatalf("%d observations were written of 6", len(obs))
		}
		for _, o := range obs {
			if o.Raw != want || o.Place == "" {
				t.Errorf("the fact %s names the raw file %q at %q", o.Fact, o.Raw, o.Place)
			}
		}
		e, err := w.reg.Get(res.Batch.RawID)
		if err != nil {
			t.Fatal(err)
		}
		if rf := e.Record.(register.RawFile); rf.Facts != int64(len(res.Batch.Facts)) || rf.Size != int64(len(body)) {
			t.Errorf("the seal's record is %+v", rf)
		}

		onDisk, err := os.ReadFile(filepath.Join(w.g.Raw.Dir(), "raw", string(want[7:9]), string(want[9:])))
		if err != nil {
			t.Fatal(err)
		}
		if clear := bytes.Contains(onDisk, []byte("C02X1")); clear == encrypted {
			t.Errorf("encrypted=%v: the raw file is in the clear on disk: %v", encrypted, clear)
		}

		junk := []byte("Serial,Hostname\n\"unterminated\n")
		w.confirm(t, laptopMap())
		if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: junk, Map: laptopMap()}); err == nil {
			t.Fatal("a broken CSV was read")
		}
		if _, err := w.g.Raw.Open(digestOf(junk)); err != nil {
			t.Errorf("a file that could not be read was not sealed first: %v", err)
		}
	}
}

// A second import of the same file writes nothing: no commit, no audit
// entry, every record unchanged, and the seal's first receipt is the same
// although the clock has moved.
func TestReimportIdempotent(t *testing.T) {
	w := newWorld(t, false)
	first := w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})
	if first.Receipt.Commit == "" {
		t.Fatal("the first import wrote nothing")
	}
	head, entries := w.reg.Head(), len(w.audited)
	w.clock.t = w.clock.t.Add(48 * time.Hour)
	again := w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})
	if again.Receipt.Commit != "" || len(again.Receipt.Written) != 0 {
		t.Fatalf("the second import wrote %d records in %s", len(again.Receipt.Written), again.Receipt.Commit)
	}
	// The source is in the register already, and is used as it stands.
	if again.Receipt.Unchanged != len(first.Batch.Records)+1 {
		t.Errorf("%d records were found unchanged, of %d", again.Receipt.Unchanged, len(first.Receipt.Written))
	}
	if w.reg.Head() != head || len(w.audited) != entries {
		t.Error("the second import moved the register or wrote to the audit log")
	}
	if !again.Sealed.Received.Equal(first.Sealed.Received) || !again.Sealed.Last.After(first.Sealed.Last) {
		t.Errorf("the seal says first received %v then %v, last %v then %v", first.Sealed.Received, again.Sealed.Received,
			first.Sealed.Last, again.Sealed.Last)
	}
	all, _ := w.g.Raw.List()
	if len(all) != 1 {
		t.Errorf("the raw store holds %d files for one", len(all))
	}
}

// Once a raw file's time is up its bytes are erased, and every fact it
// yielded still checks: against the seal, and against the list of what was
// read, whose digest the register holds. A fact changed after it was read,
// and not by a later file, is found; so is a list changed beside the seal.
func TestFactsVerifyAfterRawExpiry(t *testing.T) {
	w := newWorld(t, false)
	w.g.Keep = 30 * 24 * time.Hour
	res := w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})

	checks, err := w.g.Verify()
	if err != nil || len(checks) != 1 {
		t.Fatalf("verify: %v, %d", err, len(checks))
	}
	if c := checks[0]; !c.OK() || c.Seal != "checks" || c.Replay != "same" || c.Standing != c.Facts || c.Facts != 9 {
		t.Fatalf("before expiry: %+v", c)
	}

	if gone, _ := w.g.Expire(); len(gone) != 0 {
		t.Fatal("a raw file was erased before its time")
	}
	w.clock.t = w.clock.t.Add(31 * 24 * time.Hour)
	gone, err := w.g.Expire()
	if err != nil || len(gone) != 1 {
		t.Fatalf("expire: %v, %d", err, len(gone))
	}
	var exp *Expired
	if _, err := w.g.Raw.Open(res.Batch.Digest); !errors.As(err, &exp) {
		t.Fatalf("an erased file reads as %v", err)
	}
	checks, err = w.g.Verify(string(res.Batch.Digest))
	if err != nil {
		t.Fatal(err)
	}
	c := checks[0]
	if !c.OK() || c.Seal != "erased" || c.Yield != "checks" || c.Standing != 9 || c.File.Held {
		t.Fatalf("after expiry: %+v", c)
	}

	// A fact changed by hand, under the same raw digest, is found.
	obs := observations(t, w.reg)
	o := obs[0]
	o.Value = register.TextValue("changed")
	if _, err := w.reg.Put(person, "a change by hand", o); err != nil {
		t.Fatal(err)
	}
	c = must(w.g.Verify(string(res.Batch.RawID)))[0]
	if c.OK() || c.Changed != 1 || !strings.Contains(strings.Join(c.Problems, " "), "changed after it was read") {
		t.Errorf("a fact changed by hand: %+v", c)
	}

	// A list changed beside the seal is found by its digest.
	h, _ := hexOf(res.Batch.Raw.Yield)
	if err := os.WriteFile(filepath.Join(w.g.Raw.Dir(), "yield", h), []byte("Asset x y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = must(w.g.Verify())[0]
	if c.OK() || c.Yield != "missing" {
		t.Errorf("a changed list: %+v", c)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Every fact carries its grade, and the grade is how the file came in: a
// person's table is uploaded, a GRC tool's export through a map that names
// the tool is imported, a file a service pushed is imported. The index
// holds each fact's grade.
func TestGradeRecordedPerFact(t *testing.T) {
	w := newWorld(t, false)
	w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})

	tool := laptopMap()
	tool.Name, tool.Tool = "grc-devices", "a GRC tool's device list"
	w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: tool})

	pushed := laptopMap()
	pushed.Name = "pushed-laptops"
	w.ingest(t, service, Input{Format: FormatCSV, Body: []byte(laptops), Map: pushed})

	bySource := map[string]register.Grade{}
	for _, o := range observations(t, w.reg) {
		e, err := w.reg.Get(o.Source)
		if err != nil {
			t.Fatal(err)
		}
		src := e.Record.(register.Source)
		if o.Grade == "" || o.Grade != src.Grade {
			t.Errorf("a fact from %s is graded %q and its source %q", src.Name, o.Grade, src.Grade)
		}
		bySource[src.Name] = o.Grade
	}
	for name, want := range map[string]register.Grade{"uploaded-laptops": register.GradeUploaded,
		"imported-grc-devices": register.GradeImported, "imported-pushed-laptops": register.GradeImported} {
		if bySource[name] != want {
			t.Errorf("the facts of %s are graded %q, not %q", name, bySource[name], want)
		}
	}
	ix, err := w.reg.Index()
	if err != nil {
		t.Fatal(err)
	}
	rows := ix.Rows(register.KindObservation)
	if len(rows) != 18 {
		t.Fatalf("the index holds %d observations of 18", len(rows))
	}
	for _, r := range rows {
		if r.Grade == 0 {
			t.Error("an observation is indexed with no grade")
		}
	}
}

// What a person uploads by hand is graded uploaded, whatever made the file,
// and nothing the person or the file says raises it: a source that yields
// facts of another grade is refused.
func TestPersonUploadGradedUploaded(t *testing.T) {
	w := newWorld(t, false)
	res := w.ingest(t, person, Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()})
	if res.Batch.Grade != register.GradeUploaded || res.Batch.Source.Type != "upload" {
		t.Fatalf("a person's upload is graded %s under a source of type %s", res.Batch.Grade, res.Batch.Source.Type)
	}
	for _, o := range observations(t, w.reg) {
		if o.Grade != register.GradeUploaded {
			t.Errorf("the fact %s is graded %s", o.Fact, o.Grade)
		}
	}
	w.confirm(t, laptopMap())
	_, err := w.g.Ingest(service, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap(), Source: "uploaded-laptops"})
	if err == nil || !strings.Contains(err.Error(), "graded uploaded") {
		t.Errorf("a service's file was filed under a person's upload source: %v", err)
	}
}

// A model brings no evidence: its file is refused before it is sealed.
func TestModelFileRefusedBeforeSeal(t *testing.T) {
	w := newWorld(t, false)
	model := register.Actor{Name: "crew", Kind: audit.KindAI, May: allow}
	w.confirm(t, laptopMap())
	if _, err := w.g.Ingest(model, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()}); !errors.Is(err, register.ErrModel) {
		t.Fatalf("a model's file: %v", err)
	}
	if all, _ := w.g.Raw.List(); len(all) != 0 {
		t.Error("a model's file was sealed")
	}
	refused := register.Actor{Name: "rita", Kind: audit.KindHuman, May: func(auth.Action, string) error { return errors.New("no") }}
	if _, err := w.g.Ingest(refused, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: laptopMap()}); !errors.Is(err, register.ErrRefused) {
		t.Fatalf("a person the policy refuses: %v", err)
	}
	if all, _ := w.g.Raw.List(); len(all) != 0 {
		t.Error("a refused person's file was sealed")
	}
}
