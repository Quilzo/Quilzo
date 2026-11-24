// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// Ingester brings files into one register: it seals each in the raw
// evidence store beside the register's store, reads it, and writes what it
// read through register.Put.
type Ingester struct {
	Reg *register.Register
	Raw *Raw
	// Keep is how long a raw file is kept after it was last received. Zero
	// is DefaultKeep.
	Keep time.Duration
	// Now is the clock, for tests. Nil is the system's.
	Now func() time.Time
}

// New is the ingester of a register, with its raw evidence store in the
// store's directory, sealed with the store's own keyring.
func New(reg *register.Register) *Ingester {
	return &Ingester{Reg: reg, Raw: OpenRaw(filepath.Join(reg.Store.Root(), "evidence"), reg.Store)}
}

func (g *Ingester) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// Recorder wires a register that a server opened (the admin's, the content
// API's) to record its writes in the audit log the command line records in,
// and to write nothing while that log cannot take an entry. The program
// sets it; a server it was not set for writes nothing to the register,
// because Put refuses a register with no audit log.
var Recorder func(reg *register.Register)

// Clerk is the name proposals from an import are made under. It is the
// evidence clerk of the security programme: code that seals, reads and
// grades, and proposes what a person has to decide.
const Clerk = "evidence-clerk"

// Result is what an import did.
type Result struct {
	Batch   *Batch           `json:"batch"`
	Sealed  Sealed           `json:"sealed"`
	Receipt register.Receipt `json:"receipt"`
	// Proposed is the receipt of what was proposed for a person, when the
	// file proposed anything new.
	Proposed *register.Receipt `json:"proposed,omitempty"`
	// Expired is the raw files whose time was up, erased as this import
	// began.
	Expired []Sealed `json:"expired,omitempty"`
}

// Prepare reads the column map and the pinned keys an input needs from the
// register: the map by its machine name, and every pinned key.
func (g *Ingester) Prepare(in *Input, mapName string) error {
	if mapName != "" {
		id, err := register.DeriveID(register.KindColumnMap, register.Local, mapName)
		if err != nil {
			return err
		}
		e, err := g.Reg.Get(id)
		if errors.Is(err, register.ErrNotFound) {
			return fmt.Errorf("%w: the register has no column map called %q; a person confirms one first", register.ErrNotFound,
				plaintext.Clip(mapName, 40, "…"))
		}
		if err != nil {
			return err
		}
		m := e.Record.(register.ColumnMap)
		in.Map = &m
	}
	if in.Format == FormatDSSE {
		keys, err := g.PinnedKeys()
		if err != nil {
			return err
		}
		in.Keys = keys
	}
	return nil
}

// PinnedKeys is every key a person has pinned.
func (g *Ingester) PinnedKeys() ([]register.PinnedKey, error) {
	var out []register.PinnedKey
	for offset := 0; ; {
		entries, total, err := g.Reg.List(register.KindPinnedKey, offset, 200)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			out = append(out, e.Record.(register.PinnedKey))
		}
		offset += len(entries)
		if offset >= total || len(entries) == 0 {
			return out, nil
		}
	}
}

// Ingest seals a file, reads it and writes what it read, as by. The file is
// sealed first, before anything parses it, so a file that cannot be read is
// still held, under its hash, for as long as any other.
//
// The records are written in one commit, and a second import of the same
// file writes nothing. What the file proposes is put on the proposals ref
// under the evidence clerk's name, for a person to decide; a proposal
// already decided into the register is not proposed again.
func (g *Ingester) Ingest(by register.Actor, why string, in Input) (Result, error) {
	if len(in.Body) > MaxFile {
		return Result{}, fmt.Errorf("%w: it is %d bytes, and the most read is %d", ErrUnreadable, len(in.Body), MaxFile)
	}
	if len(in.Body) == 0 {
		return Result{}, fmt.Errorf("%w: it is empty", ErrUnreadable)
	}
	switch by.Kind {
	case audit.KindHuman, audit.KindService:
	default:
		// The register refuses the write too; refusing here first keeps a
		// model's file out of the raw store as well.
		return Result{}, fmt.Errorf("%w: a file a model brings is not evidence", register.ErrModel)
	}
	// The access policy before the seal: somebody who may not write the
	// register does not get to fill the raw store either.
	if by.May == nil {
		return Result{}, fmt.Errorf("%w: this surface did not say how to ask it", register.ErrRefused)
	}
	for _, k := range []register.Kind{register.KindObservation, register.KindRawFile} {
		spec, _ := register.SpecOf(string(k))
		if err := by.May(auth.ActEditDraft, spec.Resource()); err != nil {
			return Result{}, fmt.Errorf("%w: %v", register.ErrRefused, err)
		}
	}
	if in.Map != nil {
		if err := g.confirmed(in.Map); err != nil {
			return Result{}, err
		}
	}
	now := g.now()
	expired, err := g.Raw.Expire(now)
	if err != nil {
		return Result{}, err
	}
	sealed, err := g.Raw.Seal(in.Body, now, g.Keep)
	if err != nil {
		return Result{}, fmt.Errorf("the file could not be sealed, so it was not read: %w", err)
	}
	in.By = by.Kind
	in.Received = sealed.Received
	b, err := Read(in)
	if err != nil {
		return Result{Sealed: sealed, Expired: expired}, err
	}
	recs, err := g.withSource(b)
	if err != nil {
		return Result{Sealed: sealed, Expired: expired}, err
	}
	if _, err := g.Raw.PutYield(b.yield); err != nil {
		return Result{Sealed: sealed, Expired: expired}, err
	}
	if why == "" {
		why = fmt.Sprintf("%s file %s, %s", b.Format, string(b.Digest)[7:19], b.Grade)
	}
	rc, err := g.Reg.Put(by, label(why), recs...)
	res := Result{Batch: b, Sealed: sealed, Receipt: rc, Expired: expired}
	if err != nil {
		return res, err
	}
	if fresh := g.unproposed(b.Proposals); len(fresh) > 0 {
		clerk := register.Actor{Name: Clerk, Kind: audit.KindService, Verified: true, May: by.May}
		prc, err := g.Reg.Propose(clerk, label("proposed by "+string(b.Format)+" file "+string(b.Digest)[7:19]), fresh...)
		if err != nil {
			return res, fmt.Errorf("the file's facts were written, and what it proposes was not: %w", err)
		}
		if prc.Commit != "" {
			res.Proposed = &prc
		}
	}
	return res, nil
}

// confirmed refuses a column map that is not in the register as a person
// confirmed it: a map is how a whole table is read, and one a caller made
// up on the way in is a map nobody looked at.
func (g *Ingester) confirmed(m *register.ColumnMap) error {
	id, err := register.IDOf(*m)
	if err != nil {
		return err
	}
	e, err := g.Reg.Get(id)
	if errors.Is(err, register.ErrNotFound) {
		return fmt.Errorf("%w (the map %s is not in the register)", ErrNoMap, m.Name)
	}
	if err != nil {
		return err
	}
	have, _ := FieldsHash(e.Record)
	want, _ := FieldsHash(*m)
	if have != want {
		return fmt.Errorf("%w (the map %s differs from the one confirmed)", ErrNoMap, m.Name)
	}
	return nil
}

// withSource is a batch's records with its source and its seal: a source
// already in the register is used as it stands, and is refused when it
// yields facts of another grade than the file's.
func (g *Ingester) withSource(b *Batch) ([]register.Record, error) {
	recs := make([]register.Record, 0, len(b.Records)+2)
	e, err := g.Reg.Get(b.SourceID)
	switch {
	case errors.Is(err, register.ErrNotFound):
		recs = append(recs, b.Source)
	case err != nil:
		return nil, err
	default:
		have := e.Record.(register.Source)
		if have.Grade != b.Grade {
			return nil, fmt.Errorf("%w: the source %s yields facts graded %s, and this file's are %s; name another source",
				register.ErrInvalid, have.Name, have.Grade, b.Grade)
		}
		b.Source = have
	}
	recs = append(recs, b.Records...)
	return append(recs, b.Raw), nil
}

// unproposed is the proposals that are neither in the register already nor
// waiting the same on the proposals ref.
func (g *Ingester) unproposed(recs []register.Record) []register.Record {
	if len(recs) == 0 {
		return nil
	}
	var out []register.Record
	for _, rec := range recs {
		id, err := register.IDOf(rec)
		if err != nil {
			continue
		}
		if _, err := g.Reg.Get(id); err == nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// Files is the sealed files the register holds a record of, a page at a
// time, each with what the raw store knows of it.
func (g *Ingester) Files(offset, limit int) ([]File, int, error) {
	entries, total, err := g.Reg.List(register.KindRawFile, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	out := make([]File, 0, len(entries))
	for _, e := range entries {
		out = append(out, g.file(e))
	}
	return out, total, nil
}

// File is one sealed file: its record in the register and what the raw
// store knows of it.
type File struct {
	ID     register.ID      `json:"id"`
	Record register.RawFile `json:"record"`
	// Sealed is the raw store's own account; Held says the bytes are kept.
	Sealed  *Sealed   `json:"sealed,omitempty"`
	Held    bool      `json:"held"`
	Updated time.Time `json:"updated"`
	// Problem is why the raw store could not say, when it could not.
	Problem string `json:"problem,omitempty"`
}

func (g *Ingester) file(e register.Entry) File {
	rf := e.Record.(register.RawFile)
	f := File{ID: e.ID, Record: rf, Updated: e.Updated.At()}
	s, err := g.Raw.Meta(rf.Digest)
	if err != nil {
		f.Problem = err.Error()
		return f
	}
	f.Sealed, f.Held = &s, s.Held()
	return f
}

// FileNamed is a sealed file by its record's identifier or by its digest.
func (g *Ingester) FileNamed(name string) (File, error) {
	if register.ID(name).Valid() {
		e, err := g.Reg.Get(register.ID(name))
		if err != nil {
			return File{}, err
		}
		if e.Kind != register.KindRawFile {
			return File{}, fmt.Errorf("%w: %s is a %s, not a sealed file", register.ErrNotFound, name, e.Kind)
		}
		return g.file(e), nil
	}
	if !strings.HasPrefix(name, "sha256:") {
		name = "sha256:" + name
	}
	if _, err := hexOf(register.Digest(name)); err != nil {
		return File{}, fmt.Errorf("%w: %v", register.ErrNotFound, err)
	}
	for offset := 0; ; {
		files, total, err := g.Files(offset, 200)
		if err != nil {
			return File{}, err
		}
		for _, f := range files {
			if string(f.Record.Digest) == name {
				return f, nil
			}
		}
		offset += len(files)
		if offset >= total || len(files) == 0 {
			return File{}, fmt.Errorf("%w: no sealed file has the digest %s", register.ErrNotFound, name)
		}
	}
}

// Check is what Verify found of one sealed file.
type Check struct {
	File File `json:"file"`
	// Seal is whether the bytes still hash to the digest they were read
	// under: "checks", or "erased" once their time was up.
	Seal string `json:"seal"`
	// Yield is whether the list of what was read is beside the seal and
	// hashes to the digest the register holds.
	Yield string `json:"yield"`
	// Replay is whether reading the file again yields the same list:
	// "same", or why it could not be read again.
	Replay string `json:"replay"`
	// Facts is how many records the list names; Standing is how many are in
	// the register as they were read; Superseded how many a later file has
	// replaced since; Changed how many were changed by anything else.
	Facts      int      `json:"facts"`
	Standing   int      `json:"standing"`
	Superseded int      `json:"superseded"`
	Changed    int      `json:"changed"`
	Problems   []string `json:"problems,omitempty"`
}

// OK reports whether nothing was found wrong.
func (c Check) OK() bool { return len(c.Problems) == 0 }

// Verify checks sealed files: the named ones, or every one the register
// holds a record of. A file whose bytes were erased when its time was up
// still checks: its seal, the list of what was read from it and every fact
// that list names.
func (g *Ingester) Verify(names ...string) ([]Check, error) {
	var files []File
	if len(names) == 0 {
		for offset := 0; ; {
			page, total, err := g.Files(offset, 200)
			if err != nil {
				return nil, err
			}
			files = append(files, page...)
			offset += len(page)
			if offset >= total || len(page) == 0 {
				break
			}
		}
	}
	for _, n := range names {
		f, err := g.FileNamed(n)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	out := make([]Check, 0, len(files))
	for _, f := range files {
		out = append(out, g.check(f))
	}
	return out, nil
}

func (g *Ingester) check(f File) Check {
	c := Check{File: f}
	rf := f.Record
	problem := func(format string, args ...any) { c.Problems = append(c.Problems, fmt.Sprintf(format, args...)) }
	body, err := g.Raw.Open(rf.Digest)
	var gone *Expired
	switch {
	case err == nil:
		c.Seal = "checks"
		if int64(len(body)) != rf.Size {
			problem("the file is %d bytes and its record says %d", len(body), rf.Size)
		}
	case errors.As(err, &gone):
		c.Seal = "erased"
	default:
		c.Seal = "missing"
		problem("the raw file: %v", err)
	}
	list, err := g.Raw.Yield(rf.Yield)
	if err != nil {
		c.Yield = "missing"
		problem("the list of what was read from it: %v", err)
	} else {
		c.Yield = "checks"
		g.checkFacts(&c, rf, list, problem)
	}
	switch {
	case body == nil:
		c.Replay = "not possible: the file is not held"
	case list == nil:
		c.Replay = "not possible: there is no list to compare with"
	default:
		c.Replay = g.replay(rf, body, list)
		if c.Replay != "same" {
			problem("read again, the file yields another list: %s", c.Replay)
		}
	}
	return c
}

// checkFacts holds each record the list names to the register: there, and
// as it was read, or replaced by a later read of another file.
func (g *Ingester) checkFacts(c *Check, rf register.RawFile, list []byte, problem func(string, ...any)) {
	for _, line := range strings.Split(strings.TrimRight(string(list), "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			problem("the list has a line that names no record")
			continue
		}
		c.Facts++
		e, err := g.Reg.Get(register.ID(parts[1]))
		if err != nil {
			problem("the %s %s it yielded is not in the register", strings.ToLower(parts[0]), parts[1])
			continue
		}
		hash, err := FieldsHash(e.Record)
		if err != nil || hash == parts[2] {
			c.Standing++
			continue
		}
		raw, holds := rawOf(e.Record)
		switch {
		case holds && raw != rf.Digest:
			c.Superseded++
		case !holds:
			// An asset's name is a label and changes with the file that
			// last named it; it carries no raw digest of its own.
			c.Superseded++
		default:
			c.Changed++
			problem("the %s %s was changed after it was read, and not by a later file", strings.ToLower(parts[0]), parts[1])
		}
	}
	if int64(c.Facts) != rf.Facts {
		problem("the list names %d records and the seal's record says %d", c.Facts, rf.Facts)
	}
}

// rawOf is the raw digest a record says it was read from, and whether its
// kind holds one.
func rawOf(rec register.Record) (register.Digest, bool) {
	b, _ := json.Marshal(rec)
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return "", false
	}
	spec, _ := register.SpecOf(string(rec.Kind()))
	for _, f := range spec.Fields {
		if f.Name == "raw" {
			var d register.Digest
			_ = json.Unmarshal(fields["raw"], &d)
			return d, true
		}
	}
	return "", false
}

// replay reads a held file again as it was read the first time, and says
// whether the list is the same.
func (g *Ingester) replay(rf register.RawFile, body, list []byte) string {
	in := Input{Format: Format(rf.Format), Body: body, By: audit.KindHuman, Received: rf.Received.At()}
	if e, err := g.Reg.Get(rf.Source); err == nil {
		in.Source = e.Record.(register.Source).Name
	}
	if rf.Map != "" {
		e, err := g.Reg.Get(rf.Map)
		if err != nil {
			return "not possible: its column map is not in the register"
		}
		m := e.Record.(register.ColumnMap)
		in.Map = &m
	}
	if rf.Grade == register.GradeImported && (in.Map == nil || in.Map.Tool == "") {
		in.By = audit.KindService
	}
	if in.Format == FormatDSSE {
		keys, err := g.PinnedKeys()
		if err != nil {
			return "not possible: " + err.Error()
		}
		in.Keys = keys
	}
	b, err := Read(in)
	if err != nil {
		return "it no longer reads: " + err.Error()
	}
	if !bytes.Equal(b.yield, list) {
		return fmt.Sprintf("%d records now, and %d then", len(b.Facts), strings.Count(string(list), "\n"))
	}
	return "same"
}

// Expire erases the raw files whose time to be kept is up.
func (g *Ingester) Expire() ([]Sealed, error) { return g.Raw.Expire(g.now()) }
