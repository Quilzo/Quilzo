// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package evidence brings evidence in from files: it seals each file by its
// hash before anything reads it, reads it as hostile, and turns what it
// says into the register's records, each with its grade and the place in
// the file it was read from.
//
// # What happens to a file
//
//  1. It is sealed in the raw evidence store (raw.go) under its SHA-256,
//     before a byte of it is parsed. What is read is the file that was
//     sealed, so the facts can always be followed back to bytes that were
//     never changed.
//  2. A reader for its format turns it into records: assets, observations
//     and, from a table a person mapped, any kind the register takes from
//     a table. Every fact carries its grade, the digest of the file, the
//     place it was read from (a cell, a row, a JSON pointer) and, where
//     that place was one a person opening the file would not see, a taint.
//  3. The list of what was read, a line for each record with the hash of
//     its fields, is kept beside the seal, and its digest goes in the
//     file's RawFile record. The raw file can then expire and every fact it
//     yielded still checks against the seal (ingest.go, Verify).
//  4. The records are written through register.Put, in one commit, as the
//     person or service who brought the file. Nothing a file proposes about
//     how the organisation's controls relate to a framework is written: it
//     waits on the proposals ref for a person.
//
// A second import of the same file writes nothing at all.
//
// # The grade is how the file came in, never what it says
//
// A file cannot raise its own grade. A table a person made or a tool's
// output a person uploaded is "uploaded"; a GRC tool's export read through
// a column map that names the tool, or a file a service pushed, is
// "imported"; a DSSE envelope whose signature checks against a key a
// person pinned is "signed". A connector's pull and a pipeline's push are
// graded by the modules that do them, never here.
//
// # Every file is hostile
//
// Each reader holds its input to a size, a depth and a count of records; a
// JSON document with a key given twice is refused, because two readers
// would read different values; a workbook is read by internal/xlsx, which
// refuses zip and XML bombs, works out no formula and marks what is
// hidden; nothing a file names is fetched. Text from a file reaches the
// register only as a label, one plain visible line, and never as a figure,
// a status or a date that code did not parse.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// Format is how a file is read.
type Format string

const (
	FormatCSV       Format = "csv"
	FormatXLSX      Format = "xlsx"
	FormatJSON      Format = "json"
	FormatOCSF      Format = "ocsf"
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
	FormatSARIF     Format = "sarif"
	FormatCSAF      Format = "csaf"
	FormatOpenVEX   Format = "openvex"
	FormatDSSE      Format = "dsse"
	FormatOsquery   Format = "osquery"
)

// FormatInfo says what a format is, for the help and the import screen.
type FormatInfo struct {
	Format Format `json:"format"`
	// Reads is what files it reads, in a line.
	Reads string `json:"reads"`
	// Mapped says the format is a table read through a column map.
	Mapped bool `json:"mapped,omitempty"`
	// Also is what else the format may be called on the command line.
	Also []string `json:"also,omitempty"`
}

// Formats is every format, in the order the help lists them.
func Formats() []FormatInfo {
	return []FormatInfo{
		{FormatCSV, "a table of comma-separated values, through a confirmed column map", true, nil},
		{FormatXLSX, "an Excel workbook, through a confirmed column map; hidden parts are marked", true, nil},
		{FormatJSON, "a JSON list of records, through a confirmed column map", true, nil},
		{FormatOCSF, "OCSF 1.1 to 1.5 findings, as Prowler and cloud security hubs write them", false, nil},
		{FormatCycloneDX, "a CycloneDX software bill of materials in JSON, with its VEX statements", false, []string{"sbom"}},
		{FormatSPDX, "an SPDX 2.2 or 2.3 software bill of materials in JSON", false, nil},
		{FormatSARIF, "a SARIF 2.1.0 log from a code scanner", false, nil},
		{FormatCSAF, "a CSAF 2.0 security advisory or VEX document", false, nil},
		{FormatOpenVEX, "an OpenVEX document", false, []string{"vex"}},
		{FormatDSSE, "a DSSE envelope, verified against a pinned key, holding an in-toto statement or a bill of materials", false, nil},
		{FormatOsquery, "osquery result logs and Fleet query reports", false, []string{"fleet"}},
	}
}

// FormatNamed is the format a person named, by its name or another it is
// called by, in any letter case.
func FormatNamed(name string) (Format, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, f := range Formats() {
		if string(f.Format) == name {
			return f.Format, true
		}
		for _, a := range f.Also {
			if a == name {
				return f.Format, true
			}
		}
	}
	return "", false
}

func (f Format) mapped() bool { return f == FormatCSV || f == FormatXLSX || f == FormatJSON }

// The limits every reader is held to. A file larger than MaxFile is not
// evidence anybody exported, it is a way to exhaust memory; a record count
// past MaxRecords is a register written by a file.
const (
	MaxFile    = 64 << 20
	MaxRecords = 200_000
	MaxDepth   = 64
)

var (
	// ErrUnreadable is a file the reader for its format refuses: not that
	// format, beyond a limit, or saying something no reader can take.
	ErrUnreadable = errors.New("the file cannot be read as evidence")
	// ErrNoMap is a table brought without a column map a person confirmed.
	ErrNoMap = errors.New("a table is read through a column map a person has confirmed")
	// ErrUnpinned is a signed file no pinned key verifies.
	ErrUnpinned = errors.New("no pinned key verifies the signature")
)

// Input is a file as it arrives, and what is known about how it came.
type Input struct {
	Format Format
	Body   []byte
	// Source is the machine name of the source its facts are filed under.
	// Empty is the format's own, named for how the file came in.
	Source string
	// By is whether a person or a service brought it, which is half of its
	// grade. Nothing else a caller says changes the grade.
	By audit.Kind
	// Map is the confirmed column map a table is read with.
	Map *register.ColumnMap
	// Keys are the pinned keys a signed file is verified against.
	Keys []register.PinnedKey
	// Received is when the file was first sealed. Zero is now.
	Received time.Time
}

// Fact is one record a file yielded, as a preview shows it and as the list
// kept beside the seal names it.
type Fact struct {
	Kind register.Kind `json:"kind"`
	ID   register.ID   `json:"id"`
	// Hash is the SHA-256 of the record's fields as they were read.
	Hash  string         `json:"hash"`
	Place string         `json:"place,omitempty"`
	Taint register.Taint `json:"taint,omitempty"`
	// Name and Value are what a person reads in a preview: the record's
	// label, or a fact's name, and the value read.
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// Flag is one thing in a file that a person opening it would not see,
// said once for the file.
type Flag struct {
	Taint register.Taint `json:"taint"`
	Where string         `json:"where"`
}

// Batch is what a file yields, before anything is written.
type Batch struct {
	Format Format          `json:"format"`
	Digest register.Digest `json:"digest"`
	Size   int64           `json:"size"`
	Grade  register.Grade  `json:"grade"`
	// Source is the source its facts are filed under. A source already in
	// the register is used as it stands and not written again.
	Source   register.Source `json:"source"`
	SourceID register.ID     `json:"source_id"`
	// Raw is the file's seal record, and RawID its identifier.
	Raw   register.RawFile `json:"raw"`
	RawID register.ID      `json:"raw_id"`
	// Records is what was read, in the order of their identifiers.
	Records []register.Record `json:"-"`
	// Proposals wait for a person: they are never written by an import.
	Proposals []register.Record `json:"-"`
	Facts     []Fact            `json:"facts"`
	Proposed  []Fact            `json:"proposed,omitempty"`
	Flags     []Flag            `json:"flags,omitempty"`
	// Notes are what the reader says about the file in plain words: what
	// it did not read, and why.
	Notes []string `json:"notes,omitempty"`

	yield []byte
}

// Yield is the list of what was read, a line for each record: its kind,
// its identifier and the SHA-256 of its fields. It is what the RawFile's
// Yield digest is of.
func (b *Batch) Yield() []byte { return b.yield }

// Tainted is how many of the facts were read from a part of the file a
// person opening it would not see.
func (b *Batch) Tainted() int {
	n := 0
	for _, f := range b.Facts {
		if f.Taint != "" {
			n++
		}
	}
	return n
}

// GradeFor is the grade of what a file yields, from how it came in: the
// format, who brought it and the map it was read with. A signed file's
// grade is given only once its signature has checked (dsse.go).
func GradeFor(f Format, by audit.Kind, m *register.ColumnMap) register.Grade {
	switch {
	case f == FormatDSSE:
		return register.GradeSigned
	case f.mapped() && m != nil && m.Tool != "":
		return register.GradeImported
	case by == audit.KindService:
		return register.GradeImported
	}
	return register.GradeUploaded
}

// DefaultSource is the machine name of the source a file's facts are filed
// under when the person names none: how it came in, and what it is.
func DefaultSource(f Format, g register.Grade, m *register.ColumnMap) string {
	what := string(f)
	if m != nil {
		what = m.Name
	}
	return slug(string(g) + "-" + what)
}

// sourceType is the source type a grade comes in by.
func sourceType(g register.Grade) register.SourceType {
	if g == register.GradeUploaded || g == register.GradeScreenshot {
		return "upload"
	}
	return "import"
}

// DefaultFresh is how long the facts of a source made for a file are taken
// as current: thirty days, after which the source is stale until a newer
// file comes.
const DefaultFresh = 30 * 24 * 60 * 60

// Read reads a file into records and writes nothing. It is the preview, and
// it is the read Ingest does after sealing.
func Read(in Input) (*Batch, error) {
	if len(in.Body) > MaxFile {
		return nil, fmt.Errorf("%w: it is %d bytes, and the most read is %d", ErrUnreadable, len(in.Body), MaxFile)
	}
	if len(in.Body) == 0 {
		return nil, fmt.Errorf("%w: it is empty", ErrUnreadable)
	}
	if _, ok := FormatNamed(string(in.Format)); !ok {
		return nil, fmt.Errorf("%w: %q is not a format this reads; the formats are %s", ErrUnreadable,
			plaintext.Clip(string(in.Format), 40, "…"), formatNames())
	}
	if in.Format.mapped() {
		if in.Map == nil {
			return nil, ErrNoMap
		}
		if string(in.Map.Format) != string(in.Format) {
			return nil, fmt.Errorf("%w: the map %s reads %s files, and this is %s", ErrUnreadable, in.Map.Name, in.Map.Format, in.Format)
		}
		if err := register.Validate(*in.Map); err != nil {
			return nil, fmt.Errorf("%w: the map %s: %v", ErrUnreadable, in.Map.Name, err)
		}
	} else if in.Map != nil {
		return nil, fmt.Errorf("%w: only a table is read through a column map, and this is %s", ErrUnreadable, in.Format)
	}
	grade := GradeFor(in.Format, in.By, in.Map)
	name := in.Source
	if name == "" {
		name = DefaultSource(in.Format, grade, in.Map)
	}
	src := register.Source{Name: name, Type: sourceType(grade), Title: sourceTitle(in.Format, grade, in.Map),
		Fresh: DefaultFresh, Grade: grade}
	if err := register.Validate(src); err != nil {
		return nil, fmt.Errorf("the source %q: %w", plaintext.Clip(name, 40, "…"), err)
	}
	srcID, _ := register.IDOf(src)
	received := in.Received
	if received.IsZero() {
		received = time.Now()
	}
	sum := sha256.Sum256(in.Body)
	rd := &reader{in: in, grade: grade, source: srcID, digest: register.Digest("sha256:" + hex.EncodeToString(sum[:])),
		records: map[register.ID]*held{}}
	read := readers[in.Format]
	if read == nil {
		return nil, fmt.Errorf("%w: no reader for %s is built into this program", ErrUnreadable, in.Format)
	}
	if err := read(rd); err != nil {
		if errors.Is(err, ErrUnreadable) || errors.Is(err, ErrUnpinned) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	if len(rd.order) == 0 {
		return nil, fmt.Errorf("%w: it holds nothing this reads as a fact", ErrUnreadable)
	}
	b := &Batch{Format: in.Format, Digest: rd.digest, Size: int64(len(in.Body)), Grade: rd.grade, Source: src,
		SourceID: srcID, Flags: rd.flags, Notes: rd.notes}
	if rd.repeated > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf("%d fact(s) were given more than once in the file; the last of each was read", rd.repeated))
	}
	ids := make([]register.ID, 0, len(rd.order))
	ids = append(ids, rd.order...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var lines strings.Builder
	for _, id := range ids {
		h := rd.records[id]
		b.Records = append(b.Records, h.rec)
		b.Facts = append(b.Facts, h.fact)
		fmt.Fprintf(&lines, "%s %s %s\n", h.fact.Kind, h.fact.ID, h.fact.Hash)
	}
	for _, id := range rd.proposalOrder {
		h := rd.proposals[id]
		b.Proposals = append(b.Proposals, h.rec)
		b.Proposed = append(b.Proposed, h.fact)
	}
	b.yield = []byte(lines.String())
	ysum := sha256.Sum256(b.yield)
	b.Raw = register.RawFile{Digest: rd.digest, Source: srcID, Format: string(in.Format), Grade: rd.grade,
		Size: int64(len(in.Body)), Received: register.TimeOf(received), Facts: int64(len(b.Facts)),
		Tainted: int64(b.Tainted()), Yield: register.Digest("sha256:" + hex.EncodeToString(ysum[:])), Signer: rd.signer}
	if in.Map != nil {
		b.Raw.Map, _ = register.IDOf(*in.Map)
	}
	if err := register.Validate(b.Raw); err != nil {
		return nil, err
	}
	b.RawID, _ = register.IDOf(b.Raw)
	return b, nil
}

func formatNames() string {
	var names []string
	for _, f := range Formats() {
		names = append(names, string(f.Format))
	}
	return strings.Join(names, ", ")
}

func sourceTitle(f Format, g register.Grade, m *register.ColumnMap) string {
	what := strings.ToUpper(string(f)) + " files"
	if m != nil {
		what = "tables read through the map " + m.Name
		if m.Tool != "" {
			what = label(m.Tool) + " exports read through the map " + m.Name
		}
	}
	switch g {
	case register.GradeSigned:
		return label(what + ", signed by a pinned key")
	case register.GradeImported:
		return label(what + ", imported")
	}
	return label(what + ", uploaded by hand")
}

// readers is the reader of each format.
var readers = map[Format]func(*reader) error{}

// held is one record a reader made, with the line it makes in the preview.
type held struct {
	rec  register.Record
	fact Fact
}

// reader is what a format's reader writes to: the records it reads, in the
// order it first read them, folded by identifier.
type reader struct {
	in     Input
	grade  register.Grade
	source register.ID
	digest register.Digest
	signer string

	records  map[register.ID]*held
	order    []register.ID
	repeated int

	proposals     map[register.ID]*held
	proposalOrder []register.ID

	flags []Flag
	notes []string
}

// add puts a record in the batch. A record read twice the same way is one
// record; read twice differently, the last is kept and counted, because a
// file that is a log says the later thing later.
func (rd *reader) add(rec register.Record, place string, taint register.Taint, name, value string) (register.ID, error) {
	if err := register.Validate(rec); err != nil {
		where := ""
		if place != "" {
			where = " at " + place
		}
		return "", fmt.Errorf("%w: the %s%s would be refused: %v", ErrUnreadable, strings.ToLower(string(rec.Kind())), where,
			strings.TrimPrefix(err.Error(), register.ErrInvalid.Error()+": "))
	}
	id, err := register.IDOf(rec)
	if err != nil {
		return "", err
	}
	hash, err := FieldsHash(rec)
	if err != nil {
		return "", err
	}
	f := Fact{Kind: rec.Kind(), ID: id, Hash: hash, Place: place, Taint: taint, Name: name, Value: value}
	if was, ok := rd.records[id]; ok {
		if was.fact.Hash != hash {
			rd.repeated++
			was.rec, was.fact = rec, f
		}
		return id, nil
	}
	if len(rd.records) >= MaxRecords {
		return "", fmt.Errorf("%w: it yields more than %d records", ErrUnreadable, MaxRecords)
	}
	rd.records[id] = &held{rec: rec, fact: f}
	rd.order = append(rd.order, id)
	return id, nil
}

// propose puts a record among the proposals, which wait for a person.
func (rd *reader) propose(rec register.Record, place, name string) (register.ID, error) {
	if err := register.Validate(rec); err != nil {
		return "", fmt.Errorf("%w: a proposal read at %s would be refused: %v", ErrUnreadable, place, err)
	}
	id, err := register.IDOf(rec)
	if err != nil {
		return "", err
	}
	if rd.proposals == nil {
		rd.proposals = map[register.ID]*held{}
	}
	if _, ok := rd.proposals[id]; ok {
		return id, nil
	}
	if len(rd.proposals) >= MaxRecords {
		return "", fmt.Errorf("%w: it proposes more than %d records", ErrUnreadable, MaxRecords)
	}
	hash, _ := FieldsHash(rec)
	rd.proposals[id] = &held{rec: rec, fact: Fact{Kind: rec.Kind(), ID: id, Hash: hash, Place: place, Name: name}}
	rd.proposalOrder = append(rd.proposalOrder, id)
	return id, nil
}

// asset is the asset a source reports by its own identifier, added to the
// batch.
func (rd *reader) asset(typ register.AssetType, ref, name, place string) (register.ID, error) {
	ref = label(ref)
	if ref == "" {
		return "", fmt.Errorf("%w: an asset at %s has no identifier", ErrUnreadable, place)
	}
	a := register.Asset{Source: rd.source, Ref: ref, Type: typ, Name: label(name)}
	return rd.add(a, place, "", ref, string(typ))
}

// observe adds a fact about an asset or a subject.
func (rd *reader) observe(about register.ID, fact string, v register.Scalar, place string, taint register.Taint) error {
	o := register.Observation{Source: rd.source, About: about, Fact: fact, Value: v, Grade: rd.grade, Raw: rd.digest,
		Place: label(place), Taint: taint}
	_, err := rd.add(o, place, taint, fact, v.String())
	return err
}

func (rd *reader) flag(t register.Taint, where string) {
	rd.flags = append(rd.flags, Flag{Taint: t, Where: label(where)})
}

func (rd *reader) note(format string, args ...any) {
	rd.notes = append(rd.notes, fmt.Sprintf(format, args...))
}

// FieldsHash is the SHA-256 of a record's fields as JSON, in hexadecimal:
// what the list beside a seal names a record by, and what a record in the
// register is compared with to say it stands as it was read.
func FieldsHash(rec register.Record) (string, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// label is text from a file as a label may hold it: one plain visible
// line, no longer than a label may be. What it drops is what would let a
// file make one name look like another.
func label(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, s)
	s, _ = plaintext.Visible(s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > register.MaxLabel {
		s = strings.TrimSpace(plaintext.Clip(s, register.MaxLabel-len("…"), "…"))
	}
	return s
}

// slug is text from a file as a machine name: lower case, letters, digits,
// dots and hyphens, at most sixty-four characters, and never empty.
func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.':
			b.WriteRune(r)
		case !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = strings.TrimRight(out[:64], "-.")
	}
	if out == "" {
		return "x"
	}
	return out
}

// factName is a fact's name from its parts, each made a slug, held to the
// sixty-four characters a fact's name may be. A name too long keeps its
// start and gains a short hash of the whole, so two long names stay two.
func factName(parts ...string) string {
	var ss []string
	for _, p := range parts {
		if p != "" {
			ss = append(ss, slug(p))
		}
	}
	name := strings.Join(ss, ".")
	if len(name) <= 64 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return strings.TrimRight(name[:55], "-.") + "." + hex.EncodeToString(sum[:])[:8]
}

// scalarOf is text from a file as a fact's value: true or false as a yes or
// no, a number written the way a number is written as a number, and
// anything else as the text it is. "0012" stays text, because a serial
// number is not twelve.
func scalarOf(s string) register.Scalar {
	switch s {
	case "true", "TRUE", "True":
		return register.BoolValue(true)
	case "false", "FALSE", "False":
		return register.BoolValue(false)
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil && strconv.FormatFloat(n, 'f', -1, 64) == s {
		return register.NumberValue(n)
	}
	return register.TextValue(label(s))
}

// textDigest is the digest a register Text holds for words code wrote,
// which are kept in the program and not beside the store.
func textDigest(words string) register.Text {
	sum := sha256.Sum256([]byte(words))
	return register.Text("sha256:" + hex.EncodeToString(sum[:]))
}
