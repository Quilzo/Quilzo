// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"strings"
)

// The kinds that say how evidence came in: a file as it was received and
// sealed, the column map a person confirmed for reading one kind of table,
// and a third party's key that a signed file is checked against. The
// importers that write them are internal/evidence's.
//
// None of the three is a fact about the organisation. They are what lets a
// fact be followed back: from an Observation to the sealed file it was read
// from, from the file to the map or the key it was read with, and from all
// three to the person who brought them.

// Taint says a fact was read from a part of a file that a person opening it
// would not see, or that something other than Quilzo worked out: a hidden
// sheet, a row or a column that was hidden, a cell with a comment, a
// formula's cached result, a cell a defined name points at, a link to
// another workbook. Such a fact is kept, marked, and never taken for one a
// person saw.
type Taint string

// Values lists the taints.
func (Taint) Values() []string {
	return []string{"hidden-sheet", "hidden-row", "hidden-column", "comment", "formula", "defined-name", "external-link"}
}

// RawFile is a file as it was received, sealed by its hash in the raw
// evidence store before anything read it, with what was read from it.
//
// The bytes themselves are kept outside the register, where they can be
// erased when their time is up. This record is what is left: the file's
// hash, how it came in and at which grade, and the digest of the list of
// facts it yielded. That list is kept beside the seal, so the facts still
// verify after the file has gone.
type RawFile struct {
	Digest Digest `json:"digest" reg:"required" about:"the SHA-256 of the file as it was received"`
	Source ID     `json:"source" reg:"required,ref=Source" about:"the source it came in under"`
	Format string `json:"format" reg:"required,slug" about:"how it was read: csv, xlsx, ocsf, cyclonedx and the rest"`
	Grade  Grade  `json:"grade" reg:"required" about:"how its facts reached the record"`
	Size   int64  `json:"size" reg:"min=0" about:"how many bytes it was"`
	// Received is when the file was first sealed. It is the seal's and not
	// the import's, so a second import of the same file writes nothing.
	Received Time `json:"received" reg:"required" about:"when the file was first sealed"`
	// Facts and Tainted are how many records the read yielded, and how
	// many of those were read from a hidden part of the file.
	Facts   int64 `json:"facts" reg:"min=0" about:"how many records were read from it"`
	Tainted int64 `json:"tainted" reg:"min=0" about:"how many of those were read from a part a person opening the file would not see"`
	// Yield is the SHA-256 of the list of what was read from the file: a
	// line for each record, its kind, its identifier and the hash of its
	// fields. The list is kept beside the seal; this is what it is checked
	// against.
	Yield Digest `json:"yield" reg:"required" about:"the digest of the list of records read from it"`
	// Map is the column map a table was read with, and Signer the pinned
	// key a signed file was verified against.
	Map    ID     `json:"map,omitempty" reg:"ref=ColumnMap" about:"the confirmed column map it was read with"`
	Signer string `json:"signer,omitempty" reg:"slug" about:"the name of the pinned key its signature was verified against"`
	// Stated is the person a table's statements were read as: whoever
	// brought it, whose statements they are. It is kept so that the file
	// read again to be checked yields what it did.
	Stated ID `json:"stated,omitempty" reg:"ref=Subject" about:"the person whose statements a table's records are: who brought it"`
}

const KindRawFile Kind = "RawFile"

func (RawFile) Kind() Kind { return KindRawFile }
func (f RawFile) Key() (string, string) {
	return string(f.Source), string(f.Digest) + "/" + f.Format + "/" + string(f.Map)
}
func (f RawFile) Check() error {
	if f.Tainted > f.Facts {
		return fmt.Errorf("more facts were tainted than were read")
	}
	return nil
}
func (f RawFile) index(r *Row) {
	r.About, r.Via, r.At, r.N, r.M, r.Grade = f.Source.bytes(), f.Map.bytes(), int64(f.Received), clamp32(f.Facts),
		clamp32(f.Tainted), ordinal(f.Grade)
}

var _ = define[RawFile]("A file as it was received, sealed by its hash before anything read it.", ClassInternal)

// MapFormat is what sort of file a column map reads.
type MapFormat string

// Values lists the formats a map reads.
func (MapFormat) Values() []string { return []string{"csv", "xlsx", "json"} }

// MapColumn is where one field of the records a map makes comes from: a
// column of the table, or a value the map gives itself.
type MapColumn struct {
	// Field is the field of the kind, as its JSON names it.
	Field string `json:"field" reg:"required,slug" about:"the field of the record, as the kind's schema names it"`
	// Column is the heading of the column it is read from, and Value a
	// value every record is given instead.
	Column string `json:"column,omitempty" reg:"label" about:"the heading of the column it is read from"`
	Value  string `json:"value,omitempty" reg:"label" about:"a value every record is given, in place of a column"`
	// Asset says the column holds an asset's own identifier, a serial
	// number or a host name, and the field is the Asset of this type that
	// the source reports by it. Name is the column its name is read from.
	Asset AssetType `json:"asset,omitempty" about:"the column names an asset of this type, which the field points at"`
	Name  string    `json:"name,omitempty" reg:"label" about:"the heading of the column the asset's name is read from"`
	// ID says the column holds register identifiers already, and Of says
	// it holds the natural key of a record of that kind made in Quilzo, a
	// control's reference: the field points at the record the key names.
	ID bool   `json:"id,omitempty" about:"the column holds register identifiers"`
	Of string `json:"of,omitempty" reg:"label" about:"the column holds the natural key of a record of this kind, which the field points at"`
}

// MapFact is one fact an Observation map reads from each row.
type MapFact struct {
	Fact   string `json:"fact" reg:"required,slug" about:"the fact's name, such as disk.encrypted"`
	Column string `json:"column" reg:"required,label" about:"the heading of the column its value is read from"`
}

// ColumnMap is how one sort of table is read into one kind of record: which
// column each field comes from. A person confirms it once, having seen what
// it reads from a sample, and every import of that table reads it the same
// way after.
//
// Only a person writes one. What an importer or a model guesses about a
// table's layout is a proposal until somebody has looked: a column read into
// the wrong field is a wrong fact in every record, and nobody reads a
// thousand records to find it.
type ColumnMap struct {
	Name   string    `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title  string    `json:"title,omitempty" reg:"label" about:"what people call it"`
	Makes  string    `json:"kind" reg:"required,label" about:"the kind of record it makes"`
	Format MapFormat `json:"format" reg:"required" about:"the sort of file it reads"`
	// Sheet is the worksheet it reads, by name, and Header the row the
	// headings are on, counted from one.
	Sheet  string `json:"sheet,omitempty" reg:"label" about:"the worksheet it reads, by its name"`
	Header int64  `json:"header,omitempty" reg:"min=1,max=1000" about:"the row the headings are on, counted from one"`
	// Rows is where, in a JSON file, the list of records is: a JSON
	// pointer, empty for a file that is the list.
	Rows    string      `json:"rows,omitempty" reg:"label" about:"where in a JSON file the list of records is, as a JSON pointer"`
	Columns []MapColumn `json:"columns,omitempty" reg:"max=200" about:"where each field comes from"`
	Facts   []MapFact   `json:"facts,omitempty" reg:"max=200" about:"for observations, the facts each row holds"`
	// Tool names the tool whose export the map reads, when it reads one: a
	// GRC tool's list of tests, a device manager's inventory. What such a
	// map reads is graded imported; a table without one is a person's,
	// and graded uploaded.
	Tool string `json:"tool,omitempty" reg:"label" about:"the tool whose export it reads; its facts are graded imported"`
}

const KindColumnMap Kind = "ColumnMap"

func (ColumnMap) Kind() Kind              { return KindColumnMap }
func (m ColumnMap) Key() (string, string) { return Local, m.Name }
func (m ColumnMap) Check() error {
	spec, ok := SpecOf(m.Makes)
	if !ok {
		return fmt.Errorf("%q is not a kind the register has", m.Makes)
	}
	switch {
	case spec.Signed:
		return fmt.Errorf("a %s is a decision and carries the approval that made it, which no import can give", spec.Kind)
	case spec.Unconfirmed:
		return fmt.Errorf("a %s is what a model read, which no table is", spec.Kind)
	case spec.Immutable:
		// A decision, a person's acknowledgement and a metric's value are
		// made by what they record, and never changed: one read from a
		// table would name a decider or a reader who never acted, or a
		// figure nothing computed, and stand so for good.
		return fmt.Errorf("a %s is never changed once written, and is made by what it records, never read from a table", spec.Kind)
	case spec.Kind == KindColumnMap || spec.Kind == KindRawFile || spec.Kind == KindPinnedKey || spec.Kind == KindSubject:
		return fmt.Errorf("a %s is not read from a table", spec.Kind)
	case spec.Kind == KindObservation && len(m.Facts) == 0:
		return fmt.Errorf("a map of observations names the facts each row holds")
	case spec.Kind != KindObservation && len(m.Facts) > 0:
		return fmt.Errorf("only a map of observations names facts; a %s's fields are its columns", spec.Kind)
	case m.Format != "xlsx" && m.Sheet != "":
		return fmt.Errorf("only a workbook has sheets")
	case m.Format != "json" && m.Rows != "":
		return fmt.Errorf("only a JSON file has a pointer to its rows")
	case m.Rows != "" && !strings.HasPrefix(m.Rows, "/"):
		return fmt.Errorf("a JSON pointer begins with a slash")
	}
	fields := map[string]Field{}
	for _, f := range spec.Fields {
		fields[f.Name] = f
	}
	// What the importer says of every record it writes is not a column's to
	// say: the grade is how the file came in, the raw digest and the place
	// are where it was read, and a map that read them from the file would
	// let the file say how far it is to be trusted.
	for _, c := range m.Columns {
		switch c.Field {
		case "grade", "raw", "place", "taint":
			return fmt.Errorf("the field %q is the importer's to write, never a column's", c.Field)
		}
		// Who stated something is who brought the file that says it: a
		// column naming another person would put words in their mouth.
		if f, ok := fields[c.Field]; ok && c.Field == "attested" && f.Ref == KindSubject {
			return fmt.Errorf("the field %q is the person's who brings the file, and the importer writes it, never a column", c.Field)
		}
		if f, ok := fields[c.Field]; ok && c.Field == "source" && f.Ref == KindSource {
			return fmt.Errorf("a %s's source is the one it is imported under, never a column", strings.ToLower(string(spec.Kind)))
		}
	}
	seen := map[string]bool{}
	for _, c := range m.Columns {
		f, ok := fields[c.Field]
		if !ok {
			return fmt.Errorf("a %s has no field %q", spec.Kind, c.Field)
		}
		if seen[c.Field] {
			return fmt.Errorf("the field %q is mapped twice", c.Field)
		}
		seen[c.Field] = true
		if (c.Column == "") == (c.Value == "") {
			return fmt.Errorf("the field %q is read from a column or given a value: one, and only one", c.Field)
		}
		if (c.Asset != "" || c.ID || c.Of != "") && f.Type != "id" {
			return fmt.Errorf("the field %q is not an identifier, so it cannot point at a record", c.Field)
		}
		if b2i(c.Asset != "")+b2i(c.ID)+b2i(c.Of != "") > 1 {
			return fmt.Errorf("the field %q points at an asset, holds identifiers or holds a natural key: one of the three", c.Field)
		}
		if c.Of != "" {
			if _, ok := SpecOf(c.Of); !ok {
				return fmt.Errorf("the field %q holds the keys of %q, which is not a kind the register has", c.Field, c.Of)
			}
			if c.Column == "" {
				return fmt.Errorf("the field %q reads a natural key from a column", c.Field)
			}
		}
		if c.Asset != "" && c.Column == "" {
			return fmt.Errorf("the field %q names an asset by a column", c.Field)
		}
		if c.Name != "" && c.Asset == "" {
			return fmt.Errorf("the field %q reads an asset's name and names no asset", c.Field)
		}
	}
	facts := map[string]bool{}
	for _, f := range m.Facts {
		if facts[f.Fact] {
			return fmt.Errorf("the fact %q is read twice", f.Fact)
		}
		facts[f.Fact] = true
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// attested says a column map is a person's to write: Put refuses one from
// anybody else, as it refuses a statement about a control.
func (ColumnMap) attested() bool { return true }

var _ = define[ColumnMap]("How one sort of table is read into one kind of record, as a person confirmed it.", ClassInternal)

// KeyAlgorithm is how a pinned key signs.
type KeyAlgorithm string

// Values lists the algorithms a pinned key may use.
func (KeyAlgorithm) Values() []string { return []string{"ed25519", "ecdsa-p256", "ecdsa-p384"} }

// PinnedKey is a third party's public key, pinned by a person, that a
// signed file (a DSSE envelope) is verified against. A signature by any key
// not pinned here is no signature as far as the register is concerned: a
// file that brings its own key proves only that somebody had a key.
type PinnedKey struct {
	Name      string       `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title     string       `json:"title,omitempty" reg:"label" about:"whose key it is, as people call them"`
	Algorithm KeyAlgorithm `json:"algorithm" reg:"required" about:"how it signs"`
	// Public is the key itself: its SubjectPublicKeyInfo, in DER, as
	// standard base64. KeyID is the identifier envelopes name it by, when
	// the signer gives one.
	Public string `json:"public" reg:"required,label" about:"the public key, as base64 of its DER encoding"`
	KeyID  string `json:"keyid,omitempty" reg:"label" about:"the identifier signed envelopes name it by"`
	// Fingerprint is the SHA-256 of the key's DER, which is how a person
	// checks it against what the signer published.
	Fingerprint Digest `json:"fingerprint" reg:"required" about:"the SHA-256 of the key, to check against what its owner published"`
	Pinned      Time   `json:"pinned" reg:"required" about:"when it was pinned"`
}

const KindPinnedKey Kind = "PinnedKey"

func (PinnedKey) Kind() Kind              { return KindPinnedKey }
func (k PinnedKey) Key() (string, string) { return Local, k.Name }
func (PinnedKey) Check() error            { return nil }

// attested says a pinned key is a person's to write: trusting a third
// party's signature is a decision, and no service or model makes it.
func (PinnedKey) attested() bool { return true }

func (k PinnedKey) index(r *Row) { r.At, r.State = int64(k.Pinned), ordinal(k.Algorithm) }

var _ = define[PinnedKey]("A third party's public key, pinned by a person, that signed files are verified against.", ClassInternal)

// Validate holds a record to its kind's field rules and its Check, as Put
// will, without writing anything: an importer asks it of each record it
// read, so a preview names the row that would be refused before a person
// is asked to confirm anything.
func Validate(rec Record) error {
	if rec == nil {
		return fmt.Errorf("%w: an empty record", ErrInvalid)
	}
	if _, err := specFor(rec.Kind()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validate(rec); err != nil {
		return err
	}
	_, err := IDOf(rec)
	return err
}
