// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webfont

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// face builds a TrueType or OpenType file out of tables, as a font tool lays
// one out: the offset table, the directory in tag order, then each table on
// a four-byte boundary. The tables are stand-ins with the fields this
// package reads in the right places; nothing here draws a glyph.
func face(flavour uint32, tables map[string][]byte) []byte {
	tags := make([]string, 0, len(tables))
	for tag := range tables {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	be := binary.BigEndian
	n := len(tags)
	head := make([]byte, 12+16*n)
	be.PutUint32(head[0:4], flavour)
	be.PutUint16(head[4:6], uint16(n))
	offset := uint32(len(head))
	var body bytes.Buffer
	for i, tag := range tags {
		rec := head[12+16*i:]
		copy(rec[0:4], tag)
		be.PutUint32(rec[4:8], checksum(tag, tables[tag]))
		be.PutUint32(rec[8:12], offset)
		be.PutUint32(rec[12:16], uint32(len(tables[tag])))
		body.Write(tables[tag])
		pad := int(pad4(uint64(len(tables[tag])))) - len(tables[tag])
		body.Write(make([]byte, pad))
		offset += uint32(len(tables[tag]) + pad)
	}
	return append(head, body.Bytes()...)
}

// trueTypeTables is a face with everything a sanitiser asks for, and some
// repetition, so zlib has something to do.
func trueTypeTables(fsType uint16) map[string][]byte {
	head := make([]byte, 54)
	binary.BigEndian.PutUint32(head[4:8], 0x00020000)  // fontRevision 2.0
	binary.BigEndian.PutUint32(head[8:12], 0xDEADBEEF) // checkSumAdjustment
	binary.BigEndian.PutUint32(head[12:16], 0x5F0F3CF5)
	os2 := make([]byte, 96)
	binary.BigEndian.PutUint16(os2[8:10], fsType)
	return map[string][]byte{
		"cmap": bytes.Repeat([]byte{0, 1, 2, 3}, 64),
		"glyf": bytes.Repeat([]byte("outline "), 500),
		"head": head,
		"hhea": make([]byte, 36),
		"hmtx": bytes.Repeat([]byte{0, 200}, 100),
		"loca": make([]byte, 202),
		"maxp": make([]byte, 6),
		"name": []byte("Aster, a face made for a test"),
		"OS/2": os2,
		"post": make([]byte, 32),
		"kern": {1, 2, 3}, // not a multiple of four, so padding is exercised
	}
}

func woff2Header() []byte {
	b := make([]byte, 64)
	copy(b, signature)
	binary.BigEndian.PutUint32(b[8:12], uint32(len(b)))
	return b
}

// A customer with a TrueType file has a way in now.
//
// There was none: WOFF2 needs Brotli, the standard library has no Brotli,
// and a .ttf in templates/fonts/ was refused. Convert writes WOFF 1.0 with
// zlib, and what it writes is read back, table by table, as exactly the face
// it was given.
func TestATrueTypeFaceBecomesAWOFFThatIsServed(t *testing.T) {
	src := face(flavourTrueType, trueTypeTables(0))
	out, err := Convert(src)
	if err != nil {
		t.Fatal(err)
	}
	if Sniff(out) != "woff" || Sniff(src) != "truetype" {
		t.Fatalf("sniffed %q from the result and %q from the source", Sniff(out), Sniff(src))
	}
	if len(out) >= len(src) {
		t.Errorf("the WOFF is %d bytes and the face %d; nothing was compressed", len(out), len(src))
	}
	got, err := checkWOFF(out)
	if err != nil {
		t.Fatal(err)
	}
	want := trueTypeTables(0)
	if len(got) != len(want) {
		t.Fatalf("%d tables came back of %d", len(got), len(want))
	}
	for _, tb := range got {
		if !bytes.Equal(tb.data, want[tb.tag]) {
			t.Errorf("the %q table did not survive the round trip", tb.tag)
		}
	}
	// The face's revision travels into the WOFF header.
	if major := binary.BigEndian.Uint16(out[20:22]); major != 2 {
		t.Errorf("the WOFF says version %d of a face whose head says 2", major)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Aster-400-700.woff"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Warnings) > 0 || set.Len() != 1 {
		t.Fatalf("a WOFF was not served: %v", set.Warnings)
	}
	f := set.Faces()[0]
	if f.Family != "Aster" || f.Weight != "400 700" || f.Format != "woff" {
		t.Errorf("read %+v", Face{Family: f.Family, Weight: f.Weight, Format: f.Format})
	}
	if ContentType(f.File) != "font/woff" || ContentType("Aster.woff2") != "font/woff2" {
		t.Errorf("served as %s", ContentType(f.File))
	}
	if fam := set.Families(); len(fam) != 1 || fam[0].Href != "/fonts/Aster-400-700.woff" {
		t.Errorf("the stylesheet is told %+v", fam)
	}
}

// An OpenType face with PostScript outlines converts the same way, and one
// that claims them without carrying them does not.
func TestAnOpenTypeFaceNeedsTheOutlinesItClaims(t *testing.T) {
	tables := trueTypeTables(0)
	delete(tables, "glyf")
	delete(tables, "loca")
	if _, err := Convert(face(flavourCFF, tables)); err == nil || !strings.Contains(err.Error(), "CFF") {
		t.Fatalf("an OpenType face with no CFF table: %v", err)
	}
	tables["CFF "] = bytes.Repeat([]byte("charstring"), 40)
	out, err := Convert(face(flavourCFF, tables))
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(out[4:8]) != flavourCFF {
		t.Error("the WOFF does not say it carries PostScript outlines")
	}
	if _, err := Convert(face(flavourTrueType, tables)); err == nil {
		t.Error("a TrueType face with no glyf table was converted")
	}
}

// A face whose own licence says it may not be embedded is not made into a
// web font, which is embedding it in every page.
func TestARestrictedFaceIsRefused(t *testing.T) {
	_, err := Convert(face(flavourTrueType, trueTypeTables(0x0002)))
	if err == nil || !strings.Contains(err.Error(), "restricted licence embedding") {
		t.Fatalf("a restricted face: %v", err)
	}
	// Preview and print, editable, and installable all permit it.
	for _, fsType := range []uint16{0x0000, 0x0004, 0x0008} {
		if _, err := Convert(face(flavourTrueType, trueTypeTables(fsType))); err != nil {
			t.Errorf("fsType %#04x was refused: %v", fsType, err)
		}
	}
}

// A face missing a table every browser's sanitiser insists on is refused
// here, with its name, rather than dropped by every reader's browser in
// silence.
func TestAFaceMissingARequiredTableIsRefusedByName(t *testing.T) {
	for _, tag := range requiredTables {
		tables := trueTypeTables(0)
		delete(tables, tag)
		_, err := Convert(face(flavourTrueType, tables))
		if err == nil || !strings.Contains(err.Error(), `"`+tag+`"`) {
			t.Errorf("a face with no %s table: %v", tag, err)
		}
	}
}

// A collection is several faces, and the answer says what to do about it.
func TestACollectionIsNotAFace(t *testing.T) {
	b := make([]byte, 64)
	copy(b, "ttcf")
	if Sniff(b) != "collection" {
		t.Fatalf("sniffed %q", Sniff(b))
	}
	if _, err := Convert(b); err == nil || !strings.Contains(err.Error(), "collection") {
		t.Fatalf("a collection: %v", err)
	}
}

// Too large to become a served face is refused before any work is done.
func TestASourceTooLargeToServeIsRefusedAtTheDoor(t *testing.T) {
	_, err := Convert(make([]byte, MaxSourceBytes+1))
	if err == nil || !strings.Contains(err.Error(), "Subset") {
		t.Fatalf("an oversized source: %v", err)
	}
}

// A WOFF that disagrees with itself is not served, whichever way it
// disagrees.
func TestAWOFFThatDisagreesWithItselfIsRefused(t *testing.T) {
	good, err := Convert(face(flavourTrueType, trueTypeTables(0)))
	if err != nil {
		t.Fatal(err)
	}
	be := binary.BigEndian
	entry := func(b []byte, i int) []byte { return b[44+20*i:] }
	cases := map[string]func(b []byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)-4] },
		"a length that is not the file's": func(b []byte) []byte {
			be.PutUint32(b[8:12], uint32(len(b)+4))
			return b
		},
		"a collection inside": func(b []byte) []byte {
			be.PutUint32(b[4:8], flavourTTC)
			return b
		},
		"a reserved field set": func(b []byte) []byte {
			be.PutUint16(b[14:16], 1)
			return b
		},
		"a total that does not add up": func(b []byte) []byte {
			be.PutUint32(b[16:20], be.Uint32(b[16:20])+4)
			return b
		},
		"a table past the end": func(b []byte) []byte {
			be.PutUint32(entry(b, 0)[4:8], uint32(len(b)))
			return b
		},
		"two tables in the same bytes": func(b []byte) []byte {
			copy(entry(b, 1)[4:8], entry(b, 0)[4:8])
			return b
		},
		"a table off its boundary": func(b []byte) []byte {
			be.PutUint32(entry(b, 0)[4:8], be.Uint32(entry(b, 0)[4:8])+1)
			return b
		},
		"a directory out of order": func(b []byte) []byte {
			e0, e1 := append([]byte{}, entry(b, 0)[:20]...), append([]byte{}, entry(b, 1)[:20]...)
			copy(entry(b, 0), e1)
			copy(entry(b, 1), e0)
			return b
		},
		"a table that inflates to more than it says": func(b []byte) []byte {
			for i := 0; i < int(be.Uint16(b[12:14])); i++ {
				e := entry(b, i)
				if string(e[0:4]) == "glyf" {
					be.PutUint32(e[12:16], be.Uint32(e[12:16])-4)
					be.PutUint32(b[16:20], be.Uint32(b[16:20])-4)
				}
			}
			return b
		},
		"a compressed table that is not zlib": func(b []byte) []byte {
			for i := 0; i < int(be.Uint16(b[12:14])); i++ {
				e := entry(b, i)
				if string(e[0:4]) == "glyf" {
					off := be.Uint32(e[4:8])
					copy(b[off:off+4], "junk")
				}
			}
			return b
		},
		"a metadata block over the tables": func(b []byte) []byte {
			be.PutUint32(b[24:28], 44)
			be.PutUint32(b[28:32], 8)
			return b
		},
	}
	for name, spoil := range cases {
		b := spoil(append([]byte{}, good...))
		if _, err := checkWOFF(b); err == nil {
			t.Errorf("%s: served", name)
		}
		if _, err := Check("Aster.woff", b); err == nil {
			t.Errorf("%s: Check passed it", name)
		}
	}
	if _, err := Check("Aster.woff", good); err != nil {
		t.Fatalf("the unspoilt file: %v", err)
	}
}

// The bytes have to be the format the name says, and a renamed TrueType file
// is told how to become a web font rather than only that it is not one.
func TestARenamedFaceIsRefusedWithTheWayIn(t *testing.T) {
	ttf := face(flavourTrueType, trueTypeTables(0))
	woff, err := Convert(ttf)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"Aster.woff2": ttf, "Aster.woff": ttf, "Other.woff2": woff, "Third.woff": woff2Header(),
	} {
		_, err := Check(name, b)
		if err == nil || !strings.Contains(err.Error(), "quilzo theme font add") {
			t.Errorf("%s holding the wrong format: %v", name, err)
		}
	}
	if _, err := Check("Aster.ttf", ttf); err == nil {
		t.Error("a .ttf name was accepted as a served face")
	}
}

// A range written with a dash is a range.
//
// The package documented Satoshi-400-700.woff2 as one and its own error
// message suggested Family-400-700.woff2, and the parser split on the dash
// and kept the last number: QuilzoUI-300-700.woff2 was served as
// font-weight 700, so every lighter weight was synthesised from the boldest.
// Only QuilzoUI-300..700.woff2 gave 300 700, and it still does.
func TestAWeightRangeWithADashIsARange(t *testing.T) {
	for name, want := range map[string]string{
		"QuilzoUI-300-700.woff2":        "300 700",
		"QuilzoUI-300..700.woff2":       "300 700",
		"QuilzoUI.woff2":                "100 900",
		"QuilzoUI-600.woff2":            "600",
		"QuilzoUI-light-bold.woff2":     "300 700",
		"QuilzoUI-400-700-italic.woff2": "400 700",
		"QuilzoUI-italic-400-700.woff2": "400 700",
		"QuilzoUI-500-500.woff2":        "500",
		"QuilzoUI-bold-italic.woff2":    "700",
		"QuilzoUI-variable.woff2":       "100 900",
	} {
		f, err := parse(name, woff2Header())
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if f.Weight != want {
			t.Errorf("%s is weight %q, want %q", name, f.Weight, want)
		}
		if strings.Contains(name, "italic") && f.Style != "italic" {
			t.Errorf("%s lost its style", name)
		}
	}
	for _, name := range []string{"QuilzoUI-700-300.woff2", "QuilzoUI-700..300.woff2", "QuilzoUI-wide.woff2", "QuilzoUI-0.woff2"} {
		if _, err := parse(name, woff2Header()); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	_, err := parse("QuilzoUI-700-300.woff2", woff2Header())
	if err == nil || !strings.Contains(err.Error(), "Family-300-700") {
		t.Errorf("a descending range does not say how to write it: %v", err)
	}
}

// A .ttf beside the faces still says it is not served, and now says how it
// could be.
func TestATrueTypeFileInTheDirectorySaysHowToServeIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Aster.ttf"), face(flavourTrueType, trueTypeTables(0)), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Warnings) != 1 || !strings.Contains(set.Warnings[0], "quilzo theme font add Aster.ttf") {
		t.Fatalf("warnings: %v", set.Warnings)
	}
}

// The head table's checksum leaves out its own adjustment field, which is
// derived from every other checksum and so cannot be part of one.
func TestTheHeadChecksumLeavesOutItsAdjustment(t *testing.T) {
	a := trueTypeTables(0)["head"]
	b := append([]byte{}, a...)
	binary.BigEndian.PutUint32(b[8:12], 0x01020304)
	if checksum("head", a) != checksum("head", b) {
		t.Error("the head checksum moved with checkSumAdjustment")
	}
	if checksum("glyf", a) == checksum("glyf", b) {
		t.Error("any other table's checksum ignored a changed word")
	}
	if checksum("kern", []byte{1, 2, 3}) != 0x01020300 {
		t.Errorf("a short table is not zero-padded: %#x", checksum("kern", []byte{1, 2, 3}))
	}
}
