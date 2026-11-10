// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webfont

import (
	"encoding/binary"
	"testing"
)

// declaring is a face whose OS/2 table says a weight and, if asked, that it
// is an italic, with a wght axis from lo to hi when hi is not zero.
func declaring(weight uint16, italic bool, lo, hi int) map[string][]byte {
	tables := trueTypeTables(0)
	be := binary.BigEndian
	os2 := tables["OS/2"]
	be.PutUint16(os2[4:6], weight)
	if italic {
		be.PutUint16(os2[62:64], 0x0001)
	}
	if hi != 0 {
		fvar := make([]byte, 16+20)
		be.PutUint16(fvar[0:2], 1)
		be.PutUint16(fvar[4:6], 16) // axes start after the header
		be.PutUint16(fvar[8:10], 1) // one axis
		be.PutUint16(fvar[10:12], 20)
		copy(fvar[16:20], "wght")
		be.PutUint32(fvar[20:24], uint32(lo)<<16)
		be.PutUint32(fvar[24:28], 400<<16)
		be.PutUint32(fvar[28:32], uint32(hi)<<16)
		tables["fvar"] = fvar
	}
	return tables
}

// A face says its own weight and style, in the TrueType file and in the WOFF
// made from it: OS/2's weight class for a static face, the wght axis for a
// variable one, and the italic bit.
func TestAFaceSaysItsOwnWeightAndStyle(t *testing.T) {
	for _, c := range []struct {
		what   string
		tables map[string][]byte
		want   Declared
	}{
		{"a static regular", declaring(400, false, 0, 0), Declared{Weight: "400"}},
		{"a static bold italic", declaring(700, true, 0, 0), Declared{Weight: "700", Italic: true}},
		{"a variable face", declaring(400, false, 300, 900), Declared{Weight: "300 900"}},
		{"a face that says nothing", declaring(0, false, 0, 0), Declared{}},
	} {
		src := face(flavourTrueType, c.tables)
		got, ok := Declares(src)
		if !ok || got != c.want {
			t.Errorf("%s, as TrueType: %+v %v, want %+v", c.what, got, ok, c.want)
		}
		woff, err := Convert(src)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := Declares(woff); !ok || got != c.want {
			t.Errorf("%s, as WOFF: %+v %v, want %+v", c.what, got, ok, c.want)
		}
	}
	// A WOFF2's tables are Brotli, so it says nothing this can read.
	if _, ok := Declares(woff2Header()); ok {
		t.Error("a WOFF2 was read as if its tables could be")
	}
}

// The names foundries give their files become names that say what the face
// is, and a name that already says it is kept.
//
// Family-Regular.ttf, a static face, was served as covering every weight, so
// bold text was drawn in the regular glyphs; Family-BoldItalic.ttf was
// refused for a word the filename contract does not read.
func TestAFoundrysNameBecomesTheContract(t *testing.T) {
	regular := Declared{Weight: "400"}
	italic := Declared{Weight: "400", Italic: true}
	boldItalic := Declared{Weight: "700", Italic: true}
	variable := Declared{Weight: "300 900"}
	for _, c := range []struct {
		stem string
		face Declared
		want string
	}{
		{"Aster-Regular", regular, "Aster-400"},
		{"Aster", regular, "Aster-400"},
		{"Aster-Italic", italic, "Aster-400-italic"},
		{"Aster-BoldItalic", boldItalic, "Aster-700-italic"},
		{"Aster-SemiBoldItalic", Declared{Weight: "600", Italic: true}, "Aster-600-italic"},
		{"Aster-Variable", variable, "Aster-300-900"},
		{"Aster-VariableItalic", Declared{Weight: "300 900", Italic: true}, "Aster-300-900-italic"},
		// What the name says is kept: it is the name somebody chose.
		{"Aster-Bold", Declared{Weight: "650"}, "Aster-Bold"},
		{"Aster-400-700", regular, "Aster-400-700"},
		{"Aster-600", Declared{Weight: "600", Italic: true}, "Aster-600-italic"},
		// A face that says nothing leaves the name as it was.
		{"Aster-Regular", Declared{}, "Aster-Regular"},
		// A word that is neither a weight nor a style is not guessed past:
		// the check refuses it and asks for a name.
		{"Aster-Condensed", regular, "Aster-Condensed"},
		{"Aster-700-Condensed", regular, "Aster-700-Condensed"},
	} {
		if got := Named(c.stem, c.face); got != c.want {
			t.Errorf("%s with %+v became %s, want %s", c.stem, c.face, got, c.want)
		}
	}
	// Every name it makes is one the contract reads as the face.
	face, err := parse(Named("Aster-BoldItalic", boldItalic)+".woff", mustConvert(t, declaring(700, true, 0, 0)))
	if err != nil || face.Weight != "700" || face.Style != "italic" {
		t.Fatalf("%+v %v", face, err)
	}
}

func mustConvert(t *testing.T, tables map[string][]byte) []byte {
	t.Helper()
	out, err := Convert(face(flavourTrueType, tables))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A stem says a weight when the filename contract reads one in it, and only
// then: Aster-Regular says a style and no weight, and is every weight.
func TestAStemSaysAWeightOnlyWhenItNamesOne(t *testing.T) {
	for stem, want := range map[string]bool{
		"Aster-600": true, "Aster-bold": true, "Aster-400-700": true, "Aster-400..700": true,
		"Aster-600-italic": true, "Aster": false, "Aster-Regular": false, "Aster-italic": false,
		"Aster-Variable": false,
	} {
		if got := SaysWeight(stem); got != want {
			t.Errorf("%s: says a weight %v, want %v", stem, got, want)
		}
	}
}
