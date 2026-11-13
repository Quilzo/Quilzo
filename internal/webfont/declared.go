// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webfont

import (
	"encoding/binary"
	"strings"
)

// What a face says about itself, for naming one nobody named.
//
// The filename is the contract (webfont.go), and a filename that says no
// weight declares the full range, 100 to 900. That is right for a variable
// face and wrong for every other, and foundries name their static faces
// Family-Regular.ttf, Family-Bold.ttf, Family-Italic.ttf and
// Family-BoldItalic.ttf. Added as they came, the regular was served as
// covering every weight, so a browser asked for bold found a face that
// claimed it and drew the regular glyphs; the italic did the same for bold
// italic; and the bold italic was refused for a word the contract does not
// read. Those are the files `quilzo theme font add` is handed.
//
// So a face added without a name takes the weight and the style its own
// tables state wherever its filename does not say them: OS/2 usWeightClass
// for a static face, the range of the wght axis for a variable one, and the
// italic bit of OS/2 fsSelection or of head's macStyle. Where the filename
// does say them it is kept, because it is the name somebody chose, and a
// name somebody gives is always used as given.

// Declared is the weight and style a face's own tables state.
type Declared struct {
	// Weight is one weight ("400") or a variable range ("300 900"), as CSS
	// writes it, or empty when the face does not say.
	Weight string
	// Italic is the face saying it is an italic.
	Italic bool
}

// Declares reads what a WOFF, TrueType or OpenType file states about its
// weight and style. ok is false for anything this cannot read the tables of:
// not a face, a collection, or a WOFF2, whose tables are Brotli.
func Declares(b []byte) (d Declared, ok bool) {
	var tables []table
	var err error
	switch Sniff(b) {
	case "woff":
		tables, err = checkWOFF(b)
	case "truetype", "opentype":
		tables, _, err = sfntTables(b)
	default:
		return Declared{}, false
	}
	if err != nil {
		return Declared{}, false
	}
	have := map[string][]byte{}
	for _, t := range tables {
		have[t.tag] = t.data
	}
	be := binary.BigEndian
	os2 := have["OS/2"]
	if len(os2) >= 6 {
		if w := int(be.Uint16(os2[4:6])); w >= 1 && w <= 1000 {
			d.Weight = rangeOf(w, w)
		}
	}
	// A variable face's weight is its axis, whatever weight its default
	// instance carries in OS/2.
	if lo, hi, axis := weightAxis(have["fvar"]); axis {
		d.Weight = rangeOf(lo, hi)
	}
	if len(os2) >= 64 && be.Uint16(os2[62:64])&0x0001 != 0 {
		d.Italic = true
	}
	if head := have["head"]; len(head) >= 46 && be.Uint16(head[44:46])&0x0002 != 0 {
		d.Italic = true
	}
	return d, true
}

// weightAxis is the range of a variable face's wght axis, read from its fvar
// table: the axis records start at the offset the header gives, each of the
// size it gives, with the minimum and maximum as 16.16 fixed-point numbers.
func weightAxis(fvar []byte) (lo, hi int, ok bool) {
	be := binary.BigEndian
	if len(fvar) < 16 {
		return 0, 0, false
	}
	offset := int(be.Uint16(fvar[4:6]))
	count := int(be.Uint16(fvar[8:10]))
	size := int(be.Uint16(fvar[10:12]))
	if size < 20 {
		return 0, 0, false
	}
	fixed := func(b []byte) int { return int((int32(be.Uint32(b)) + 0x8000) >> 16) }
	for i := 0; i < count; i++ {
		at := offset + i*size
		if at+20 > len(fvar) {
			return 0, 0, false
		}
		rec := fvar[at : at+20]
		if string(rec[0:4]) != "wght" {
			continue
		}
		lo, hi = fixed(rec[4:8]), fixed(rec[12:16])
		if lo < 1 || hi > 1000 || lo > hi {
			return 0, 0, false
		}
		return lo, hi, true
	}
	return 0, 0, false
}

// SaysWeight reports whether a stem names a weight or a weight range as the
// filename contract reads it: Aster-600, Aster-bold, Aster-400-700 and
// Aster-400..700 do; Aster, Aster-Regular and Aster-italic do not, and are
// served as every weight from 100 to 900.
func SaysWeight(stem string) bool {
	parts := strings.Split(stem, "-")
	for _, p := range parts[1:] {
		if _, ok := weight(strings.ToLower(strings.TrimSpace(p))); ok {
			return true
		}
	}
	return false
}

// Named is the stem to serve a face under, from the stem of the file it came
// in and what the face declares.
//
// A stem whose every part the contract reads and which says a weight is kept
// as it is, with "-italic" added when the face is an italic the stem does
// not mention. One that says no weight, or says weight and style in one word
// the contract does not read ("BoldItalic", "SemiBoldItalic"), becomes the
// family, its first part, then the weight, then "-italic" if either the stem
// or the face says so. Anything else — a word that is neither a weight nor a
// style, such as "Condensed" — is returned unchanged, so the check that
// follows refuses it and asks for a name, rather than this guessing one that
// could be another face's.
func Named(stem string, d Declared) string {
	parts := strings.Split(stem, "-")
	family := strings.TrimSpace(parts[0])
	if !reFamily.MatchString(family) {
		return stem
	}
	said, italic, compound := "", false, false
	rest := parts[1:]
	for i := 0; i < len(rest); i++ {
		p := strings.ToLower(strings.TrimSpace(rest[i]))
		switch {
		case p == "italic" || p == "oblique":
			italic = true
		case p == "" || p == "regular" || p == "normal" || p == "variable" || p == "vf":
		default:
			if lo, ok := single(p); ok && i+1 < len(rest) {
				if hi, ok := single(strings.ToLower(strings.TrimSpace(rest[i+1]))); ok && lo <= hi {
					said = rangeOf(lo, hi)
					i++
					continue
				}
			}
			if w, ok := weight(p); ok {
				said = w
				continue
			}
			// A weight and the italic in one word, as foundries write them.
			if word, ok := strings.CutSuffix(p, "italic"); ok {
				if n, ok := single(word); ok {
					said, italic, compound = rangeOf(n, n), true, true
					continue
				}
				if word == "regular" || word == "variable" {
					italic, compound = true, true
					continue
				}
			}
			return stem
		}
	}
	addItalic := d.Italic && !italic
	if said != "" && !compound {
		if addItalic {
			return stem + "-italic"
		}
		return stem
	}
	w := said
	if w == "" {
		w = d.Weight
	}
	if w == "" {
		if compound {
			return family + "-italic"
		}
		if addItalic {
			return stem + "-italic"
		}
		return stem
	}
	out := family + "-" + strings.ReplaceAll(w, " ", "-")
	if italic || d.Italic {
		out += "-italic"
	}
	return out
}
