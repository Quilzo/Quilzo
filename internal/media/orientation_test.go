// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"bytes"
	"image"
	"image/color"
	jpegenc "image/jpeg"
	"strings"
	"testing"
)

// exifTIFF builds the TIFF body of an APP1 segment carrying one tag.
//
// Little-endian, one directory, one entry, no next-directory pointer. Enough
// to be read and nothing more, because reading one tag is all the pipeline
// asks of EXIF.
func exifTIFF(tag, kind uint16, count uint32, value uint16) []byte {
	b := []byte{'I', 'I', 42, 0, 8, 0, 0, 0} // header, IFD0 at offset 8
	b = append(b, 1, 0)                      // one entry
	b = append(b,
		byte(tag), byte(tag>>8),
		byte(kind), byte(kind>>8),
		byte(count), byte(count>>8), byte(count>>16), byte(count>>24),
		byte(value), byte(value>>8), 0, 0)
	b = append(b, 0, 0, 0, 0) // no next directory
	return b
}

// jpegOriented is a w×h JPEG whose top-left corner is red, carrying the given
// EXIF orientation.
//
// The red corner is the whole test: it is the only way to tell a rotation from
// a flip without comparing every pixel, and the eight orientations differ from
// each other in exactly where that corner lands.
func jpegOriented(t *testing.T, w, h int, o uint16) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 20, G: 20, B: 20, A: 255})
		}
	}
	for y := 0; y < h/4; y++ {
		for x := 0; x < w/4; x++ {
			img.Set(x, y, color.RGBA{R: 255, G: 0, B: 0, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpegenc.Encode(&buf, img, &jpegenc.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	plain := buf.Bytes()

	payload := append([]byte("Exif\x00\x00"), exifTIFF(0x0112, 3, 1, o)...)
	seg := []byte{0xFF, 0xE1,
		byte((len(payload) + 2) >> 8), byte((len(payload) + 2) & 0xFF)}
	seg = append(seg, payload...)

	out := append([]byte{}, plain[:2]...)
	out = append(out, seg...)
	out = append(out, plain[2:]...)
	return out
}

// reddest says which corner of an image is the red one.
func reddest(t *testing.T, body []byte) string {
	t.Helper()
	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	corners := map[string]image.Point{
		"top-left":     {b.Min.X + b.Dx()/8, b.Min.Y + b.Dy()/8},
		"top-right":    {b.Max.X - b.Dx()/8 - 1, b.Min.Y + b.Dy()/8},
		"bottom-left":  {b.Min.X + b.Dx()/8, b.Max.Y - b.Dy()/8 - 1},
		"bottom-right": {b.Max.X - b.Dx()/8 - 1, b.Max.Y - b.Dy()/8 - 1},
	}
	best, bestR := "", uint32(0)
	for name, p := range corners {
		r, g, bl, _ := img.At(p.X, p.Y).RGBA()
		if r > bestR && r > g*2 && r > bl*2 {
			best, bestR = name, r
		}
	}
	return best
}

// The tag is read.
func TestTheOrientationTagIsRead(t *testing.T) {
	for want := uint16(1); want <= 8; want++ {
		body := jpegOriented(t, 40, 40, want)
		if got := orientationOf("jpeg", body); got != Orientation(want) {
			t.Errorf("orientation %d read as %d", want, got)
		}
	}
	plain := jpegOriented(t, 40, 40, 1)
	if got := orientationOf("png", plain); got != 0 {
		t.Errorf("a png was asked for an orientation and answered %d", got)
	}
}

// A photograph out of a phone is stored the way up it is meant to be seen.
//
// This is the bug: the tag says turn it, the re-encode drops the tag, and the
// pixels never moved. The upload looked right in the operating system's
// preview and wrong on the published page — and nothing in the file was left
// to say it should not be.
func TestAnUploadIsTurnedTheWayItsTagAsks(t *testing.T) {
	// 6 is the common one: a phone held upright.
	body := jpegOriented(t, 40, 80, 6)
	if reddest(t, body) != "top-left" {
		t.Fatal("the fixture's marker is not where the test assumes")
	}

	out, err := Optimise("jpeg", body, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Width != 80 || out.Height != 40 {
		t.Errorf("it is %dx%d; a quarter turn did not swap the axes",
			out.Width, out.Height)
	}
	if got := reddest(t, out.Body); got != "top-right" {
		t.Errorf("the marked corner is %s, want top-right: the tag was "+
			"dropped and the pixels were left where they were", got)
	}
	if hasMetadata("jpeg", out.Body) {
		t.Error("the orientation tag survived, so a browser will turn it again")
	}
}

// All eight, because the four that involve a mirror are the ones a clever
// derivation gets subtly wrong and nobody has a photograph to notice with.
func TestEveryOrientationMovesTheMarkerWhereItShould(t *testing.T) {
	for _, tc := range []struct {
		o      uint16
		corner string
	}{
		{1, "top-left"},
		{2, "top-right"},
		{3, "bottom-right"},
		{4, "bottom-left"},
		{5, "top-left"},
		{6, "top-right"},
		{7, "bottom-right"},
		{8, "bottom-left"},
	} {
		body := jpegOriented(t, 48, 64, tc.o)
		out, err := Optimise("jpeg", body, Options{})
		if err != nil {
			t.Fatalf("orientation %d: %v", tc.o, err)
		}
		if got := reddest(t, out.Body); got != tc.corner {
			t.Errorf("orientation %d put the marker %s, want %s",
				tc.o, got, tc.corner)
		}
		wantW, wantH := 48, 64
		if Orientation(tc.o).SwapsAxes() {
			wantW, wantH = 64, 48
		}
		if out.Width != wantW || out.Height != wantH {
			t.Errorf("orientation %d is %dx%d, want %dx%d",
				tc.o, out.Width, out.Height, wantW, wantH)
		}
	}
}

// Turning and resizing compose in the right order.
//
// The width limit applies to the picture as it will be seen, not as it was
// stored — otherwise a portrait photograph from a phone is bounded on the
// wrong axis and comes out a different size from the same picture uploaded
// the other way up.
func TestTheWidthLimitAppliesAfterTheTurn(t *testing.T) {
	body := jpegOriented(t, 200, 400, 6) // becomes 400x200
	out, err := Optimise("jpeg", body, Options{MaxWidth: 100})
	if err != nil {
		t.Fatal(err)
	}
	if out.Width != 100 || out.Height != 50 {
		t.Errorf("it is %dx%d, want 100x50", out.Width, out.Height)
	}
}

// Renditions are turned too, or the thumbnail faces a different way from the
// picture it is a copy of.
func TestRenditionsAreTurnedAsWell(t *testing.T) {
	body := jpegOriented(t, 600, 1200, 6)
	rs, err := Renditions("jpeg", body, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no renditions were made, so this checked nothing")
	}
	for _, r := range rs {
		if got := reddest(t, r.Body); got != "top-right" {
			t.Errorf("a %d-wide rendition has its marker %s, want top-right",
				r.Width, got)
		}
	}
}

// Correcting twice is correcting wrongly.
//
// A rendition is built from bytes the parent's optimisation already produced,
// and those carry no tag — so this must read no orientation and turn nothing.
// If it did, every thumbnail would be a quarter turn past its picture.
func TestAnAlreadyCorrectedImageIsNotTurnedAgain(t *testing.T) {
	body := jpegOriented(t, 600, 1200, 6)
	once, err := Optimise("jpeg", body, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if orientationOf("jpeg", once.Body) != 0 {
		t.Fatal("the optimised copy still carries a tag")
	}
	twice, err := Optimise("jpeg", once.Body, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if twice.Width != once.Width || twice.Height != once.Height {
		t.Errorf("a second pass changed %dx%d to %dx%d",
			once.Width, once.Height, twice.Width, twice.Height)
	}
	if got := reddest(t, once.Body); got != "top-right" {
		t.Fatalf("the first pass is wrong: %s", got)
	}
	if got := reddest(t, twice.Body); got != "top-right" {
		t.Errorf("a second pass turned it again, to %s", got)
	}
}

// Keeping the metadata keeps the tag, and then the pixels must NOT move.
//
// This is the one case where leaving them alone is the right answer: the file
// is stored whole, the tag goes with it, and a browser applies it. Turning the
// pixels as well would show the photograph twice-turned to every reader.
func TestAKeptFileIsNotTurned(t *testing.T) {
	body := jpegOriented(t, 40, 80, 6)
	out, err := Optimise("jpeg", body, Options{KeepMetadata: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Body, body) {
		t.Error("the bytes changed although the file was to be kept as it was")
	}
	if out.Width != 40 || out.Height != 80 {
		t.Errorf("it reports %dx%d; the stored pixels are 40x80",
			out.Width, out.Height)
	}
	var said bool
	for _, did := range out.Did {
		if strings.Contains(did, "kept as uploaded") {
			said = true
		}
	}
	if !said {
		t.Errorf("it does not say the file was kept: %v", out.Did)
	}
}

// The parse gives up rather than guessing, on everything malformed.
//
// This reads attacker-controlled bytes, which is the reason the rest of this
// package refuses to parse EXIF at all. Every one of these must return no
// answer and none may panic or read outside its slice.
func TestAMalformedTagIsNoAnswer(t *testing.T) {
	cases := map[string][]byte{
		"empty":               {},
		"short":               {'I', 'I', 42, 0},
		"bad byte order":      append([]byte{'X', 'Y', 42, 0, 8, 0, 0, 0}, 0, 0),
		"bad magic":           {'I', 'I', 43, 0, 8, 0, 0, 0, 0, 0},
		"offset past the end": {'I', 'I', 42, 0, 0xFF, 0xFF, 0xFF, 0xFF},
		"offset inside the header": {'I', 'I', 42, 0, 2, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0},
		"count of zero": {'I', 'I', 42, 0, 8, 0, 0, 0, 0, 0},
		"absurd count":  {'I', 'I', 42, 0, 8, 0, 0, 0, 0xFF, 0xFF},
		"truncated entry": append([]byte{'I', 'I', 42, 0, 8, 0, 0, 0, 1, 0},
			0x12, 0x01, 3, 0),
		"wrong type":         exifTIFF(0x0112, 4, 1, 6),
		"wrong count":        exifTIFF(0x0112, 3, 2, 6),
		"value out of range": exifTIFF(0x0112, 3, 1, 99),
		"a different tag":    exifTIFF(0x0111, 3, 1, 6),
	}
	for name, body := range cases {
		if got := orientationInTIFF(body); got != 0 {
			t.Errorf("%s answered %d; it should answer nothing", name, got)
		}
	}
}

// And the segment walk gives up on a malformed container.
func TestAMalformedSegmentIsNoAnswer(t *testing.T) {
	cases := map[string][]byte{
		"empty":             {},
		"soi only":          {0xFF, 0xD8},
		"not a marker":      {0xFF, 0xD8, 0x00, 0x00, 0x00, 0x00},
		"length of zero":    {0xFF, 0xD8, 0xFF, 0xE1, 0, 0, 0, 0},
		"length past end":   {0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF, 0, 0},
		"app1 without exif": {0xFF, 0xD8, 0xFF, 0xE1, 0, 6, 'h', 'i', 0, 0},
		"scan first":        {0xFF, 0xD8, 0xFF, 0xDA, 0, 2, 0xFF, 0xE1, 0, 8},
	}
	for name, body := range cases {
		if got := orientationOf("jpeg", body); got != 0 {
			t.Errorf("%s answered %d; it should answer nothing", name, got)
		}
	}
}

// The parser is fuzzed, because the bytes it reads came from a stranger.
//
// The rest of this package refuses to parse EXIF precisely to avoid this, and
// the one tag that has to be read is therefore the one place where a hostile
// TIFF reaches a loop with offsets in it. The property is narrow and total: it
// returns a value in 0..8 and it does not panic, for any input at all.
func FuzzOrientation(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{'I', 'I', 42, 0, 8, 0, 0, 0})
	f.Add(exifTIFF(0x0112, 3, 1, 6))
	f.Add(exifTIFF(0x0112, 3, 1, 99))
	f.Add([]byte{'M', 'M', 0, 42, 0, 0, 0, 8, 0, 1, 1, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0})
	f.Add([]byte{'I', 'I', 42, 0, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, body []byte) {
		got := orientationInTIFF(body)
		if got > 8 {
			t.Errorf("answered %d, which is not an orientation", got)
		}
		// And through the container walk, which is the other half of the
		// untrusted path: a JPEG whose segment lengths are hostile.
		jpg := append([]byte{0xFF, 0xD8, 0xFF, 0xE1,
			byte((len(body) + 8) >> 8), byte((len(body) + 8) & 0xFF),
			'E', 'x', 'i', 'f', 0, 0}, body...)
		if got := orientationOf("jpeg", jpg); got > 8 {
			t.Errorf("the segment walk answered %d", got)
		}
	})
}
