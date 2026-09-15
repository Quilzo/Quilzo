// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"bytes"
	"image"
	"image/color"
	pngenc "image/png"
	"strings"
	"testing"
)

// marked builds a w×h picture with a red square in its top-left quarter, so a
// transform can be told apart from a no-op by looking at one pixel.
func marked(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 20, G: 20, B: 20, A: 255})
		}
	}
	for y := 0; y < h/4; y++ {
		for x := 0; x < w/4; x++ {
			img.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	return img
}

func markedPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pngenc.Encode(&buf, marked(w, h)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// corner says which corner of an image holds the red mark.
func corner(t *testing.T, img image.Image) string {
	t.Helper()
	b := img.Bounds()
	for name, p := range map[string]image.Point{
		"top-left":     {b.Min.X + b.Dx()/8, b.Min.Y + b.Dy()/8},
		"top-right":    {b.Max.X - b.Dx()/8 - 1, b.Min.Y + b.Dy()/8},
		"bottom-left":  {b.Min.X + b.Dx()/8, b.Max.Y - b.Dy()/8 - 1},
		"bottom-right": {b.Max.X - b.Dx()/8 - 1, b.Max.Y - b.Dy()/8 - 1},
	} {
		r, g, bl, _ := img.At(p.X, p.Y).RGBA()
		if r > g*2 && r > bl*2 {
			return name
		}
	}
	return "nowhere"
}

// An aspect crop takes the largest rectangle of that shape that fits.
func TestAnAspectCropTakesTheLargestThatFits(t *testing.T) {
	for _, tc := range []struct {
		w, h   int
		aspect string
		wantW  int
		wantH  int
	}{
		{1200, 800, "16:9", 1200, 675},
		{800, 1200, "16:9", 800, 450},
		{1200, 800, "1:1", 800, 800},
		{1200, 800, "2:3", 533, 800},
	} {
		got, err := ApplyEdit(marked(tc.w, tc.h), Edit{Aspect: tc.aspect}, nil)
		if err != nil {
			t.Fatalf("%dx%d as %s: %v", tc.w, tc.h, tc.aspect, err)
		}
		if got.Bounds().Dx() != tc.wantW || got.Bounds().Dy() != tc.wantH {
			t.Errorf("%dx%d as %s gave %dx%d, want %dx%d",
				tc.w, tc.h, tc.aspect, got.Bounds().Dx(), got.Bounds().Dy(),
				tc.wantW, tc.wantH)
		}
	}
}

// The crop is taken around the focal point somebody already set.
//
// That field existed and did one thing: it wrote a CSS object-position, so
// every reader's browser cropped the picture and every reader downloaded all
// of it. The same number now decides where a real crop is cut.
func TestAnAspectCropIsTakenAroundTheFocalPoint(t *testing.T) {
	src := marked(400, 400)

	centred, err := ApplyEdit(src, Edit{Aspect: "4:1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A 4:1 strip out of the middle of a square misses a mark in the corner.
	if got := corner(t, centred); got != "nowhere" {
		t.Errorf("a centred strip found the mark %s", got)
	}

	top, err := ApplyEdit(src, Edit{Aspect: "4:1"}, &Focus{X: 50, Y: 0})
	if err != nil {
		t.Fatal(err)
	}
	if got := corner(t, top); got != "top-left" {
		t.Errorf("a strip focused at the top found the mark %s, want top-left",
			got)
	}
}

// A focal point at the edge does not push the crop outside the picture.
func TestTheCropStaysInsideThePicture(t *testing.T) {
	for _, f := range []*Focus{
		{X: 0, Y: 0}, {X: 100, Y: 100}, {X: -50, Y: 400},
	} {
		r, err := boxFor(Edit{Aspect: "1:1"}, 400, 200, f)
		if err != nil {
			t.Fatal(err)
		}
		if r.Min.X < 0 || r.Min.Y < 0 || r.Max.X > 400 || r.Max.Y > 200 {
			t.Errorf("focus %+v put the crop at %v", f, r)
		}
		if r.Dx() != 200 || r.Dy() != 200 {
			t.Errorf("focus %+v gave a %dx%d crop, want 200x200",
				f, r.Dx(), r.Dy())
		}
	}
}

// An explicit box cuts where it says.
func TestAnExplicitBoxCutsWhereItSays(t *testing.T) {
	got, err := ApplyEdit(marked(400, 400),
		Edit{Crop: &Box{X: 50, Y: 50, W: 50, H: 50}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds().Dx() != 200 || got.Bounds().Dy() != 200 {
		t.Errorf("the crop is %dx%d, want 200x200",
			got.Bounds().Dx(), got.Bounds().Dy())
	}
	// The bottom-right quarter holds no mark.
	if c := corner(t, got); c != "nowhere" {
		t.Errorf("the bottom-right quarter found the mark %s", c)
	}
}

// Turns and mirrors put the mark where they should.
//
// Written out as explicit mappings rather than composed, and checked the same
// way: the ones involving a mirror are where a clever derivation goes subtly
// wrong and nobody has a picture to notice with.
func TestEveryTurnAndFlipMovesTheMark(t *testing.T) {
	for _, tc := range []struct {
		e    Edit
		want string
	}{
		{Edit{Turn: 90}, "top-right"},
		{Edit{Turn: 180}, "bottom-right"},
		{Edit{Turn: 270}, "bottom-left"},
		{Edit{Flip: "across"}, "top-right"},
		{Edit{Flip: "down"}, "bottom-left"},
	} {
		got, err := ApplyEdit(marked(200, 200), tc.e, nil)
		if err != nil {
			t.Fatalf("%+v: %v", tc.e, err)
		}
		if c := corner(t, got); c != tc.want {
			t.Errorf("%s put the mark %s, want %s", tc.e.Describe(), c, tc.want)
		}
	}
}

// A quarter turn swaps the sides.
func TestAQuarterTurnSwapsTheSides(t *testing.T) {
	got, err := ApplyEdit(marked(400, 200), Edit{Turn: 90}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds().Dx() != 200 || got.Bounds().Dy() != 400 {
		t.Errorf("it is %dx%d, want 200x400",
			got.Bounds().Dx(), got.Bounds().Dy())
	}
}

// Grey uses luma, not an average.
//
// An average turns a saturated red and a saturated blue into the same grey,
// which is how a chart with a key becomes unreadable — and unreadable is the
// thing this is most often used to avoid.
func TestGreyKeepsColoursApart(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 2, 1))
	src.Set(0, 0, color.RGBA{R: 255, A: 255})
	src.Set(1, 0, color.RGBA{B: 255, A: 255})

	got, err := ApplyEdit(src, Edit{Grey: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r1, g1, b1, _ := got.At(0, 0).RGBA()
	r2, _, _, _ := got.At(1, 0).RGBA()
	if r1 != g1 || g1 != b1 {
		t.Errorf("the first pixel is not grey: %d %d %d", r1, g1, b1)
	}
	if r1 == r2 {
		t.Error("a saturated red and a saturated blue became the same grey")
	}
}

// The order is fixed, so a recipe means one thing.
//
// Crop then turn is not turn then crop, and a recipe whose meaning depended on
// the order somebody typed the flags would be one nobody could reproduce.
func TestTheOrderIsCropThenTurn(t *testing.T) {
	// A 400x200 picture. Cropping the left half gives 200x200; turning that
	// gives 200x200. Turning first would give 200x400, and cropping the left
	// half of that gives 100x400.
	got, err := ApplyEdit(marked(400, 200),
		Edit{Crop: &Box{X: 0, Y: 0, W: 50, H: 100}, Turn: 90}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds().Dx() != 200 || got.Bounds().Dy() != 200 {
		t.Errorf("it is %dx%d, want 200x200 — the crop ran after the turn",
			got.Bounds().Dx(), got.Bounds().Dy())
	}
}

// A recipe that cannot be carried out is refused before anything is decoded.
func TestABadRecipeIsRefused(t *testing.T) {
	for name, e := range map[string]Edit{
		"nothing at all":    {},
		"both ways to cut":  {Aspect: "16:9", Crop: &Box{W: 50, H: 50}},
		"outside the frame": {Crop: &Box{X: 60, Y: 0, W: 50, H: 100}},
		"no area":           {Crop: &Box{X: 0, Y: 0, W: 0, H: 100}},
		"a free angle":      {Turn: 45},
		"an unknown flip":   {Flip: "sideways"},
		"not a ratio":       {Aspect: "wide"},
		"a ratio with zero": {Aspect: "16:0"},
		"an extreme ratio":  {Aspect: "4000:1"},
	} {
		if err := e.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Derive produces bytes that decode, and says what it did.
func TestDeriveProducesADecodablePicture(t *testing.T) {
	out, err := Derive("png", markedPNG(t, 400, 400),
		Edit{Aspect: "16:9", Grey: true}, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	img, _, err := image.Decode(bytes.NewReader(out.Body))
	if err != nil {
		t.Fatalf("the derived bytes do not decode: %v", err)
	}
	if img.Bounds().Dx() != out.Width || img.Bounds().Dy() != out.Height {
		t.Errorf("it reports %dx%d and the bytes are %dx%d",
			out.Width, out.Height, img.Bounds().Dx(), img.Bounds().Dy())
	}
	if !strings.Contains(strings.Join(out.Did, " "), "16:9") {
		t.Errorf("it does not say what it did: %v", out.Did)
	}
}

// The format does not change under somebody's feet.
//
// Cropping a PNG and being handed a JPEG is a surprise, and the two have
// different extensions, different media types and different answers about
// transparency.
func TestDeriveKeepsTheFormat(t *testing.T) {
	out, err := Derive("png", markedPNG(t, 400, 400), Edit{Turn: 90}, nil,
		Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Format != "png" {
		t.Errorf("a cropped png came back as %s", out.Format)
	}
}

// A format with no decoder here is refused with a reason.
func TestDeriveRefusesAFormatItCannotRead(t *testing.T) {
	if _, err := Derive("webp", []byte("RIFF....WEBP"), Edit{Turn: 90}, nil,
		Options{}); err == nil {
		t.Error("a webp was accepted for editing")
	}
}

// The action term says what was done, because c2pa.cropped and c2pa.resized
// are different statements.
func TestTheActionSaysWhatWasDone(t *testing.T) {
	for _, tc := range []struct {
		e    Edit
		want string
	}{
		{Edit{Aspect: "16:9"}, "c2pa.cropped"},
		{Edit{Crop: &Box{W: 50, H: 50}}, "c2pa.cropped"},
		{Edit{Turn: 90}, "c2pa.orientation"},
		{Edit{Flip: "across"}, "c2pa.orientation"},
		{Edit{Grey: true}, "c2pa.color_adjustments"},
	} {
		if got := tc.e.Action(); got != tc.want {
			t.Errorf("%s asserts %s, want %s", tc.e.Describe(), got, tc.want)
		}
	}
}
