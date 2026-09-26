// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package screen

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
)

// editor builds something the shape of a code editor: a dark background,
// a slightly different gutter, and text-like runs in two or three colours.
//
// Synthetic, and deliberately so. A screenshot checked into a test is a
// licence question and a megabyte in the repository; what matters here is the
// structure — flat colour, hard edges, a small palette per region — and that
// is reproducible.
func editor(w, h int) Frame {
	f := Frame{Width: w, Height: h, Pix: make([]byte, w*h*4)}
	bg := colour{0x1e, 0x1e, 0x2e, 0xff}
	gutter := colour{0x18, 0x18, 0x25, 0xff}
	text := colour{0xcd, 0xd6, 0xf4, 0xff}
	keyword := colour{0xcb, 0xa6, 0xf7, 0xff}

	set := func(x, y int, c colour) {
		if x < 0 || y < 0 || x >= w || y >= h {
			return
		}
		copy(f.Pix[(y*w+x)*4:], c[:])
	}
	for y := range h {
		for x := range w {
			c := bg
			if x < 48 {
				c = gutter
			}
			set(x, y, c)
		}
	}
	// Lines of "text": eight pixels tall, every sixteenth row, with runs of
	// glyph-shaped pixels. Deterministic, so the test is too.
	r := rand.New(rand.NewPCG(7, 11))
	for line := 0; line*16+12 < h; line++ {
		y := line*16 + 4
		x := 56
		for x < w-8 {
			run := 3 + r.IntN(6)
			c := text
			if r.IntN(5) == 0 {
				c = keyword
			}
			for dx := range run {
				for dy := range 7 {
					if (dx+dy)%3 != 0 {
						set(x+dx, y+dy, c)
					}
				}
			}
			x += run + 1 + r.IntN(4)
		}
	}
	return f
}

// photo builds something with no palette at all: every pixel different.
func photo(w, h int) Frame {
	f := Frame{Width: w, Height: h, Pix: make([]byte, w*h*4)}
	r := rand.New(rand.NewPCG(3, 5))
	for i := 0; i+4 <= len(f.Pix); i += 4 {
		f.Pix[i] = byte(r.IntN(256))
		f.Pix[i+1] = byte(r.IntN(256))
		f.Pix[i+2] = byte(r.IntN(256))
		f.Pix[i+3] = 0xff
	}
	return f
}

func roundTrip(t *testing.T, e *Encoder, d *Decoder, f Frame) Stats {
	t.Helper()
	encoded, stats, err := e.Encode(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := d.Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.Width != f.Width || back.Height != f.Height {
		t.Fatalf("decoded %dx%d, want %dx%d", back.Width, back.Height,
			f.Width, f.Height)
	}
	if !bytes.Equal(back.Pix, f.Pix) {
		var first int
		for i := range f.Pix {
			if f.Pix[i] != back.Pix[i] {
				first = i
				break
			}
		}
		t.Fatalf("the decoded frame differs from the original, first at "+
			"byte %d (pixel %d)", first, first/4)
	}
	return stats
}

// Text is either right or it is not. This is the whole argument for the
// package, so it is the first test and it checks every byte.
func TestAFrameSurvivesExactly(t *testing.T) {
	f := editor(1280, 720)
	stats := roundTrip(t, NewEncoder(), NewDecoder(), f)
	if !stats.Key {
		t.Error("the first frame is not a key frame")
	}
	if stats.Changed != stats.Tiles {
		t.Errorf("a key frame sent %d of %d tiles", stats.Changed,
			stats.Tiles)
	}
	if stats.Ratio() < 5 {
		t.Errorf("an editor frame compressed %.1fx, which is not worth "+
			"having", stats.Ratio())
	}
	t.Logf("key frame: %d bytes from %d, %.0fx, %s", stats.Bytes,
		stats.Source, stats.Ratio(), stats.Why())
}

// Typing a character changes one tile out of five hundred, and that is where
// the compression comes from.
func TestTypingSendsOneTile(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	f := editor(1920, 1080)
	first := roundTrip(t, e, d, f)

	// A character appears: a few pixels in one tile.
	next := Frame{Width: f.Width, Height: f.Height,
		Pix: append([]byte(nil), f.Pix...)}
	for dy := range 7 {
		for dx := range 5 {
			copy(next.Pix[((404+dy)*next.Width+612+dx)*4:],
				[]byte{0xa6, 0xe3, 0xa1, 0xff})
		}
	}
	stats := roundTrip(t, e, d, next)

	if stats.Key {
		t.Fatal("the second frame is a key frame")
	}
	if stats.Changed != 1 {
		t.Fatalf("typing changed %d tile(s) of %d", stats.Changed,
			stats.Tiles)
	}
	if stats.Bytes > 400 {
		t.Errorf("one character cost %d bytes", stats.Bytes)
	}
	t.Logf("key frame %d bytes, then one character %d bytes (%d tiles)",
		first.Bytes, stats.Bytes, stats.Tiles)
}

// A still screen is a header, which is what a meeting looks like for most of
// its length.
func TestAnUnchangedFrameIsAlmostNothing(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	f := editor(1920, 1080)
	roundTrip(t, e, d, f)
	stats := roundTrip(t, e, d, f)

	if stats.Changed != 0 {
		t.Fatalf("an identical frame changed %d tile(s)", stats.Changed)
	}
	if stats.Bytes > 200 {
		t.Errorf("an unchanged 1920x1080 frame cost %d bytes", stats.Bytes)
	}
	if !strings.Contains(stats.Why(), "the frame is a header") {
		t.Errorf("the summary is %q", stats.Why())
	}
	t.Logf("still frame: %d bytes for %d pixels", stats.Bytes,
		f.Width*f.Height)
}

// A codec that silently emits fifty megabytes a second when pointed at the
// wrong content is worse than one that says it is the wrong tool.
func TestAPhotographIsReportedAsTheWrongContent(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	f := photo(640, 480)
	stats := roundTrip(t, e, d, f)

	if !stats.Photographic() {
		t.Fatalf("random pixels were not reported as photographic: %+v",
			stats)
	}
	if stats.Raw*2 <= stats.Changed {
		t.Errorf("%d of %d tiles went out raw", stats.Raw, stats.Changed)
	}
	if !strings.Contains(stats.Why(), "worst at") {
		t.Errorf("the summary is %q", stats.Why())
	}
	// It is still lossless, which roundTrip has already checked. It is just
	// large — and the point is that it says so.
	t.Logf("photograph: %d bytes from %d, %.2fx — %s", stats.Bytes,
		stats.Source, stats.Ratio(), stats.Why())

	// And an editor frame is not reported that way.
	e2, d2 := NewEncoder(), NewDecoder()
	if roundTrip(t, e2, d2, editor(640, 480)).Photographic() {
		t.Error("an editor frame was called photographic")
	}
}

// A terminal is flat colour, and a tile of one colour should cost five bytes
// before deflate.
func TestFlatColourCostsAlmostNothing(t *testing.T) {
	f := Frame{Width: 256, Height: 256, Pix: make([]byte, 256*256*4)}
	for i := 0; i+4 <= len(f.Pix); i += 4 {
		copy(f.Pix[i:], []byte{0x00, 0x00, 0x00, 0xff})
	}
	stats := roundTrip(t, NewEncoder(), NewDecoder(), f)
	if stats.Solid != stats.Tiles {
		t.Errorf("%d of %d tiles were solid", stats.Solid, stats.Tiles)
	}
	// Sixteen tiles at five bytes each, a bitmap, an eighteen-byte header,
	// and deflate over the lot.
	if stats.Bytes > 150 {
		t.Errorf("a blank 256x256 screen cost %d bytes", stats.Bytes)
	}
}

// Two colours at one bit a pixel is the text case and is where most of the
// win is.
func TestTwoColourTilesUseOneBitAPixel(t *testing.T) {
	f := Frame{Width: 128, Height: 128, Pix: make([]byte, 128*128*4)}
	for y := range 128 {
		for x := range 128 {
			c := []byte{0x1e, 0x1e, 0x2e, 0xff}
			if (x/2+y/3)%2 == 0 {
				c = []byte{0xcd, 0xd6, 0xf4, 0xff}
			}
			copy(f.Pix[(y*128+x)*4:], c)
		}
	}
	stats := roundTrip(t, NewEncoder(), NewDecoder(), f)
	if stats.Mono != stats.Tiles {
		t.Errorf("%d of %d tiles were two-colour", stats.Mono, stats.Tiles)
	}
	if !strings.Contains(stats.Why(), "which is text") {
		t.Errorf("the summary is %q", stats.Why())
	}
}

// Sixteen colours is the ceiling, and the seventeenth sends the tile raw.
func TestThePaletteCeilingIsWhereRawBegins(t *testing.T) {
	build := func(colours int) Frame {
		f := Frame{Width: 64, Height: 64, Pix: make([]byte, 64*64*4)}
		for i := 0; i+4 <= len(f.Pix); i += 4 {
			v := byte((i / 4) % colours)
			copy(f.Pix[i:], []byte{v, v, v, 0xff})
		}
		return f
	}
	at := roundTrip(t, NewEncoder(), NewDecoder(), build(MaxPalette))
	if at.Palette != 1 {
		t.Errorf("%d colours gave %d palette tile(s)", MaxPalette,
			at.Palette)
	}
	over := roundTrip(t, NewEncoder(), NewDecoder(), build(MaxPalette+1))
	if over.Raw != 1 {
		t.Errorf("%d colours gave %d raw tile(s)", MaxPalette+1, over.Raw)
	}
}

// The last column and row are partial, which is where an off-by-one in the
// packing would live.
func TestPartialTilesAtTheEdgesRoundTrip(t *testing.T) {
	for _, size := range [][2]int{
		{1, 1}, {63, 63}, {65, 65}, {100, 37}, {TileSize, TileSize},
		{TileSize + 1, TileSize - 1}, {1920, 1080},
	} {
		f := editor(size[0], size[1])
		roundTrip(t, NewEncoder(), NewDecoder(), f)
	}
}

// A receiver that missed a tile is wrong until it is sent another key frame,
// and this codec has no concealment. Saying so is better than pretending a
// lost packet is survivable.
func TestAKeyframeCanBeAskedFor(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	f := editor(320, 240)
	roundTrip(t, e, d, f)
	if s := roundTrip(t, e, d, f); s.Key {
		t.Fatal("the second frame was a key frame unasked")
	}
	e.Keyframe()
	s := roundTrip(t, e, d, f)
	if !s.Key {
		t.Fatal("a requested key frame was not one")
	}
	if s.Changed != s.Tiles {
		t.Errorf("a key frame sent %d of %d tiles", s.Changed, s.Tiles)
	}
}

// A resize is a key frame whether anybody asked or not, because a delta
// against a different shape has nowhere to land.
func TestAResizeForcesAKeyframe(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	roundTrip(t, e, d, editor(320, 240))
	s := roundTrip(t, e, d, editor(640, 480))
	if !s.Key {
		t.Fatal("a resize produced a delta")
	}
}

// A decoder that allocated whatever it was told to would be a way to
// exhaust memory from the network.
func TestADecoderRefusesWhatItCannotHold(t *testing.T) {
	e := NewEncoder()
	good, _, err := e.Encode(editor(128, 128))
	if err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func([]byte) []byte{
		"a different magic": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] = 'X'
			return out
		},
		"a future version": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[4] = 99
			return out
		},
		"an enormous width": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[6], out[7], out[8], out[9] = 0x7f, 0xff, 0xff, 0xff
			return out
		},
		"a zero height": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[10], out[11], out[12], out[13] = 0, 0, 0, 0
			return out
		},
		"an enormous payload": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[14], out[15], out[16], out[17] = 0x7f, 0xff, 0xff, 0xff
			return out
		},
		"a truncated frame": func(b []byte) []byte { return b[:len(b)/2] },
		"nothing at all":    func([]byte) []byte { return nil },
	} {
		if _, err := NewDecoder().Decode(spoil(good)); err == nil {
			t.Errorf("a frame with %s was decoded", name)
		}
	}
	// The ceiling message says why it exists rather than just refusing.
	bad := append([]byte(nil), good...)
	bad[14], bad[15], bad[16], bad[17] = 0x7f, 0xff, 0xff, 0xff
	_, err = NewDecoder().Decode(bad)
	if !strings.Contains(err.Error(), "exhaust memory") {
		t.Errorf("the refusal is %v", err)
	}
}

// A delta with no key frame before it has nothing to apply to, and saying so
// is better than painting on an empty buffer.
func TestADeltaWithoutAKeyframeIsRefused(t *testing.T) {
	e := NewEncoder()
	f := editor(320, 240)
	if _, _, err := e.Encode(f); err != nil {
		t.Fatal(err)
	}
	next := Frame{Width: f.Width, Height: f.Height,
		Pix: append([]byte(nil), f.Pix...)}
	copy(next.Pix[0:], []byte{1, 2, 3, 4})
	delta, _, err := e.Encode(next)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh decoder has never seen the key frame.
	_, err = NewDecoder().Decode(delta)
	if err == nil {
		t.Fatal("a delta applied to nothing")
	}
	if !strings.Contains(err.Error(), "missed a key frame") {
		t.Errorf("the refusal is %v", err)
	}
}

func TestAMalformedFrameIsRefused(t *testing.T) {
	for name, f := range map[string]Frame{
		"no pixels":     {Width: 0, Height: 10, Pix: nil},
		"wrong length":  {Width: 4, Height: 4, Pix: make([]byte, 10)},
		"absurdly wide": {Width: MaxDimension + 1, Height: 1},
	} {
		if _, _, err := NewEncoder().Encode(f); err == nil {
			t.Errorf("a frame with %s was encoded", name)
		}
	}
}

// The numbers the package exists for, printed so a reader can see them
// rather than take the doc comment's word.
func TestTheArithmeticIsWorthIt(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	f := editor(1920, 1080)
	key := roundTrip(t, e, d, f)

	next := Frame{Width: f.Width, Height: f.Height,
		Pix: append([]byte(nil), f.Pix...)}
	for dy := range 7 {
		for dx := range 5 {
			copy(next.Pix[((404+dy)*next.Width+612+dx)*4:],
				[]byte{0xa6, 0xe3, 0xa1, 0xff})
		}
	}
	typed := roundTrip(t, e, d, next)
	still := roundTrip(t, e, d, next)

	t.Logf("1920x1080, four bytes a pixel: %d bytes raw", key.Source)
	t.Logf("  key frame   %7d bytes  (%.0fx)", key.Bytes, key.Ratio())
	t.Logf("  a keystroke %7d bytes", typed.Bytes)
	t.Logf("  still       %7d bytes", still.Bytes)
	t.Logf("  at 30fps, a session of typing is about %d KB/s",
		typed.Bytes*30/1024)

	if typed.Bytes*30 > key.Bytes {
		t.Error("a second of typing costs more than a whole key frame, " +
			"which means the delta is not doing its job")
	}
}
