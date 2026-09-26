// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package screen

import (
	"math/rand/v2"
	"testing"
)

func noisy(w, h int, seed uint64) Frame {
	f := Frame{Width: w, Height: h, Pix: make([]byte, w*h*4)}
	for i := range f.Pix {
		f.Pix[i] = 0x20
	}
	r := rand.New(rand.NewPCG(seed, 99))
	for line := 0; line*16+10 < h; line++ {
		y := line*16 + 3
		for x := 20; x < w-20; {
			run := 3 + r.IntN(8)
			// Glyphs, so consecutive rows differ. Real text does; a
			// solid bar does not, and a fixture made of solid bars
			// would be testing something easier than the job.
			for dy := range 7 {
				ink := byte(0x80 + r.IntN(0x70))
				for dx := range run {
					if (dx+dy*3)%5 == 0 {
						continue
					}
					o := ((y+dy)*w + x + dx) * 4
					f.Pix[o], f.Pix[o+1], f.Pix[o+2] = ink, 0xd0, 0xf0
				}
			}
			x += run + 2 + r.IntN(4)
		}
	}
	return f
}

func shift(f Frame, by int) Frame {
	out := Frame{Width: f.Width, Height: f.Height,
		Pix: make([]byte, len(f.Pix))}
	for i := range out.Pix {
		out.Pix[i] = 0x20
	}
	row := f.Width * 4
	for y := range f.Height {
		src := y - by
		if src < 0 || src >= f.Height {
			continue
		}
		copy(out.Pix[y*row:(y+1)*row], f.Pix[src*row:(src+1)*row])
	}
	return out
}

func TestScrolledMeasuresAnOddShift(t *testing.T) {
	f := noisy(640, 480, 5)
	for _, by := range []int{-137, -64, -13, -1, 0, 1, 20, 100, 213} {
		got, ok := Scrolled(f, shift(f, by))
		if !ok {
			t.Errorf("shift %d: not measured", by)
			continue
		}
		if got != by {
			t.Errorf("shift %d: measured %d", by, got)
		}
	}
}

func TestScrolledRefusesUnrelatedFrames(t *testing.T) {
	a, b := noisy(640, 480, 5), noisy(640, 480, 77)
	if dy, ok := Scrolled(a, b); ok {
		t.Fatalf("two different screens measured as a scroll of %d", dy)
	}
}

func TestScrolledRefusesADifferentSize(t *testing.T) {
	if _, ok := Scrolled(noisy(640, 480, 1), noisy(800, 480, 1)); ok {
		t.Fatal("a resize is not a scroll")
	}
}

func TestScrolledIgnoresBlankRows(t *testing.T) {
	// A mostly empty screen: a few lines at the top, the rest background.
	// The blank rows match at every shift and must not decide the answer.
	f := Frame{Width: 320, Height: 480, Pix: make([]byte, 320*480*4)}
	for i := range f.Pix {
		f.Pix[i] = 0x20
	}
	r := rand.New(rand.NewPCG(3, 4))
	for line := range 12 {
		y := line*16 + 3
		for x := 10; x < 300; x += 9 {
			for dy := range 7 {
				ink := byte(0x80 + r.IntN(0x70))
				for dx := range 5 {
					if (dx+dy*3)%5 == 0 {
						continue
					}
					o := ((y+dy)*320 + x + dx) * 4
					f.Pix[o] = ink
				}
			}
		}
	}
	if dy, ok := Scrolled(f, shift(f, 48)); !ok || dy != 48 {
		t.Fatalf("dy = %d, ok = %v; want 48", dy, ok)
	}
}
