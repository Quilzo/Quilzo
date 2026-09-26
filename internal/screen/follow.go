// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package screen

// Following content between frames.
//
// The tile index answers "where is this content now" only when the content
// landed back on the tile grid, which a scroll by whole lines does and a
// scroll by a hundred pixels does not. A hundred pixels is the common case,
// so the grid alone is not enough.
//
// What saves it is that a scroll is a translation: every row of the new
// frame is some row of the old one, moved. So hash the frame a pixel row at
// a time, and the shift falls out of which rows matched where. One pass over
// the pixels, no search, and the answer is exact rather than rounded to a
// tile.

// rowHash is FNV-1a over one row of pixels.
func (f Frame) rowHash(y int) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	row := f.Pix[y*f.Width*4 : (y+1)*f.Width*4]
	for _, b := range row {
		h ^= uint64(b)
		h *= prime64
	}
	return h
}

// Rows is a hash for every pixel row of a frame.
func (f Frame) Rows() []uint64 {
	out := make([]uint64, f.Height)
	for y := range f.Height {
		out[y] = f.rowHash(y)
	}
	return out
}

// common is how many times a row may repeat before it stops being evidence.
//
// A row of blank background appears hundreds of times and matches every
// other blank row at every possible shift, so it votes for everything and
// therefore for nothing. Dropping those rows is what keeps this one pass
// instead of a search.
const common = 8

// MinEvidence is the share of rows that have to agree before a measured
// scroll is believed.
//
// Below this the frames are not the same content moved, they are different
// content that happens to have some rows in common — a window changed, a
// menu opened, the presenter switched application. Guessing a shift there
// would move every mark on the screen by a number nobody can check.
const MinEvidence = 8 // one row in eight

// Scrolled measures how far a frame's content moved since the last one.
//
// A positive dy means the content moved down the screen. ok is false when
// the two frames are not the same thing translated, which is the answer
// whenever somebody switches window — and the answer that stops a mark being
// dragged somewhere arbitrary.
func Scrolled(before, after Frame) (dy int, ok bool) {
	if before.Width != after.Width || before.Height != after.Height ||
		before.Height == 0 {
		return 0, false
	}
	was := make(map[uint64][]int, before.Height)
	for y, h := range before.Rows() {
		was[h] = append(was[h], y)
	}
	votes := make(map[int]int, before.Height)
	for y, h := range after.Rows() {
		from := was[h]
		if len(from) == 0 || len(from) > common {
			continue
		}
		for _, o := range from {
			votes[y-o]++
		}
	}
	best, bestN, tied := 0, 0, 0
	for shift, n := range votes {
		switch {
		case n > bestN:
			best, bestN, tied = shift, n, 1
		case n == bestN:
			tied++
		}
	}
	// A rival is a different answer, not the same one off by a pixel. Rows
	// a few pixels apart can be identical — the flat top of a line of text,
	// the inside of a filled box — so shifts next to the winner are the
	// winner blurred, and a blur of a few pixels moves a mark by a few
	// pixels. A shift from somewhere else on the screen is a different
	// claim about what happened, and that is what has to be ruled out.
	rival := 0
	for shift, n := range votes {
		if abs(shift-best) <= blur {
			continue
		}
		if n > rival {
			rival = n
		}
	}
	need := after.Height / MinEvidence
	if need < 4 {
		need = 4
	}
	if tied > 1 || bestN < need || bestN < rival*2 {
		return 0, false
	}
	return best, true
}

// blur is how far apart two shifts have to be to count as rivals.
//
// About half a line of text.
const blur = 8

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
