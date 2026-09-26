// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package annotate

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/screen"
)

// tallDoc is a document taller than the window, so scrolling reveals
// content instead of sliding everything into blank space.
func tallDoc(lines int) screen.Frame {
	long := screen.Frame{Width: wide, Height: screen.TileSize * 40,
		Pix: make([]byte, wide*screen.TileSize*40*4)}
	for i := range long.Pix {
		long.Pix[i] = 0xF8
	}
	// Draw the lines directly at pixel rows rather than tile rows, so a
	// scroll of any distance is a real translation of real content.
	for line := range lines {
		y := line * 24
		if y+16 >= long.Height {
			break
		}
		seed := uint32(line)*2654435761 + 1
		for gx := 0; gx < wide; gx += 8 {
			seed = seed*1103515245 + 12345
			if seed>>16&3 == 0 {
				continue
			}
			for gy := range 14 {
				ink := byte(seed >> uint(8+gy%3*8))
				for dx := range 6 {
					if (dx+gy*3)%5 == 0 {
						continue
					}
					o := ((y+gy)*wide + gx + dx) * 4
					long.Pix[o], long.Pix[o+1] = ink, 0x22
				}
			}
		}
	}
	return long
}

func view(doc screen.Frame, top int) screen.Frame {
	out := screen.Frame{Width: doc.Width, Height: tall,
		Pix: make([]byte, doc.Width*tall*4)}
	copy(out.Pix, doc.Pix[top*doc.Width*4:])
	return out
}

// TestTrackedThroughAnOddScroll is the case the tile grid cannot do alone:
// a hundred pixels is not a whole number of tiles, so no fingerprint matches
// and the mark would otherwise vanish.
func TestTrackedThroughAnOddScroll(t *testing.T) {
	doc := tallDoc(60)
	s := NewSession("s1")
	s.Board.Open = true
	if _, ok := s.Frame(view(doc, 0)); !ok {
		t.Fatal("the first frame is never a scroll")
	}
	at := time.Unix(1_800_000_000, 0).UTC()
	const markY = screen.TileSize*3 + 20
	if _, err := s.Mark("m1", "ada", at, Box,
		[]screen.Tile{{X: 100, Y: markY}, {X: 190, Y: markY + 18}},
		""); err != nil {
		t.Fatal(err)
	}

	if dy, ok := s.Frame(view(doc, 100)); !ok || dy != -100 {
		t.Fatalf("measured %d, ok = %v; want -100", dy, ok)
	}
	got := s.Place(at)
	if len(got) != 1 {
		t.Fatalf("%d placements", len(got))
	}
	p := got[0].Placement
	if p.State != Tracked {
		t.Fatalf("state = %s (%s), want tracked", p.State, p.State.Why())
	}
	if want := markY - 100; p.Y != want {
		t.Fatalf("y = %d, want %d", p.Y, want)
	}
	if !p.State.Drawable() {
		t.Fatal("a tracked mark is drawn")
	}
}

// TestContentBeatsTracking: when the content is findable, that answer wins,
// because it is a sighting rather than an inference.
func TestContentBeatsTracking(t *testing.T) {
	doc := tallDoc(60)
	s := NewSession("s1")
	s.Board.Open = true
	s.Frame(view(doc, 0))
	at := time.Unix(1_800_000_000, 0).UTC()
	if _, err := s.Mark("m1", "ada", at, Pointer,
		[]screen.Tile{{X: 100, Y: screen.TileSize*3 + 20}}, ""); err != nil {
		t.Fatal(err)
	}
	s.Frame(view(doc, screen.TileSize*2))
	p := s.Place(at)[0].Placement
	if p.State != Followed {
		t.Fatalf("state = %s, want followed", p.State)
	}
}

// TestSwitchingWindowEndsTheEra: once the measurement breaks, the offset
// means nothing, and a mark from before it is placed by content or not at
// all.
func TestSwitchingWindowEndsTheEra(t *testing.T) {
	doc := tallDoc(60)
	s := NewSession("s1")
	s.Board.Open = true
	s.Frame(view(doc, 0))
	at := time.Unix(1_800_000_000, 0).UTC()
	if _, err := s.Mark("m1", "ada", at, Pointer,
		[]screen.Tile{{X: 100, Y: screen.TileSize*3 + 20}}, ""); err != nil {
		t.Fatal(err)
	}

	other := tallDoc(60)
	for i := range other.Pix {
		other.Pix[i] ^= 0x5A
	}
	if _, ok := s.Frame(view(other, 0)); ok {
		t.Fatal("a different window is not a scroll")
	}
	if s.Era() != 1 {
		t.Fatalf("era = %d, want 1", s.Era())
	}
	if s.Scrolled() != 0 {
		t.Fatal("a new era starts from nothing")
	}
	p := s.Place(at)[0].Placement
	if p.State.Drawable() {
		t.Fatalf("state = %s; a mark from a lost era is not placed by "+
			"arithmetic nobody can check", p.State)
	}
}

// TestScrolledOffIsLostRatherThanClamped.
func TestScrolledOffIsLostRatherThanClamped(t *testing.T) {
	doc := tallDoc(60)
	s := NewSession("s1")
	s.Board.Open = true
	s.Frame(view(doc, 0))
	at := time.Unix(1_800_000_000, 0).UTC()
	if _, err := s.Mark("m1", "ada", at, Pointer,
		[]screen.Tile{{X: 100, Y: 40}}, ""); err != nil {
		t.Fatal(err)
	}
	// Scroll far past it, a hundred pixels at a time so each step is
	// measurable.
	for top := 100; top <= 500; top += 100 {
		if _, ok := s.Frame(view(doc, top)); !ok {
			t.Fatalf("step to %d was not measured", top)
		}
	}
	if p := s.Place(at)[0].Placement; p.State != Lost {
		t.Fatalf("state = %s, want lost", p.State)
	}
}

func TestMarkNeedsAFrame(t *testing.T) {
	s := NewSession("s1")
	s.Board.Open = true
	if _, err := s.Mark("m1", "ada", time.Now(), Pointer,
		[]screen.Tile{{X: 1, Y: 1}}, ""); err == nil {
		t.Fatal("there is nothing to mark before the first frame")
	}
}
