// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package annotate

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/screen"
)

const (
	wide = screen.TileSize * 6
	tall = screen.TileSize * 8
)

// document draws something shaped like a text editor: mostly blank, with a
// run of lines that differ from one another, starting at a given scroll
// offset in lines. Scrolling means calling it again with a different offset,
// which is exactly what the anchor has to survive.
func document(firstLine, lines int) screen.Frame {
	f := screen.Frame{Width: wide, Height: tall,
		Pix: make([]byte, wide*tall*4)}
	for i := range f.Pix {
		f.Pix[i] = 0xF8 // blank background, identical everywhere
	}
	for row := range lines {
		line := firstLine + row
		y := row * screen.TileSize
		if y+screen.TileSize > tall {
			break
		}
		// Each line gets a run of "glyphs" drawn from its own number, so no
		// two lines look alike and no line looks like blank space.
		seed := uint32(line)*2654435761 + 1
		for gx := 0; gx < wide; gx += 8 {
			seed = seed*1103515245 + 12345
			if seed>>16&3 == 0 {
				continue // a space between words
			}
			ink := byte(seed >> 24)
			for gy := 8; gy < 24; gy++ {
				for dx := range 6 {
					o := ((y+gy)*wide + gx + dx) * 4
					f.Pix[o], f.Pix[o+1] = ink, 0x22
				}
			}
		}
	}
	return f
}

func mustMake(t *testing.T, f screen.Frame, k Kind, x, y int) Mark {
	t.Helper()
	path := []screen.Tile{{X: x, Y: y}}
	switch k.Segments() {
	case 1:
	case 2:
		path = append(path, screen.Tile{X: x + 40, Y: y + 20})
	default:
		path = append(path, screen.Tile{X: x + 10, Y: y + 5},
			screen.Tile{X: x + 20, Y: y + 9})
	}
	note := ""
	if k == Note {
		note = "this is the bit"
	}
	m, err := Make(f, "m1", "s1", "ada", time.Unix(1_800_000_000, 0), k,
		path, note)
	if err != nil {
		t.Fatalf("Make(%s): %v", k, err)
	}
	return m
}

// TestFollowsAScroll is the whole reason the package exists.
func TestFollowsAScroll(t *testing.T) {
	before := document(10, 6)
	m := mustMake(t, before, Box, 100, screen.TileSize*3+20)
	if m.Anchor.Loose {
		t.Fatal("a mark on a line of text should anchor to it")
	}

	// The same document, scrolled down by two lines. The content the mark
	// was drawn on is still on the screen, two tiles higher.
	after := document(12, 6)
	got := m.Anchor.Resolve(after.Index())
	if got.State != Followed {
		t.Fatalf("state = %s (%s), want followed", got.State, got.State.Why())
	}
	if got.Moved.Y != -2 || got.Moved.X != 0 {
		t.Fatalf("moved by %+v, want two tiles up", got.Moved)
	}
	if want := screen.TileSize*1 + 20; got.Y != want {
		t.Fatalf("y = %d, want %d", got.Y, want)
	}
	if got.X != 100 {
		t.Fatalf("x = %d, want it unchanged at 100", got.X)
	}
}

func TestUnmovedContentIsHeld(t *testing.T) {
	f := document(10, 6)
	m := mustMake(t, f, Pen, 100, screen.TileSize*2+10)
	got := m.Anchor.Resolve(f.Index())
	if got.State != Held {
		t.Fatalf("state = %s, want held", got.State)
	}
	if !got.Original {
		t.Fatal("an unmoved mark is at its original position")
	}
}

// TestBlankSpaceIsLoose is the honest half. A mark on empty background
// cannot follow anything, and says so instead of following the wrong thing.
func TestBlankSpaceIsLoose(t *testing.T) {
	f := document(10, 2) // two lines at the top, the rest blank
	m := mustMake(t, f, Arrow, 100, screen.TileSize*6+10)
	if !m.Anchor.Loose {
		t.Fatal("a mark on blank space should be loose")
	}
	got := m.Anchor.Resolve(document(12, 2).Index())
	if got.State != Loose {
		t.Fatalf("state = %s, want loose", got.State)
	}
	if !got.State.Drawable() {
		t.Fatal("a loose mark is still drawn, just not followed")
	}
}

// TestLostContentIsNotDrawn: the window changed and what was circled is gone.
func TestLostContentIsNotDrawn(t *testing.T) {
	m := mustMake(t, document(10, 6), Box, 100, screen.TileSize*3+20)
	got := m.Anchor.Resolve(document(900, 6).Index())
	if got.State != Lost {
		t.Fatalf("state = %s, want lost", got.State)
	}
	if got.State.Drawable() {
		t.Fatal("a lost mark must not be drawn; a box around whatever " +
			"scrolled into its place is worse than no box")
	}
}

// TestRepeatedContentIsDoubtful: two identical lines, nothing to tell them
// apart, so the mark is reported rather than placed on a coin flip.
func TestRepeatedContentIsDoubtful(t *testing.T) {
	f := document(10, 6)
	m := mustMake(t, f, Box, 100, screen.TileSize*3+20)

	// Build a frame where that exact line appears twice with identical
	// surroundings: every line the same.
	same := screen.Frame{Width: wide, Height: tall,
		Pix: make([]byte, wide*tall*4)}
	copy(same.Pix, f.Pix)
	src := f.Pix[screen.TileSize*3*wide*4 : screen.TileSize*4*wide*4]
	for row := range tall / screen.TileSize {
		o := row * screen.TileSize * wide * 4
		copy(same.Pix[o:], src)
	}
	got := m.Anchor.Resolve(same.Index())
	if got.State != Doubtful {
		t.Fatalf("state = %s, want doubtful", got.State)
	}
	if got.State.Drawable() {
		t.Fatal("a doubtful mark must not be drawn")
	}
	if got.Rivals < 2 {
		t.Fatalf("rivals = %d, want the count of candidates", got.Rivals)
	}
}

func TestBoardRefusesUnlessAllowed(t *testing.T) {
	f := document(10, 6)
	m := mustMake(t, f, Pen, 100, 100)
	b := &Board{Session: "s1"}
	if err := b.Add(m); err == nil {
		t.Fatal("annotation should be off by default")
	}
	b.Allowed = []string{"ada"}
	if err := b.Add(m); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Add(m); err != nil || len(b.Marks) != 1 {
		t.Fatalf("the same mark twice should be one mark: %v, %d marks",
			err, len(b.Marks))
	}
}

func TestPointerExpires(t *testing.T) {
	f := document(10, 6)
	m := mustMake(t, f, Pointer, 100, 100)
	if m.Until.IsZero() {
		t.Fatal("a pointer expires")
	}
	if !m.Live(m.At.Add(time.Second)) {
		t.Fatal("a fresh pointer is live")
	}
	if m.Live(m.At.Add(PointerLife)) {
		t.Fatal("a pointer past its life is not live")
	}
}

func TestRetractionKeepsTheMark(t *testing.T) {
	f := document(10, 6)
	m := mustMake(t, f, Note, 100, 100)
	b := &Board{Session: "s1", Open: true}
	if err := b.Add(m); err != nil {
		t.Fatal(err)
	}
	if err := b.Retract("m1", "grace", "", m.At, false); err == nil {
		t.Fatal("taking back somebody else's mark needs a reason")
	}
	if err := b.Retract("m1", "grace", "wrong line", m.At, true); err != nil {
		t.Fatal(err)
	}
	if len(b.Marks) != 1 {
		t.Fatal("a retraction keeps the mark and its record")
	}
	if b.Marks[0].Note != "" {
		t.Fatal("an erasing retraction takes the words")
	}
	if !b.Marks[0].Retracted() || b.Marks[0].Pulled.Why != "wrong line" {
		t.Fatal("the reason survives the erasure; the words do not")
	}
	if len(b.Live(m.At)) != 0 {
		t.Fatal("a retracted mark is not drawn")
	}
}

func TestValidateRefusesTheUseless(t *testing.T) {
	base := mustMake(t, document(10, 6), Pen, 100, 100)
	for _, c := range []struct {
		name string
		edit func(*Mark)
	}{
		{"no author", func(m *Mark) { m.By = "" }},
		{"unknown kind", func(m *Mark) { m.Kind = "laser" }},
		{"one point for a pen", func(m *Mark) { m.Path = m.Path[:1] }},
		{"three points for a box", func(m *Mark) { m.Kind = Box }},
		{"words on a stroke", func(m *Mark) { m.Note = "hello" }},
		{"empty note", func(m *Mark) { m.Kind = Note; m.Path = m.Path[:1] }},
		{"expires before it exists", func(m *Mark) {
			m.Until = m.At.Add(-time.Hour)
		}},
	} {
		m := base
		m.Path = append([]Point(nil), base.Path...)
		c.edit(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestSightCountsWhatIsNotDrawn(t *testing.T) {
	before := document(10, 6)
	b := &Board{Session: "s1", Open: true}
	for i, y := range []int{
		screen.TileSize*1 + 10, screen.TileSize*3 + 10,
	} {
		m := mustMake(t, before, Box, 100, y)
		m.ID = string(rune('a' + i))
		if err := b.Add(m); err != nil {
			t.Fatal(err)
		}
	}
	at := b.Marks[0].At
	if s := b.Look(before, at); s.Drawn != 2 || s.Stale() != 0 {
		t.Fatalf("against its own frame: %+v", s)
	}
	s := b.Look(document(900, 6), at)
	if s.Stale() != 2 || s.Drawn != 0 {
		t.Fatalf("against a different document: %+v", s)
	}
	if s.Why() == "" {
		t.Fatal("a sight with stale marks has something to say")
	}
}

// TestSubTileScrollIsLost states the limitation rather than hiding it.
//
// Content is followed when it moves by whole tiles, which is what a scroll
// by whole lines does. A scroll of a few pixels changes what every tile
// contains, so nothing matches and every mark is reported lost. That is the
// wrong answer in the sense that the content is still there — and the right
// behaviour, because the alternative is drawing the mark a few pixels out
// and saying nothing.
func TestSubTileScrollIsLost(t *testing.T) {
	before := document(10, 6)
	m := mustMake(t, before, Box, 100, screen.TileSize*3+20)

	nudged := screen.Frame{Width: wide, Height: tall,
		Pix: make([]byte, wide*tall*4)}
	for i := range nudged.Pix {
		nudged.Pix[i] = 0xF8
	}
	const by = 20
	copy(nudged.Pix, before.Pix[by*wide*4:])

	if got := m.Anchor.Resolve(nudged.Index()); got.State != Lost {
		t.Fatalf("state = %s, want lost", got.State)
	}
}
