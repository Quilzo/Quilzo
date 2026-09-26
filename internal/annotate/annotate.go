// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package annotate holds marks made on a shared screen.
//
// Everybody who has sat through a screen share knows the failure. Somebody
// circles line 40, the presenter scrolls, and the circle is now around line
// 52 — pointing, with complete confidence, at the wrong thing. Every product
// that draws on a screen share has this bug, because every one of them
// anchors a mark to the glass: the mark is at (840, 310) and it stays at
// (840, 310) while the content underneath it moves away.
//
// This package anchors a mark to the content instead. Because we own the
// codec, a frame can be asked what its tiles contain, and a mark records the
// fingerprint of the tile it was drawn on rather than the pixel it landed on.
// When the view scrolls, the tile holding that content is somewhere else in
// the next frame, and the mark is found there and moves with it.
//
// That only goes so far, and the honesty is in the part that does not work.
// A tile of blank background is identical to every other tile of blank
// background, so a mark on empty space cannot be anchored to anything and
// says so. Content that scrolled by a fraction of a tile is not found at all.
// And when the content is simply gone — the window closed, the document
// changed — the mark is lost.
//
// A mark in any of those states is *reported and not drawn*. That is the
// whole design. A circle around the wrong line of code is worse than no
// circle, because it is confidently wrong and nobody in the call can tell.
//
// Marks carry no pixels. A mark is a kind, a path, a colour, an author and a
// content fingerprint, and a fingerprint is a hash of pixels rather than the
// pixels. So the record of what a group pointed at during a session can be
// kept after the frames themselves are gone, which is usually what the
// retention schedule wants and never what a burnt-in overlay allows.
package annotate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/screen"
)

// Kind is what a mark is.
type Kind string

const (
	// Pointer is where somebody is looking. It is not a statement and it
	// expires on its own.
	Pointer Kind = "pointer"
	// Pen is a freehand stroke.
	Pen Kind = "pen"
	// Box is a rectangle, from one corner to the other.
	Box Kind = "box"
	// Arrow points from its first position at its second.
	Arrow Kind = "arrow"
	// Highlight is a translucent band over a run of content.
	Highlight Kind = "highlight"
	// Note is words placed at a position.
	Note Kind = "note"
)

// Kinds is every kind, in the order a chooser should offer them.
var Kinds = []Kind{Pointer, Pen, Box, Arrow, Highlight, Note}

// Known reports whether a kind is one this draws.
func (k Kind) Known() bool {
	for _, c := range Kinds {
		if c == k {
			return true
		}
	}
	return false
}

// Transient reports whether a kind disappears by itself.
//
// A pointer is a gesture: it means "here, now", and a gesture that stays on
// the screen after the moment has passed is litter. Everything else is a
// statement and stays until somebody takes it back.
func (k Kind) Transient() bool { return k == Pointer }

// Segments is how many positions a kind needs.
//
// Zero means any number above one.
func (k Kind) Segments() int {
	switch k {
	case Pointer, Note:
		return 1
	case Box, Arrow, Highlight:
		return 2
	default:
		return 0
	}
}

// MaxPoints caps a freehand stroke.
//
// A pen stroke is sampled from a pointing device and an unbounded one is a
// way to put a megabyte into a session record by holding the mouse down.
const MaxPoints = 2000

// MaxNote is the longest a note can be.
//
// Not a document. A note that needs more than this is a message, and a
// message belongs in the room where it can be threaded, edited and found
// again, rather than floating over a frame that will not exist tomorrow.
const MaxNote = 280

// Point is a position, in pixels, relative to a mark's anchor.
type Point struct {
	DX int `json:"dx"`
	DY int `json:"dy"`
}

// Mark is one thing somebody drew.
type Mark struct {
	ID      string      `json:"id"`
	Session string      `json:"session"`
	By      string      `json:"by"`
	At      time.Time   `json:"at"`
	Kind    Kind        `json:"kind"`
	Anchor  Anchor      `json:"anchor"`
	Path    []Point     `json:"path"`
	Colour  string      `json:"colour,omitempty"`
	Note    string      `json:"note,omitempty"`
	Until   time.Time   `json:"until,omitzero"`
	Pulled  *Retraction `json:"pulled,omitempty"`
}

// Retraction is a mark taken back.
//
// Taking a mark back leaves the retraction rather than removing the mark,
// for the same reason a deleted message leaves a tombstone: a session where
// marks can silently disappear is a session where nobody can say afterwards
// what was on the screen when a decision was made.
type Retraction struct {
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Why    string    `json:"why,omitempty"`
	Erased bool      `json:"erased,omitempty"`
}

// Retracted reports whether a mark has been taken back.
func (m Mark) Retracted() bool { return m.Pulled != nil }

// Live reports whether a mark should be on the screen at a moment.
func (m Mark) Live(at time.Time) bool {
	if m.Retracted() {
		return false
	}
	if !m.Until.IsZero() && !at.Before(m.Until) {
		return false
	}
	return !at.Before(m.At)
}

// Validate refuses a mark that cannot be drawn.
func (m Mark) Validate() error {
	if m.ID == "" || m.Session == "" || m.By == "" {
		return fmt.Errorf("a mark needs an id, a session and an author")
	}
	if m.At.IsZero() {
		return fmt.Errorf("a mark needs a time; ordering two marks that " +
			"overlap is the only way to know which is on top")
	}
	if !m.Kind.Known() {
		return fmt.Errorf("%q is not a kind of mark; the kinds are %s",
			m.Kind, joinKinds())
	}
	switch want := m.Kind.Segments(); {
	case want == 0 && len(m.Path) < 2:
		return fmt.Errorf("a %s needs at least two positions", m.Kind)
	case want > 0 && len(m.Path) != want:
		return fmt.Errorf("a %s is %d position(s), not %d",
			m.Kind, want, len(m.Path))
	}
	if len(m.Path) > MaxPoints {
		return fmt.Errorf("%d positions is more than a stroke; the cap is %d",
			len(m.Path), MaxPoints)
	}
	if m.Kind == Note {
		if strings.TrimSpace(m.Note) == "" {
			return fmt.Errorf("a note with no words is an empty box on " +
				"somebody else's screen")
		}
		if len([]rune(m.Note)) > MaxNote {
			return fmt.Errorf("a note is at most %d characters; this is %d, "+
				"which is a message and belongs in the room where it can be "+
				"found again", MaxNote, len([]rune(m.Note)))
		}
	} else if m.Note != "" {
		return fmt.Errorf("only a note carries words")
	}
	if m.Kind.Transient() && m.Until.IsZero() {
		return fmt.Errorf("a pointer has to expire; one that does not is a " +
			"stray dot nobody can remember putting there")
	}
	if !m.Until.IsZero() && !m.Until.After(m.At) {
		return fmt.Errorf("this expires before it is made")
	}
	return m.Anchor.Validate()
}

func joinKinds() string {
	out := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ", ")
}

// Make builds a mark against the frame it was drawn on.
//
// path is in screen pixels, which is what a pointing device gives. The first
// position sets the anchor and the rest are stored relative to it, so a mark
// that follows its content keeps its shape.
func Make(f screen.Frame, id, session, by string, at time.Time, k Kind,
	path []screen.Tile, note string) (Mark, error) {
	if len(path) == 0 {
		return Mark{}, fmt.Errorf("a mark needs somewhere to be")
	}
	a, err := Pin(f, path[0].X, path[0].Y)
	if err != nil {
		return Mark{}, err
	}
	x0, y0 := path[0].X, path[0].Y
	rel := make([]Point, 0, len(path))
	for _, p := range path {
		rel = append(rel, Point{DX: p.X - x0, DY: p.Y - y0})
	}
	m := Mark{
		ID: id, Session: session, By: by, At: at.UTC(), Kind: k,
		Anchor: a, Path: rel, Note: note,
	}
	if k.Transient() {
		m.Until = m.At.Add(PointerLife)
	}
	return m, m.Validate()
}

// PointerLife is how long a pointer stays up.
//
// Long enough to follow somebody's hand, short enough that a forgotten
// pointer is not a second cursor for the rest of the call.
const PointerLife = 4 * time.Second

// Board is every mark in one session.
type Board struct {
	Session string   `json:"session"`
	Marks   []Mark   `json:"marks,omitempty"`
	Allowed []string `json:"allowed,omitempty"`
	Open    bool     `json:"open,omitempty"`
}

// May reports whether somebody can mark.
//
// The default is closed. Open annotation is the right setting for a working
// session and the wrong one for a demonstration to a customer, and a product
// that guesses gets it wrong in the meeting where it matters.
func (b Board) May(who string) bool {
	if b.Open {
		return true
	}
	for _, a := range b.Allowed {
		if a == who {
			return true
		}
	}
	return false
}

// Add puts a mark on the board.
func (b *Board) Add(m Mark) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Session != b.Session {
		return fmt.Errorf("that mark is from session %s", m.Session)
	}
	if !b.May(m.By) {
		return fmt.Errorf("%s cannot mark this screen. Annotation is off "+
			"unless the person sharing turns it on", m.By)
	}
	for _, e := range b.Marks {
		if e.ID == m.ID {
			return nil // The same mark sent twice is one mark.
		}
	}
	b.Marks = append(b.Marks, m)
	return nil
}

// Retract takes a mark back.
func (b *Board) Retract(id, by, why string, at time.Time, erase bool) error {
	for i := range b.Marks {
		if b.Marks[i].ID != id {
			continue
		}
		m := &b.Marks[i]
		if m.Retracted() {
			return fmt.Errorf("that mark was already taken back")
		}
		if m.By != by && strings.TrimSpace(why) == "" {
			return fmt.Errorf("taking back somebody else's mark needs a " +
				"reason. It is their mark and they will want to know")
		}
		m.Pulled = &Retraction{
			By: by, At: at.UTC(), Why: strings.TrimSpace(why), Erased: erase,
		}
		if erase {
			m.Note = ""
		}
		return nil
	}
	return fmt.Errorf("no mark %s on this board", id)
}

// Live is the marks that should be drawn at a moment, bottom to top.
func (b Board) Live(at time.Time) []Mark {
	out := make([]Mark, 0, len(b.Marks))
	for _, m := range b.Marks {
		if m.Live(at) {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
