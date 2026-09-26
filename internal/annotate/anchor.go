// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package annotate

import (
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/screen"
)

// Anchor is what a mark is attached to.
//
// Tile is the content the mark was drawn on, as a hash of its pixels.
// Neighbours are the eight tiles around it, which is what tells two
// identical tiles apart: on a page of text a single line of body copy may
// appear twice, but a line with the same line above it and the same line
// below it usually appears once.
//
// Col and Row are where the tile sat when the mark was made. They are not
// how the mark is placed — they are how "it has not moved" is told from "it
// moved back to where it was", and they are the fallback when the content
// could not be anchored at all.
type Anchor struct {
	Tile       string   `json:"tile"`
	Neighbours []string `json:"neighbours,omitempty"`
	Col        int      `json:"col"`
	Row        int      `json:"row"`
	DX         int      `json:"dx"`
	DY         int      `json:"dy"`
	// Loose says the content was not distinctive enough to follow, so this
	// mark is pinned to the glass like everybody else's.
	Loose bool `json:"loose,omitempty"`
	// Era and Offset are the session's scroll measurement when the mark was
	// made: which unbroken run of frames, and how far into it. They are what
	// lets a mark be placed through a scroll that did not land on the tile
	// grid, and they mean nothing across an era boundary.
	Era    int `json:"era,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// Validate refuses an anchor that cannot place anything.
func (a Anchor) Validate() error {
	if a.Tile == "" {
		return fmt.Errorf("an anchor needs the content it was made on")
	}
	if a.Col < 0 || a.Row < 0 {
		return fmt.Errorf("an anchor cannot be off the top or left")
	}
	if a.DX < 0 || a.DX >= screen.TileSize ||
		a.DY < 0 || a.DY >= screen.TileSize {
		return fmt.Errorf("an offset inside a tile is 0 to %d, not (%d, %d)",
			screen.TileSize-1, a.DX, a.DY)
	}
	return nil
}

// Pin anchors a screen position to the content under it.
func Pin(f screen.Frame, x, y int) (Anchor, error) {
	if err := f.Valid(); err != nil {
		return Anchor{}, err
	}
	if x < 0 || y < 0 || x >= f.Width || y >= f.Height {
		return Anchor{}, fmt.Errorf(
			"(%d, %d) is off a %d by %d screen", x, y, f.Width, f.Height)
	}
	ix := f.Index()
	col, row := x/screen.TileSize, y/screen.TileSize
	a := Anchor{
		Tile:       ix.Fingerprint(col, row),
		Neighbours: neighboursOf(ix, col, row),
		Col:        col, Row: row,
		DX: x % screen.TileSize, DY: y % screen.TileSize,
	}
	// An anchor is only made if it can be found again in the very frame it
	// was made from, by the same search that will look for it later. That is
	// a stricter test than "is this tile unique", and a more useful one: on
	// a page of text no single tile may be unique while nearly every tile
	// with its own surroundings is. It also rules out the case this exists
	// to rule out — a mark on blank background, where the search would come
	// back with four hundred equally good answers.
	if _, _, ok := find(ix, a.Tile, a.Neighbours); !ok {
		a.Loose = true
		a.Neighbours = nil
	}
	return a, nil
}

// offsets are the eight tiles around one, in reading order.
var offsets = [8][2]int{
	{-1, -1}, {0, -1}, {1, -1},
	{-1, 0}, {1, 0},
	{-1, 1}, {0, 1}, {1, 1},
}

func neighboursOf(ix screen.Index, col, row int) []string {
	out := make([]string, len(offsets))
	for i, o := range offsets {
		out[i] = ix.Fingerprint(col+o[0], row+o[1])
	}
	return out
}

// find looks for content and its surroundings, and reports whether exactly
// one place on the screen is the best answer.
//
// Content that scrolled brings its neighbours along, which is what makes
// this work: two identical lines of text in different parts of a document
// almost never have identical lines above and below as well.
func find(ix screen.Index, tile string, nb []string) (screen.Tile, int, bool) {
	found := ix.At(tile)
	switch len(found) {
	case 0:
		return screen.Tile{}, 0, false
	case 1:
		return found[0], 1, true
	}
	best, bestScore, ties := screen.Tile{}, -1, 0
	for _, c := range found {
		score := 0
		for i, o := range offsets {
			if i >= len(nb) || nb[i] == "" {
				continue
			}
			if ix.Fingerprint(c.X+o[0], c.Y+o[1]) == nb[i] {
				score++
			}
		}
		switch {
		case score > bestScore:
			best, bestScore, ties = c, score, 1
		case score == bestScore:
			ties++
		}
	}
	// A tie, or a winner that matched nothing around it, is not an answer.
	// It is several answers, and picking one of them is the bug.
	if ties != 1 || bestScore <= 0 {
		return screen.Tile{}, len(found), false
	}
	return best, len(found), true
}

// State is what became of an anchor in a later frame.
type State string

const (
	// Held: the content is exactly where it was.
	Held State = "held"
	// Followed: the content moved and the mark went with it. This is the
	// case every other product gets wrong.
	Followed State = "followed"
	// Doubtful: the content is on the screen in more than one place and
	// nothing distinguishes them.
	Doubtful State = "doubtful"
	// Lost: the content is not on the screen any more.
	Lost State = "lost"
	// Tracked: the content was not found, but the view is known to have
	// scrolled by a measured distance and the mark went that far. Placed by
	// inference rather than by sighting, and labelled as such.
	Tracked State = "tracked"
	// Loose: the mark was never anchored to anything, because it was drawn
	// on blank space. It is where it was put, and that is all anybody can
	// say about it.
	Loose State = "loose"
)

// Drawable reports whether a mark in this state may be put on the screen.
//
// Doubtful and Lost are not drawn. This is the point of the package. A mark
// placed at a guessed position looks exactly like a mark placed at the right
// one, so the person reading the screen has no way to tell that the circle
// is around the wrong line — and the person who drew it has less, because on
// their screen it never moved.
func (s State) Drawable() bool {
	switch s {
	case Held, Followed, Tracked, Loose:
		return true
	default:
		return false
	}
}

// Why says what happened, for somebody reading a list of marks.
func (s State) Why() string {
	switch s {
	case Held:
		return "on the content it was drawn on"
	case Followed:
		return "the content moved and this moved with it"
	case Tracked:
		return "the content was not found on the grid, so this was placed " +
			"by how far the view is measured to have scrolled"
	case Doubtful:
		return "the content it was drawn on is now in several places and " +
			"nothing tells them apart, so this is not drawn"
	case Lost:
		return "the content it was drawn on is no longer on the screen, " +
			"so this is not drawn"
	case Loose:
		return "drawn on blank space, so it is pinned to the screen and " +
			"does not follow anything"
	}
	return string(s)
}

// Placement is where a mark goes in a particular frame.
type Placement struct {
	X, Y     int
	State    State
	Moved    screen.Tile // how far the content shifted, in tiles
	Rivals   int         // how many candidates, when Doubtful
	Original bool        // the position is where it was first drawn
}

// Resolve finds a mark's anchor in a later frame.
func (a Anchor) Resolve(ix screen.Index) Placement {
	at := func(t screen.Tile) (int, int) {
		return t.X*screen.TileSize + a.DX, t.Y*screen.TileSize + a.DY
	}
	was := screen.Tile{X: a.Col, Y: a.Row}
	ox, oy := at(was)

	if a.Loose {
		return Placement{X: ox, Y: oy, State: Loose, Original: true}
	}

	best, rivals, ok := find(ix, a.Tile, a.Neighbours)
	switch {
	case !ok && rivals == 0:
		return Placement{X: ox, Y: oy, State: Lost, Original: true}
	case !ok:
		return Placement{
			X: ox, Y: oy, State: Doubtful, Rivals: rivals, Original: true,
		}
	}
	return place(best, was, at)
}

func place(now, was screen.Tile, at func(screen.Tile) (int, int)) Placement {
	x, y := at(now)
	p := Placement{X: x, Y: y, State: Held, Original: now == was}
	if now != was {
		p.State = Followed
		p.Moved = screen.Tile{X: now.X - was.X, Y: now.Y - was.Y}
	}
	return p
}

// Placed is a mark and where it ended up.
type Placed struct {
	Mark      Mark      `json:"mark"`
	Placement Placement `json:"placement"`
}

// Resolve places every live mark against a frame.
//
// Bottom to top, so drawing them in order gives the right overlaps.
func (b Board) Resolve(f screen.Frame, at time.Time) []Placed {
	ix := f.Index()
	live := b.Live(at)
	out := make([]Placed, 0, len(live))
	for _, m := range live {
		out = append(out, Placed{Mark: m, Placement: m.Anchor.Resolve(ix)})
	}
	return out
}

// Sight is what a board looks like against one frame.
type Sight struct {
	Drawn    int `json:"drawn"`
	Followed int `json:"followed"`
	Tracked  int `json:"tracked"`
	Doubtful int `json:"doubtful"`
	Lost     int `json:"lost"`
	Loose    int `json:"loose"`
}

// Look counts the states of every live mark.
func (b Board) Look(f screen.Frame, at time.Time) Sight {
	var s Sight
	for _, p := range b.Resolve(f, at) {
		if p.Placement.State.Drawable() {
			s.Drawn++
		}
		switch p.Placement.State {
		case Followed:
			s.Followed++
		case Doubtful:
			s.Doubtful++
		case Lost:
			s.Lost++
		case Loose:
			s.Loose++
		}
	}
	return s
}

// Stale is the marks that are no longer pointing at anything.
//
// Worth saying out loud during a session rather than leaving to be noticed.
// Somebody drew those, believes they are on the screen, and is about to say
// "as you can see" about something nobody can see.
func (s Sight) Stale() int { return s.Doubtful + s.Lost }

// Why describes a sight in a sentence, or returns false when there is
// nothing worth saying.
func (s Sight) Why() string {
	switch {
	case s.Stale() == 0 && s.Followed == 0 && s.Tracked == 0:
		return ""
	case s.Stale() == 0 && s.Tracked == 0:
		return fmt.Sprintf("%d mark(s) moved with the content", s.Followed)
	case s.Stale() == 0 && s.Followed == 0:
		return fmt.Sprintf("%d mark(s) moved with the measured scroll",
			s.Tracked)
	case s.Stale() == 0:
		return fmt.Sprintf("%d mark(s) moved with the content and %d with "+
			"the measured scroll", s.Followed, s.Tracked)
	case s.Lost == 0:
		return fmt.Sprintf("%d mark(s) are not drawn: what they were drawn "+
			"on is now in more than one place", s.Doubtful)
	case s.Doubtful == 0:
		return fmt.Sprintf("%d mark(s) are not drawn: what they were drawn "+
			"on has gone", s.Lost)
	}
	return fmt.Sprintf("%d mark(s) are not drawn: %d lost their content and "+
		"%d cannot tell which copy of it is theirs", s.Stale(), s.Lost,
		s.Doubtful)
}
