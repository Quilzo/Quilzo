// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package annotate

import (
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/screen"
)

// Session follows a shared screen and holds the marks made on it.
//
// Two ways of finding a mark again, in order. First the content: the tile it
// was drawn on, looked up by what it contains. That is exact and survives
// anything — a scroll, a window moving, content coming back after being
// covered — but only when the content landed back on the tile grid.
//
// When it did not, the session falls back to how far the whole view has
// scrolled, measured from the frames themselves. That places the mark to the
// pixel through a scroll of any distance, and it is an inference rather than
// a sighting: it says where the content went, not that it is there. So it is
// drawn and it is labelled, and the moment the measurement breaks — somebody
// switches window — it stops being offered at all.
type Session struct {
	Board *Board

	last   screen.Frame
	total  int
	era    int
	primed bool
}

// NewSession starts a session with annotation closed.
func NewSession(id string) *Session {
	return &Session{Board: &Board{Session: id}}
}

// Frame advances the session to the next frame of the share.
//
// moved is how far the content scrolled since the last frame. ok is false
// when the two frames are not the same content translated, which is what
// switching window looks like: the session starts a new era, and marks from
// before it can only be found by their content.
func (s *Session) Frame(f screen.Frame) (moved int, ok bool) {
	if err := f.Valid(); err != nil {
		return 0, false
	}
	defer func() { s.last, s.primed = f, true }()
	if !s.primed {
		return 0, true
	}
	dy, ok := screen.Scrolled(s.last, f)
	if !ok {
		s.era++
		s.total = 0
		return 0, false
	}
	s.total += dy
	return dy, true
}

// Scrolled is how far the view has moved within the current era.
func (s *Session) Scrolled() int { return s.total }

// Era counts how many times the session lost track of the screen.
func (s *Session) Era() int { return s.era }

// Mark makes a mark on the frame the session is on and adds it.
func (s *Session) Mark(id, by string, at time.Time, k Kind,
	path []screen.Tile, note string) (Mark, error) {
	if !s.primed {
		return Mark{}, fmt.Errorf("there is no frame to mark yet")
	}
	m, err := Make(s.last, id, s.Board.Session, by, at, k, path, note)
	if err != nil {
		return Mark{}, err
	}
	m.Anchor.Era, m.Anchor.Offset = s.era, s.total
	return m, s.Board.Add(m)
}

// Place resolves every live mark against the frame the session is on.
func (s *Session) Place(at time.Time) []Placed {
	if !s.primed {
		return nil
	}
	ix := s.last.Index()
	live := s.Board.Live(at)
	out := make([]Placed, 0, len(live))
	for _, m := range live {
		p := m.Anchor.Resolve(ix)
		if !p.State.Drawable() && m.Anchor.Era == s.era {
			p = s.byScroll(m.Anchor, p)
		}
		out = append(out, Placed{Mark: m, Placement: p})
	}
	return out
}

// byScroll places an anchor by how far the view has moved since it was made.
func (s *Session) byScroll(a Anchor, content Placement) Placement {
	moved := s.total - a.Offset
	y := a.Row*screen.TileSize + a.DY + moved
	x := a.Col*screen.TileSize + a.DX
	if y < 0 || y >= s.last.Height {
		// It scrolled off. Reporting it gone is the true answer, and
		// clamping it to the edge of the screen would be a mark sitting in
		// the corner pointing at nothing.
		return Placement{X: x, Y: y, State: Lost, Original: false}
	}
	return Placement{
		X: x, Y: y, State: Tracked,
		Moved: screen.Tile{Y: moved}, Rivals: content.Rivals,
	}
}

// Look counts the states of every live mark on the current frame.
func (s *Session) Look(at time.Time) Sight {
	var sight Sight
	for _, p := range s.Place(at) {
		if p.Placement.State.Drawable() {
			sight.Drawn++
		}
		switch p.Placement.State {
		case Followed:
			sight.Followed++
		case Tracked:
			sight.Tracked++
		case Doubtful:
			sight.Doubtful++
		case Lost:
			sight.Lost++
		case Loose:
			sight.Loose++
		}
	}
	return sight
}
