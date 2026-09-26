// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/annotate"
	"github.com/quilzo/quilzo/internal/screen"
)

// Drawing on somebody else's screen, and the scroll that ruins it.
//
// Circle line 40, the presenter scrolls, and the circle is around line 52.
// Every product that annotates a screen share does this, because every one
// of them pins the drawing to the glass. This one pins it to the content —
// which the codec can do and a video codec cannot — and, where it cannot,
// says so and stops drawing rather than pointing confidently at the wrong
// line.
//
// `annotate follow` puts marks on a synthetic editor, scrolls it, and prints
// what happened to each one.

func cmdAnnotate(args []string) error {
	if len(args) == 0 {
		args = []string{"follow"}
	}
	switch args[0] {
	case "follow":
		return annotateFollow(args[1:])
	default:
		return fmt.Errorf("unknown annotate command %q; try follow", args[0])
	}
}

func annotateFollow(args []string) error {
	fs := flag.NewFlagSet("follow", flag.ContinueOnError)
	width := fs.Int("width", 1280, "the shared screen's width")
	height := fs.Int("height", 720, "its height")
	scroll := fs.Int("scroll", screen.TileSize*2,
		"how far the presenter scrolls, in pixels, after the marks are made")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scroll < 0 {
		return fmt.Errorf("scrolling up is the same problem upside down; " +
			"pass a positive number")
	}

	// A document taller than the window, so scrolling reveals content
	// rather than sliding the whole thing into blank space.
	doc := synthetic(*width, *height+*scroll+screen.TileSize)

	at := time.Now().UTC()
	sess := annotate.NewSession("demo")
	sess.Board.Open = true
	if _, ok := sess.Frame(viewport(doc, 0, *height)); !ok {
		return fmt.Errorf("the first frame could not be read")
	}

	type spot struct {
		name string
		x, y int
		kind annotate.Kind
	}
	spots := []spot{
		{"on a line of code", 200, *height / 4, annotate.Box},
		{"further down the file", 320, *height / 2, annotate.Arrow},
		{"in the margin", 8, *height * 3 / 4, annotate.Pen},
		{"a note on a line", 500, *height/4 + screen.TileSize, annotate.Note},
	}
	for i, s := range spots {
		path := []screen.Tile{{X: s.x, Y: s.y}}
		switch s.kind.Segments() {
		case 1:
		case 2:
			path = append(path, screen.Tile{X: s.x + 90, Y: s.y + 12})
		default:
			path = append(path, screen.Tile{X: s.x + 30, Y: s.y + 6})
		}
		note := ""
		if s.kind == annotate.Note {
			note = "is this the one that shadows the outer name?"
		}
		if _, err := sess.Mark(fmt.Sprintf("m%d", i+1), "ada", at, s.kind,
			path, note); err != nil {
			return err
		}
	}

	// The presenter scrolls, in the small steps a wheel produces rather
	// than one jump, because that is what the measurement sees.
	const step = 40
	for top := step; top <= *scroll; top += step {
		if _, ok := sess.Frame(viewport(doc, top, *height)); !ok {
			return fmt.Errorf("lost track of the screen at %d", top)
		}
	}
	if *scroll%step != 0 {
		if _, ok := sess.Frame(viewport(doc, *scroll, *height)); !ok {
			return fmt.Errorf("lost track of the screen at %d", *scroll)
		}
	}

	placed := sess.Place(at)
	sight := sess.Look(at)

	if w.JSON(map[string]any{
		"scroll": *scroll, "measured": sess.Scrolled(),
		"marks": placed, "sight": sight,
	}) {
		return nil
	}

	w.Human("%s%d mark(s) on a %dx%d screen, then it scrolls %d pixel(s)"+
		"%s\n", bold, len(placed), *width, *height, *scroll, reset)
	w.Human("  %smeasured from the frames as %d%s\n\n", dim,
		-sess.Scrolled(), reset)
	for i, p := range placed {
		colour := green
		if !p.Placement.State.Drawable() {
			colour = yellow
		}
		w.Human("  %s%-12s%s %s%s%s\n", dim, p.Mark.Kind, reset,
			colour, p.Placement.State, reset)
		w.Human("    %s%s%s\n", dim, spots[i].name, reset)
		w.Human("    %s%s%s\n", dim, p.Placement.State.Why(), reset)
		if p.Placement.State == annotate.Followed ||
			p.Placement.State == annotate.Tracked {
			w.Human("    %sdrawn at (%d, %d) instead of (%d, %d)%s\n",
				dim, p.Placement.X, p.Placement.Y, spots[i].x, spots[i].y,
				reset)
		}
		w.Human("\n")
	}
	if why := sight.Why(); why != "" {
		w.Human("  %s%s%s\n", bold, why, reset)
	}
	w.Human("\n  %sa mark that cannot be placed is not placed. Somewhere "+
		"between a rectangle around the wrong function and no rectangle at "+
		"all, the second is the one nobody has to catch%s\n", dim, reset)
	return nil
}

// viewport takes a screen-sized view of a taller document.
func viewport(doc screen.Frame, top, height int) screen.Frame {
	out := screen.Frame{Width: doc.Width, Height: height,
		Pix: make([]byte, doc.Width*height*4)}
	copy(out.Pix, doc.Pix[top*doc.Width*4:])
	return out
}
