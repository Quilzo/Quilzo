// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// Cropping a picture without losing it.
//
// See internal/media/edit.go for why an edit derives rather than overwrites,
// and what it deliberately cannot do. This is the command; what it adds is
// everything that has to travel with the new file for it to be usable and
// lawful:
//
//	the licence   an edit does not renew permission and does not end it. A
//	              crop of a photograph licensed until October is licensed
//	              until October, and the rights gate has to see that.
//	the origin    a crop of a picture a model made is still a picture a model
//	              made. Dropping it here would be a way to launder generated
//	              content into an undeclared file, which is the exact failure
//	              the media provenance gate exists to catch.
//	the alt text  required before an image may be used, so a derivative with
//	              none is a file nobody can put on a page. Inherited, because
//	              a crop of a photograph usually shows the same thing —
//	              and overridable, because sometimes it does not.

func mediaEdit(root string, args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	crop := fs.String("crop", "",
		"an aspect ratio like 16:9, cropped around the focal point")
	box := fs.String("box", "",
		"an exact rectangle as percentages: x,y,width,height")
	turn := fs.String("turn", "",
		"right, left or over — a quarter, a quarter the other way, or a half")
	flip := fs.String("flip", "", "across (left to right) or down (top to bottom)")
	grey := fs.Bool("grey", false, "take the colour out")
	alt := fs.String("alt", "",
		"what the edited picture shows; inherited from the original when omitted")
	dryRun := fs.Bool("dry-run", false, "say what it would make, store nothing")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf(
			"usage: quilzo media edit ID [--crop 16:9] [--box x,y,w,h] " +
				"[--turn right] [--flip across] [--grey]")
	}

	e := media.Edit{Aspect: strings.TrimSpace(*crop), Grey: *grey}
	if b := strings.TrimSpace(*box); b != "" {
		parsed, err := parseBox(b)
		if err != nil {
			return err
		}
		e.Crop = parsed
	}
	switch strings.TrimSpace(*turn) {
	case "":
	case "right":
		e.Turn = 90
	case "over":
		e.Turn = 180
	case "left":
		e.Turn = 270
	default:
		return fmt.Errorf(
			"%q is not a turn; try right, left or over", strings.TrimSpace(*turn))
	}
	e.Flip = strings.TrimSpace(*flip)
	if err := e.Validate(); err != nil {
		return err
	}

	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	parent, err := lib.Stat(rest[0])
	if err != nil {
		return err
	}

	if *dryRun {
		// The same derivation, thrown away. Not a separate code path that
		// resembles the real one: a rehearsal that works while the performance
		// does not is the worst thing a --dry-run can be.
		_, body, perr := lib.Preview(rest[0], e, 0)
		if perr != nil {
			return perr
		}
		would, aerr := media.Accept(medialib.EditedName(parent, e), body, time.Now())
		if aerr != nil {
			return aerr
		}
		if w.JSON(map[string]any{
			"parent": parent.ID, "did": e.Describe(),
			"was":    fmt.Sprintf("%dx%d", parent.Width, parent.Height),
			"now":    fmt.Sprintf("%dx%d", would.Width, would.Height),
			"stored": false,
		}) {
			return nil
		}
		w.Human("  %s%s%s\n", dim, e.Describe(), reset)
		w.Human("  %sit would be about %dx%d, from %dx%d%s\n", dim,
			would.Width, would.Height, parent.Width, parent.Height, reset)
		inherits(parent)
		w.Human("  %snothing was stored%s\n", dim, reset)
		return nil
	}

	f, err := lib.Edit(rest[0], e, mediaOptionsAt(root),
		strings.TrimSpace(*alt), resolveCaller(root, "").Name)
	if err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("media.edit", "/",
		audit.Success, map[string]string{
			"from": shortID(parent.ID), "id": shortID(f.ID),
			"did": e.Describe(),
		}))

	if w.JSON(f) {
		return nil
	}
	w.Human("edited %s%s%s\n", bold, parent.Name, reset)
	w.Human("  %s%s%s\n", dim, e.Describe(), reset)
	w.Human("  %s%dx%d from %dx%d · %s · %d bytes%s\n", dim,
		f.Width, f.Height, parent.Width, parent.Height, f.Format, f.Size, reset)
	inherits(parent)
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	w.Human("  %sin a page: /media/%s%s\n", dim, f.ID, reset)
	w.Human("  %sthe original is untouched, and still %s%s\n",
		dim, shortID(parent.ID), reset)
	return nil
}

// inherits says what travelled with the copy, because a licence that silently
// did not follow is a licence somebody publishes without.
func inherits(parent media.File) {
	if parent.Origin.Declared() {
		w.Human("  %sit keeps the original's origin: %s%s\n",
			dim, parent.Origin.SourceType, reset)
	}
	if parent.Rights.Declared() {
		w.Human("  %sit keeps the original's licence: %s%s\n",
			dim, parent.Rights.Licence, reset)
	}
}

// parseBox reads "x,y,w,h" as percentages.
func parseBox(s string) (*media.Box, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf(
			"a box is four numbers: x,y,width,height as percentages, like " +
				"10,0,80,100")
	}
	var n [4]float64
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return nil, fmt.Errorf("%q in the box is not a number", p)
		}
		n[i] = v
	}
	return &media.Box{X: n[0], Y: n[1], W: n[2], H: n[3]}, nil
}
