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
	parent, body, err := lib.Get(rest[0])
	if err != nil {
		return err
	}
	if parent.Kind != media.Image {
		return fmt.Errorf(
			"%s is a %s, and this edits pictures", shortID(parent.ID), parent.Kind)
	}

	derived, err := media.Derive(parent.Format, body, e, parent.Focus,
		mediaOptionsAt(root))
	if err != nil {
		return err
	}

	f, err := media.Accept(editedName(parent, e), derived.Body, time.Now())
	if err != nil {
		return fmt.Errorf(
			"the edited picture does not validate, so it has not been "+
				"stored: %w", err)
	}
	// Everything that has to travel with it. See the comment at the top.
	f.Alt = strings.TrimSpace(*alt)
	if f.Alt == "" {
		f.Alt = parent.Alt
	}
	f.Rights = parent.Rights
	f.Origin = parent.Origin
	f.Source = parent.Source
	f.EditOf = parent.ID
	f.Edit = &e
	// Not the focal point. It was a point in the original, and after a crop or
	// a turn it names a different part of the picture — carrying it across
	// would silently move somebody's subject.
	f.UploadedBy = resolveCaller(root, "").Name

	if *dryRun {
		if w.JSON(map[string]any{
			"parent": parent.ID, "would_be": f.ID, "did": derived.Did,
			"was":   fmt.Sprintf("%dx%d", parent.Width, parent.Height),
			"now":   fmt.Sprintf("%dx%d", derived.Width, derived.Height),
			"bytes": derived.Now, "stored": false,
		}) {
			return nil
		}
		w.Human("  %swould be %s%s\n", dim, shortID(f.ID), reset)
		reportDerived(parent, f, derived)
		w.Human("  %snothing was stored%s\n", dim, reset)
		return nil
	}

	if err := lib.Put(f, derived.Body); err != nil {
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
	reportDerived(parent, f, derived)
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	w.Human("  %sin a page: /media/%s%s\n", dim, f.ID, reset)
	w.Human("  %sthe original is untouched, and still %s%s\n",
		dim, shortID(parent.ID), reset)
	return nil
}

func reportDerived(parent, f media.File, derived media.Optimised) {
	for _, did := range derived.Did {
		w.Human("  %s%s%s\n", dim, did, reset)
	}
	w.Human("  %s%dx%d from %dx%d · %s · %d bytes%s\n", dim,
		derived.Width, derived.Height, parent.Width, parent.Height,
		f.Format, derived.Now, reset)
	if parent.Origin.Declared() {
		w.Human("  %sit keeps the original's origin: %s%s\n",
			dim, parent.Origin.SourceType, reset)
	}
	if parent.Rights.Declared() {
		w.Human("  %sit keeps the original's licence: %s%s\n",
			dim, parent.Rights.Licence, reset)
	}
}

// editedName gives the derivative a name somebody can recognise in a list.
//
// The stored name is display only — the address is the hash — so this is
// allowed to be prose. A library of files all called the same thing is a
// library where the picker is useless, which is the screen this feature most
// obviously feeds.
func editedName(parent media.File, e media.Edit) string {
	base := parent.Name
	if base == "" {
		base = shortID(parent.ID)
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		base = base[:i]
	}
	var tag string
	switch {
	case e.Crop != nil:
		tag = "cropped"
	case strings.TrimSpace(e.Aspect) != "":
		tag = strings.ReplaceAll(strings.TrimSpace(e.Aspect), ":", "-")
	case e.Turn != 0:
		tag = "turned"
	case strings.TrimSpace(e.Flip) != "":
		tag = "flipped"
	case e.Grey:
		tag = "grey"
	}
	if e.Grey && tag != "grey" {
		tag += "-grey"
	}
	// Extension already carries the dot, which is how the format table
	// spells it — "name-16-9..png" is what adding another one produces.
	return base + "-" + tag + parent.Extension()
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
