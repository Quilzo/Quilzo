// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
)

// Saying which part of a picture must survive a crop.
//
// Renditions are narrower copies; the crop happens in the browser, where the
// gallery, the portraits and both aspect-ratio helpers all say
// `object-fit: cover` and the default is dead centre. A wide photograph in a
// square frame keeps its middle, so a face standing to one side is what goes.
//
// See internal/medialib/focus.go for why this turns into a stylesheet rule
// rather than a template change.

// spots are the nine places anybody actually means.
//
// A name rather than two numbers, because "top left" is what somebody says and
// 0,0 is what they would have to work out. The numbers are still there for the
// case a name does not fit — a horizon two-thirds down, a face slightly off a
// third — and that case is rare enough to be the long form.
var spots = map[string]media.Focus{
	"top-left":     {X: 0, Y: 0},
	"top":          {X: 50, Y: 0},
	"top-right":    {X: 100, Y: 0},
	"left":         {X: 0, Y: 50},
	"centre":       {X: 50, Y: 50},
	"center":       {X: 50, Y: 50},
	"right":        {X: 100, Y: 50},
	"bottom-left":  {X: 0, Y: 100},
	"bottom":       {X: 50, Y: 100},
	"bottom-right": {X: 100, Y: 100},
}

func spotNames() string {
	names := make([]string, 0, len(spots))
	for n := range spots {
		// One spelling in the message. Both are accepted and listing both
		// makes the list read as eleven places rather than nine.
		if n == "center" {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func mediaFocus(root string, args []string) error {
	fs := flag.NewFlagSet("focus", flag.ContinueOnError)
	at := fs.String("at", "",
		"one of: "+spotNames()+"; or two percentages as X,Y")
	clear := fs.Bool("clear", false, "go back to the centre")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf(
			"usage: quilzo media focus ID --at top-left\n" +
				"       quilzo media focus ID --at 30,20\n" +
				"       quilzo media focus ID --clear")
	}

	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	f, err := lib.Stat(rest[0])
	if err != nil {
		return err
	}
	if f.Kind != media.Image {
		// Refused rather than stored. A focus only means something where
		// something crops, and recording one on a PDF is a setting that will
		// never do anything and will outlive whoever set it.
		return fmt.Errorf(
			"%s is a %s, and a focal point is about cropping a picture",
			f.Name, f.Kind)
	}

	switch {
	case *clear:
		f.Focus = nil
	case strings.TrimSpace(*at) == "":
		// Reading rather than writing. `media focus ID` with no flags is what
		// somebody types to find out what it is set to.
		return reportFocus(f)
	default:
		spot, perr := parseSpot(*at)
		if perr != nil {
			return perr
		}
		f.Focus = &spot
	}

	_, body, err := lib.Get(f.ID)
	if err != nil {
		return err
	}
	// Written back through the library, which re-derives the narrower copies.
	// They are rebuilt rather than edited for the reason `media origin` gives:
	// each is its own file at its own hash.
	f.Renditions = nil
	if err := lib.Put(f, body); err != nil {
		return err
	}

	record(root, resolveCaller(root, "").auditRecord("media.focus", "/"+f.ID,
		audit.Success, map[string]string{"at": f.Focus.Position()}))

	if w.JSON(f) {
		return nil
	}
	if f.Focus == nil {
		w.Human("  %s%s crops from the centre again%s\n", dim, f.Name, reset)
		return nil
	}
	w.Human("  %s%s crops around %s%s\n", dim, f.Name, f.Focus.Position(), reset)
	w.Human("  %severy layout that already crops this picture uses it; "+
		"nothing else changes%s\n", dim, reset)
	return nil
}

func reportFocus(f media.File) error {
	if w.JSON(f) {
		return nil
	}
	if f.Focus == nil {
		w.Human("  %s%s crops from the centre, which is the default%s\n",
			dim, f.Name, reset)
		return nil
	}
	w.Human("  %s%s crops around %s%s\n", dim, f.Name, f.Focus.Position(), reset)
	return nil
}

// parseSpot reads a name or a pair of percentages.
func parseSpot(s string) (media.Focus, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if spot, ok := spots[s]; ok {
		return spot, nil
	}
	x, y, found := strings.Cut(s, ",")
	if !found {
		return media.Focus{}, fmt.Errorf(
			"%q is not a place. Use one of: %s\n"+
				"  or two percentages from the top left, as X,Y — 30,20",
			s, spotNames())
	}
	xn, xerr := strconv.Atoi(strings.TrimSpace(x))
	yn, yerr := strconv.Atoi(strings.TrimSpace(y))
	if xerr != nil || yerr != nil {
		return media.Focus{}, fmt.Errorf(
			"%q is not two numbers. A point is X,Y in percent from the top "+
				"left, so the middle is 50,50", s)
	}
	// Refused rather than clamped. Position clamps because it writes a
	// stylesheet and must be certain; here somebody typed something, and
	// silently turning 200 into 100 teaches them the wrong thing about what
	// the number means.
	if xn < 0 || xn > 100 || yn < 0 || yn > 100 {
		return media.Focus{}, fmt.Errorf(
			"%d,%d is outside the picture. Both are percentages, so 0 to 100",
			xn, yn)
	}
	return media.Focus{X: xn, Y: yn}, nil
}
