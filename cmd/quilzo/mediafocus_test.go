// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/media"
)

// The command line and the browser mean the same thing by the same words.
//
// The nine places are written out twice, because the two tables live in
// packages that cannot import each other: cmd/quilzo reaches into
// internal/admin and not the other way round, and internal/admin must not
// depend on a command. One table would be better and is not available.
//
// So this is what holds them together. A place that means one point in the
// terminal and another in the browser is a setting that moves when you change
// interface, and nothing else would notice.
func TestBothInterfacesOfferTheSameNinePlaces(t *testing.T) {
	browser := admin.FocusPoints()

	for name, point := range spots {
		// "center" is accepted on the command line as a spelling of "centre".
		// The browser offers one spelling, because a list of nine places that
		// shows two of them twice reads as eleven.
		if name == "center" {
			if point != spots["centre"] {
				t.Errorf("the two spellings of centre disagree: %+v vs %+v",
					point, spots["centre"])
			}
			continue
		}
		theirs, known := browser[name]
		if !known {
			t.Errorf("the command line offers %q and the browser does not", name)
			continue
		}
		if theirs != point {
			t.Errorf("%q is %+v on the command line and %+v in the browser",
				name, point, theirs)
		}
	}

	for name := range browser {
		if _, known := spots[name]; !known {
			t.Errorf("the browser offers %q and the command line does not", name)
		}
	}
}

// Every place is inside the picture, and the corners are the corners.
//
// The numbers go into a stylesheet as percentages, so a place outside 0..100
// would be a declaration a browser drops — silently, leaving the crop where it
// was and nothing saying why.
func TestEveryPlaceIsInsideThePicture(t *testing.T) {
	corners := map[string]media.Focus{
		"top-left": {X: 0, Y: 0}, "top-right": {X: 100, Y: 0},
		"bottom-left": {X: 0, Y: 100}, "bottom-right": {X: 100, Y: 100},
		"centre": {X: 50, Y: 50},
	}
	for name, point := range spots {
		if point.X < 0 || point.X > 100 || point.Y < 0 || point.Y > 100 {
			t.Errorf("%q is %+v, which is outside the picture", name, point)
		}
		if want, known := corners[name]; known && point != want {
			t.Errorf("%q is %+v, want %+v", name, point, want)
		}
	}
	if len(spots) != 10 {
		t.Errorf("there are %d places; nine, plus the second spelling of "+
			"centre", len(spots))
	}
}

// What somebody types is refused rather than quietly moved.
func TestAPlaceThatIsNotAPlaceIsRefused(t *testing.T) {
	for _, in := range []string{
		"middle", "top left", "", "  ", "30", "30,", ",20",
		"a,b", "30,20,10", "-1,50", "50,101", "1000,1000",
	} {
		if _, err := parseSpot(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
	// And the forms that work, do.
	for in, want := range map[string]media.Focus{
		"top-left":  {X: 0, Y: 0},
		"TOP-LEFT":  {X: 0, Y: 0},
		" centre  ": {X: 50, Y: 50},
		"center":    {X: 50, Y: 50},
		"30,20":     {X: 30, Y: 20},
		" 30 , 20 ": {X: 30, Y: 20},
		"0,0":       {X: 0, Y: 0},
		"100,100":   {X: 100, Y: 100},
	} {
		got, err := parseSpot(in)
		if err != nil {
			t.Errorf("%q was refused: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q gave %+v, want %+v", in, got, want)
		}
	}
}
