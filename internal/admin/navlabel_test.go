// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import "testing"

// Every label in the menu fits on one line.
//
// "What agents remember" took two lines in the sidebar, and a menu item on
// two lines reads as two items. A label has 131 pixels beside its icon at
// 1,280 wide (the drawer on a phone has more); these are the widths
// Chromium drew each character at in the menu's font, Quilzo UI at 500 and
// 14px. The limit leaves a few pixels for the difference between the sum
// of characters and the drawn word.
var labelWidths = map[string]int{
	" ":                          4,
	",":                          3,
	"!'.:;Iijl|":                 4,
	"/":                          4,
	"()[\\}":                     5,
	"1\"]frt{":                   6,
	"*-?^`x":                     7,
	"235+>EFJLcksvyz":            8,
	"46789#$<=BKPRSTXYZabehnpu~": 9,
	"0&ADHNUV_dgoq":              10,
	"Cw":                         11,
	"GOQ":                        12,
	"%@M":                        13,
	"Wm":                         14,
}

const labelRoom = 126

func labelWidth(s string) int {
	w := 0
	for _, r := range s {
		width := 14 // anything not measured counts as the widest
		for chars, px := range labelWidths {
			if containsRune(chars, r) {
				width = px
				break
			}
		}
		w += width
	}
	return w
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestEveryNavLabelFitsOnOneLine(t *testing.T) {
	// The measure itself: what wrapped does not fit, and what fits does.
	if labelWidth("What agents remember") <= labelRoom || labelWidth("Agents remember") <= labelRoom {
		t.Fatal("labels Chromium drew on two lines measure as fitting")
	}
	if labelWidth("Workforce risk xx") > labelRoom {
		t.Fatal("a label Chromium drew on one line measures as too wide")
	}
	for _, d := range destinations {
		if w := labelWidth(d.Label); w > labelRoom {
			t.Errorf("%q is about %d pixels wide and the menu has %d: it would take two lines", d.Label, w, labelRoom)
		}
	}
}
