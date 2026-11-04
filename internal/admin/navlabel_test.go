// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

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

// Every screen has one name: the menu's label, its heading and the tab's
// title say the same thing. The menu's Chatbots opened a tab called
// Assistants, Your accounts a screen called Connected accounts, Log one
// called Audit log and API one called API playground, so whoever followed
// the menu, or read a screen's name aloud, found a different one.
func TestEveryScreenIsCalledWhatTheMenuCallsIt(t *testing.T) {
	srv, token := fullyWired(t)
	wirePosture(srv, true)
	title := regexp.MustCompile(`(?s)<title>(.*?)</title>`)
	heading := regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)
	tags := regexp.MustCompile(`<[^>]+>`)
	checked := 0
	for _, d := range destinations {
		w := get(t, srv, d.Path, token)
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", d.Path, w.Code)
			continue
		}
		body := w.Body.String()
		var tab, h1 string
		if m := title.FindStringSubmatch(body); m != nil {
			tab = html.UnescapeString(m[1])
		}
		if m := heading.FindStringSubmatch(body); m != nil {
			h1 = strings.TrimSpace(html.UnescapeString(tags.ReplaceAllString(m[1], "")))
		}
		if h1 != d.Label {
			t.Errorf("the menu's %q opens a screen headed %q", d.Label, h1)
		}
		if tab != d.Label+" — Quilzo" {
			t.Errorf("the menu's %q opens a tab called %q", d.Label, tab)
		}
		checked++
	}
	if checked < 40 {
		t.Fatalf("only %d screens checked", checked)
	}
}
