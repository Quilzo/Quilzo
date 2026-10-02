// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"regexp"
	"strings"
	"testing"
)

// Search is in the bar at every width: the box where there is room for it,
// and a way to the Find screen where there is not. Below the wide layout
// the box used to go and nothing took its place, so a phone or a tablet had
// no search in the bar at all.
func TestTheBarHasAWayToSearchAtEveryWidth(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/", token).Body.String()
	bar := body[:strings.Index(body, "</header>")]
	if !strings.Contains(bar, `class="findbar"`) || !regexp.MustCompile(`<a class="iconbutton findlink" href="/find"`).MatchString(bar) {
		t.Fatal("the bar lacks the search box or the link to the Find screen")
	}
	css := stylesheet(t)
	if !strings.Contains(css, "@media (max-width: 59.99rem) { .findlink { display: inline-flex; } }") ||
		!strings.Contains(css, "@media (max-width: 59.99rem) { .findbar { display: none; } }") {
		t.Error("the search box and the link do not hand over at the same width")
	}
}

// The narrow rules end where the wide layout begins. "max-width: 60rem"
// and "min-width: 60rem" both match a window exactly 960 pixels wide, which
// is how the search box disappeared from the wide layout at that one width.
func TestNarrowAndWideRulesDoNotShareAWidth(t *testing.T) {
	css := stylesheet(t)
	if strings.Contains(css, "min-width: 60rem") && strings.Contains(css, "max-width: 60rem)") {
		t.Error("a max-width: 60rem rule matches the same 960px window as the wide layout; use 59.99rem")
	}
}

// A long name keeps to one line and keeps its whole self in the title. A
// forty-letter name wrapped into a column four lines tall that overlapped
// the search box.
func TestALongNameKeepsToOneLine(t *testing.T) {
	srv, token := setup(t)
	name := "Northwind Traders Internal Content Hub X"
	srv.Brand.Name = name
	body := get(t, srv, "/", token).Body.String()
	if !strings.Contains(body, `title="`+name+`"`) || !strings.Contains(body, `<span class="brand-name">`+name+`</span>`) {
		t.Fatal("the name is not in the bar whole, with a title")
	}
	if !regexp.MustCompile(`\.brand-name \{[^}]*white-space: nowrap[^}]*text-overflow|\.brand-name \{[^}]*text-overflow: ellipsis; white-space: nowrap`).MatchString(stylesheet(t)) {
		t.Error("the name is allowed to wrap")
	}
}

func stylesheet(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
