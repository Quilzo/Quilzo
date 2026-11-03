// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// The account menu is two choices and it does not scroll.
//
// It did. The menu opens inside the bar, and the bar's rule for small text
// links -- 5px of padding above and below and the same as a negative margin,
// so a 16px link becomes a 24px target without its line moving -- reached the
// menu's 44px items too. In the menu's grid the negative margin took 10px off
// every row: the two items overlapped by 8px, and the last one ended a pixel
// below the menu, whose overflow (auto, as every popover's is) then drew a
// scroll bar beside "Your profile" and "Sign out".
//
// Measured in Chromium before the fix: grid rows 73px 34px 34px for items
// 44px tall, scrollHeight 154 against a clientHeight of 153. A layout cannot
// be computed here, so this holds the two facts that produced it: the menu
// is inside the bar, and a menu item's own rule, later in the stylesheet,
// takes the margin back.
func TestTheAccountMenuItemsDoNotOverlapOrScroll(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/", token).Body.String()
	bar := body[:strings.Index(body, "</header>")]
	if !strings.Contains(bar, `id="accountmenu" class="menu" popover`) {
		t.Fatal("the account menu is no longer in the bar; re-check what of the bar's link rule reaches it")
	}
	css := stylesheet(t)
	barRule := strings.Index(css, ".bar a, p > a:only-child {")
	if barRule < 0 {
		t.Fatal("the bar's link target rule moved; this test reads where it is")
	}
	item := regexp.MustCompile(`(?m)^\.menu a, \.menu button, \.menu-danger \{[^}]*margin-block: 0;`).FindStringIndex(css)
	if item == nil {
		t.Fatal("the menu item rule does not set margin-block: 0, so the bar's -5px reaches the menu's items")
	}
	if item[0] < barRule {
		t.Error("the menu item rule comes before the bar's link rule, so the bar's -5px wins on equal specificity")
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
