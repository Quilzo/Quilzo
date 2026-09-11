// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// The group holding the current screen is open, and it is the only one.
//
// Twenty-eight destinations in five groups made a column about 1,425 pixels
// tall. The layout is a grid row, so the page could not be shorter than the
// menu: /review has a third of a kilobyte of content and still produced a page
// taller than the screen, and seven screens had less in them than the
// navigation beside them.
//
// One <details> per group fixes that without a script, and the state is
// derived rather than stored — the group you want open is the one you are in,
// which is known at render time, so it is right on the first paint and cannot
// go stale when you navigate.
func TestOnlyTheCurrentNavGroupIsOpen(t *testing.T) {
	srv, token := fullyWired(t)

	for _, path := range []string{"/", "/design", "/people", "/review", "/media"} {
		t.Run(path, func(t *testing.T) {
			body := get(t, srv, path, token).Body.String()

			groups := strings.Count(body, `<details class="navgroup"`)
			if groups < 4 {
				t.Fatalf("found %d navigation groups; the menu is not being "+
					"rendered and this test proves nothing", groups)
			}
			if open := strings.Count(body, `<details class="navgroup" open>`); open != 1 {
				t.Errorf("%d of %d groups are open; exactly the one holding "+
					"this screen should be", open, groups)
			}
			// And it is the right one: the open group is the one containing
			// the entry marked as current.
			if got := openGroupWithCurrent(body); !got {
				t.Error("the open group does not contain the current entry, " +
					"so the menu opened a section you are not in")
			}
		})
	}
}

// Every destination is still in the document, closed rather than dropped.
//
// A disclosure hides its contents from assistive technology as well as from
// the eye, which is correct for a disclosure and wrong for a menu that has
// quietly lost entries. The distinction is whether the markup is there to be
// opened, so that is what this checks.
func TestCollapsingAGroupDoesNotDropItsEntries(t *testing.T) {
	srv, token := fullyWired(t)
	body := get(t, srv, "/", token).Body.String()

	// /people sits in a group that is closed on the pages screen.
	for _, path := range []string{"/people", "/settings", "/logs", "/publishing"} {
		if !strings.Contains(body, `href="`+path+`"`) {
			t.Errorf("%s is not in the document at all, so collapsing its "+
				"group removed it rather than closing it", path)
		}
	}
}

// openGroupWithCurrent reports whether the open group holds the current entry.
func openGroupWithCurrent(body string) bool {
	for _, seg := range strings.Split(body, `<details class="navgroup"`)[1:] {
		end := strings.Index(seg, "</details>")
		if end < 0 {
			continue
		}
		if !strings.HasPrefix(seg, " open>") {
			continue
		}
		if strings.Contains(seg[:end], `aria-current="page"`) {
			return true
		}
	}
	return false
}
