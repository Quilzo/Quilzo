// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"regexp"
	"strings"
	"testing"
)

// The menu ends where the screen ends.
//
// The last group in the navigation — Reference — could not be scrolled to.
// The sidebar was `position: sticky; top: 0; max-height: 100vh`, and it starts
// below the bar: a box one viewport tall, beginning one bar-height down, ends
// one bar-height below the fold. Scrolling the menu to its internal end left
// that strip off-screen, and `overscroll-behavior: contain` — doing exactly
// what it was added for — stopped the gesture carrying on into the page. So
// the obvious thing to do did nothing, and the only way to reach the last
// group was to scroll the page rather than the menu.
//
// It came and went, because it only happens when the menu overflows at all.
// With the disclosure groups closed everything fits and there is no strip.
//
// The fix is arithmetic: stick below a bar of declared height and take that
// height off, so the bottom of the box lands on the bottom of the viewport at
// every scroll position. This test is what keeps the two halves of that
// arithmetic agreeing, because nothing else would notice them drifting — the
// page renders either way, and the symptom is a group you have to already
// know about to go looking for.
func TestTheMenuColumnEndsAtTheBottomOfTheScreen(t *testing.T) {
	css := readStyle(t)

	if !regexp.MustCompile(`--bar-h:\s*[\d.]+r?em`).MatchString(css) {
		t.Fatal("no --bar-h is declared; the sidebar's height is derived from " +
			"it and a number written twice is a number that drifts")
	}

	bar := ruleFor(t, css, `body > .bar {`)
	// height, not min-height. A minimum is a value that may be exceeded, and a
	// bar one line taller than it claims puts the end of the menu back below
	// the fold — which is the whole bug, reappearing only for whoever has a
	// long enough name to make the bar wrap.
	if !strings.Contains(bar, "height: var(--bar-h)") ||
		strings.Contains(bar, "min-height: var(--bar-h)") {
		t.Errorf("the bar does not declare `height: var(--bar-h)`, so the "+
			"number the sidebar subtracts is a guess:\n  %s", bar)
	}
	if !strings.Contains(bar, "position: sticky") {
		t.Errorf("the bar is not sticky, so the sidebar under it has no fixed "+
			"place to start from:\n  %s", bar)
	}

	side := ruleFor(t, css, `body > .sidenav {`)
	if !strings.Contains(side, "top: var(--bar-h)") {
		t.Errorf("the sidebar does not stick below the bar, so it sticks "+
			"underneath it:\n  %s", side)
	}
	// Both are checked rather than either: sticking below the bar without
	// taking its height off is the same overhang measured from a different
	// place, and taking it off without sticking below it hides the top of the
	// menu instead of the bottom. Neither half is a fix on its own.
	if !strings.Contains(side, "calc(100vh - var(--bar-h))") {
		t.Errorf("the sidebar is not a viewport less the bar, so its bottom "+
			"hangs below the fold and the last group cannot be scrolled to:\n  %s",
			side)
	}
	if strings.Contains(side, "max-height: 100vh;") {
		t.Errorf("the sidebar is a whole viewport tall and starts below the "+
			"bar, which is the overhang this fixed:\n  %s", side)
	}

	// A bar that wraps is taller than it says, and the arithmetic above is
	// then wrong by a line — silently, and only for some people's names.
	inner := ruleFor(t, css, `.bar-inner {`)
	if !strings.Contains(inner, "flex-wrap: nowrap") {
		t.Errorf("the bar may wrap in the wide layout, so its height is not "+
			"--bar-h for everybody:\n  %s", inner)
	}
}

// ruleFor returns the body of the last rule opening with sel.
//
// The last one, because these selectors appear at the top level and again
// inside the wide-layout media query, and it is the media query's copy that
// governs the arrangement this is about.
func ruleFor(t *testing.T, css, sel string) string {
	t.Helper()
	i := strings.LastIndex(css, sel)
	if i < 0 {
		t.Fatalf("no rule for %q in the stylesheet", sel)
	}
	rest := css[i+len(sel):]
	end := strings.IndexByte(rest, '}')
	if end < 0 {
		t.Fatalf("rule for %q is not closed", sel)
	}
	return strings.Join(strings.Fields(rest[:end]), " ")
}
