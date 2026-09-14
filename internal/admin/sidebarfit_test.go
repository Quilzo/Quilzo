// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The last group in the menu can be reached, and no length here is a number
// somebody wrote down.
//
// # Four bugs, one cause, and then two more from the fixes
//
// First the last group in the menu could not be scrolled to: the sidebar was a
// sticky box one viewport tall starting one bar-height below the top, so it
// ended one bar-height under the fold. The fix was arithmetic — declare the
// bar's height, subtract it — and it worked.
//
// Then a search box went into the bar. The base rule floors every text input
// at 48px for target size, the declared bar was 56px with 13px of padding and
// border, and 48 does not fit in 43. The input hung past the bar and crossed
// the rule under it. Nothing failed; the page rendered, and the only symptom
// was a line through a control.
//
// Both are the same bug: a length that has to agree with content, kept in a
// place that does not know what the content is.
//
// The answer to both was a screen-height grid with the content scrolling in
// its own row, which removed every constant and made the window a frame — a
// long page had a short scrollbar in the middle of the screen with the footer
// parked under it, and the browser's own scroll was not the one moving the
// text. So the page scrolls and the menu is pinned.
//
// And pinning it with a ceiling of its own put a second scrollbar a few pixels
// from the first, doing something different. There is no ceiling now: top and
// bottom together hold a short menu under the bar and let a long one scroll up
// with the page until its end is on screen, so everything in it is reachable
// through the scroll everybody already has.
//
// What this checks is the properties that keep the first bug fixed without any
// of the rest coming back.
func TestTheLastGroupInTheMenuCanBeReached(t *testing.T) {
	css := readStyle(t)

	if strings.Contains(css, "--bar-h") {
		t.Error("the bar's height is declared as a constant again. Whatever " +
			"reads it has to agree with what the bar actually contains, and " +
			"nothing makes that true — it was wrong within one release of " +
			"being introduced, and silently")
	}

	wide := mediaBlock(t, css, "@media (min-width: 60rem)")
	body := ruleFor(t, wide, "body:has(> .sidenav) { display: grid;")
	if strings.Contains(body, "height: 100dvh") {
		t.Errorf("the wide layout is a screen-height grid again, so the "+
			"document does not scroll — the scrollbar is a short one in the "+
			"middle of the screen and the footer sits under it:\n  %s", body)
	}
	if !strings.Contains(body, "grid-template-rows: auto 1fr auto") {
		t.Errorf("the rows are not auto/1fr/auto, so the bar and the footer "+
			"do not take what they need and give the rest to the menu:\n  %s",
			body)
	}

	// The menu, pinned. The column is a stretched grid item so its edge rule
	// runs the height of the page; the list inside it is what sticks, because
	// an element with no room to move inside its own area cannot stick.
	menu := ruleBody(t, css, "body:has(> .sidenav) > .sidenav > .navgroups")
	if !strings.Contains(menu, "position: sticky") {
		t.Errorf("the menu is not pinned, so it scrolls away with the "+
			"page:\n  %s", menu)
	}
	// Both offsets, which is what makes one rule work for a menu of any
	// length. top alone pins a long menu by its head and leaves its end
	// permanently below the fold, which is the bug at the top of this comment;
	// bottom alone pushes a short one to the floor of the window.
	for _, edge := range []string{"top: 1rem", "bottom: 1rem"} {
		if !strings.Contains(menu, edge) {
			t.Errorf("the menu has lost %q. With only one of the two, either "+
				"a long menu's end is unreachable or a short one is pushed "+
				"to the bottom of the window:\n  %s", edge, menu)
		}
	}
	// The wheel over the menu moves the menu. Without a scroll box of its own
	// there is nothing here for the wheel to act on and it falls through to the
	// page, which is not what anybody expects from a sidebar.
	for _, want := range []string{"max-height", "overflow-y: auto"} {
		if !strings.Contains(menu, want) {
			t.Errorf("the menu has lost %q, so the wheel over it scrolls the "+
				"page instead:\n  %s", want, menu)
		}
	}
	// Thin and quiet, not the platform's block. It indicates there is more,
	// which a reader needs; it is not a control anybody should have to aim at.
	if !strings.Contains(menu, "scrollbar-width: thin") {
		t.Errorf("the menu draws the platform's full-width scrollbar a few "+
			"pixels from the page's own:\n  %s", menu)
	}
	// And scroll chaining stays on. It is what moves the menu the last few
	// pixels into place the one time the cap is short of where the box sits:
	// at the top of a page the menu starts below the bar, so a box the height
	// of the window ends that far past the bottom of it. One notch past the
	// end of the menu and the page has scrolled, the menu has stuck, and the
	// two agree. contain would stop exactly that and leave the last strip
	// unreachable — measured: the last item's bottom sat 44px below the fold
	// and nothing could move it.
	if strings.Contains(menu, "overscroll-behavior: contain") {
		t.Errorf("the menu contains its own overscroll, so when it reaches "+
			"its end the page cannot take over — and the strip of it that "+
			"sits below the fold at the top of a page is then unreachable:"+
			"\n  %s", menu)
	}
	// The groups keep their height rather than being squeezed into that cap.
	// A flex item shrinks to fit by default, so a menu longer than the window
	// compressed instead of scrolling — measured, the container's scrollHeight
	// equalled its clientHeight with 1800px of content in it.
	if !strings.Contains(ruleBody(t, css,
		"body:has(> .sidenav) > .sidenav > .navgroups > *"), "flex-shrink: 0") {
		t.Error("the menu groups can shrink again, so a menu taller than the " +
			"window compresses instead of scrolling and the last group is " +
			"still not reachable")
	}
	// A column that scrolls with the page is not a column that wraps.
	// .navgroups is flex-wrap: wrap in the base rule, for the arrangement
	// where the groups sit in a row across the top. Anything that constrains
	// it as a column makes wrap start a second column, and 14rem cannot hold
	// two — the group names were sliced down the middle at the edge of the
	// sidebar, with nothing overflowing anywhere a scrollbar could appear.
	if !strings.Contains(menu, "flex-wrap: nowrap") {
		t.Errorf("the menu can wrap again, so anything that constrains it "+
			"turns it into two columns in a 14rem space and the group names "+
			"are cut off:\n  %s", menu)
	}
	// And neither offset is derived from anything else's height. That
	// subtraction is exactly what put the end of the menu one bar-height
	// under the fold.
	if strings.Contains(menu, "var(--bar") || strings.Contains(menu, "- var(") {
		t.Errorf("the menu's position is worked out from something else's "+
			"height, which is the arithmetic this is here to keep out:\n  %s",
			menu)
	}
}

// A control in the bar fits in the bar.
//
// The base rule floors every text input and every button at 48px, for target
// size, and `min-height` beats `height` — so `.findbar input { height: 32px }`
// did nothing at all and the input rendered at 48. The comment beside it
// asserted 32, which is how a wrong measurement survived review: the code and
// the note agreed with each other and not with the browser.
//
// Anything in the bar that means to be smaller than the house size has to say
// min-height, because that is the property being lowered.
func TestABarControlLowersTheFloorItIsGiven(t *testing.T) {
	css := readStyle(t)

	for _, sel := range []string{".findbar input {", ".findbar button {"} {
		rule := ruleFor(t, css, sel)
		if !strings.Contains(rule, "height:") {
			continue // not sized here, so nothing to lower
		}
		if !strings.Contains(rule, "min-height:") {
			t.Errorf("%s sets a height and not a min-height. The base rule "+
				"floors it at 48px and min-height wins, so the declaration "+
				"does nothing and the control renders at 48:\n  %s", sel, rule)
		}
	}
}

// mediaBlock returns the contents of a media query, brace-matched.
//
// Needed because the same selectors appear at the top level, inside the wide
// layout, and now inside @media print — and "the last one" silently became the
// print override. This test read that copy, reported that the content does not
// scroll, and was right about the rule it had found and wrong about which rule
// it meant.
func mediaBlock(t *testing.T, css, query string) string {
	t.Helper()
	i := strings.Index(css, query)
	if i < 0 {
		t.Fatalf("no %s in the stylesheet", query)
	}
	open := strings.IndexByte(css[i:], '{')
	if open < 0 {
		t.Fatalf("%s is not followed by a block", query)
	}
	depth := 0
	for j := i + open; j < len(css); j++ {
		switch css[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return css[i+open+1 : j]
			}
		}
	}
	t.Fatalf("%s is not closed", query)
	return ""
}

// ruleFor returns the body of the last rule opening with sel.
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

// The content column is capped, and the cap is bounded by the space there is.
//
// `max-width: 68rem` reads as a ceiling and behaved as a floor: on a screen
// with the menu beside it the column is narrower than 68rem, and a page
// holding a wide table came out at the cap — overflowing its own grid area,
// giving the page a sideways scrollbar, and then a vertical one too, because
// 100dvh is taller than what a horizontal scrollbar leaves. Five screens
// scrolled 15px in a direction nothing was meant to scroll.
//
// Every one of them had a table. None of them failed anything: the pages
// rendered, and a sweep of all thirty-one screens in a browser is what found
// it, after the layout they sit in had already been changed and checked on one
// screen.
func TestTheContentColumnIsNeverWiderThanTheSpaceThereIs(t *testing.T) {
	shell := ruleFor(t, readStyle(t), ".shell {")

	if !strings.Contains(shell, "max-width: min(") {
		t.Errorf("the content column's cap is not bounded by what is "+
			"available. A bare length is a floor on any screen narrower than "+
			"it, and the page then scrolls sideways:\n  %s", shell)
	}
	if !strings.Contains(shell, "100%") {
		t.Errorf("the cap does not mention the space there is:\n  %s", shell)
	}
}

// The shell is laid out only on pages that have one.
//
// Three screens have their own body and no navigation: signing in with a
// token, signing in with a passkey, and the API explorer. They are the pages
// somebody reaches before there is a menu to show, or that render themselves.
//
// The wide-layout rules said `body`, so they applied there too — a 14rem
// column held open for a menu that was not there, and a `main` taller than a
// row that could not grow, positioned 84px above the top of the window with
// nothing scrolling. The first paragraph of the sign-in screen was off the
// screen and unreachable. Somebody signing in could not read the start of
// their own sign-in page.
//
// `:has(> .sidenav)` asks the question that was meant. Structural rather than
// a list of page classes, so a fourth standalone screen is right without
// anybody remembering this — which is the property worth asserting, because a
// list is the part that goes stale.
func TestTheShellIsOnlyLaidOutWhereThereIsOne(t *testing.T) {
	wide := mediaBlock(t, readStyle(t), "@media (min-width: 60rem)")

	// Every rule that arranges the shell has to ask first.
	for _, sel := range []string{
		"display: grid; grid-template-columns: 14rem 1fr",
		"> .bar { grid-area: bar",
		"> .sidenav { grid-area: nav",
		"> main { grid-area: main",
		"> footer { grid-area: foot",
	} {
		i := strings.Index(wide, sel)
		if i < 0 {
			t.Errorf("no rule for %q in the wide layout", sel)
			continue
		}
		start := strings.LastIndexByte(wide[:i], '\n') + 1
		line := strings.TrimSpace(wide[start : i+len(sel)])
		if !strings.Contains(line, ":has(> .sidenav)") {
			t.Errorf("this arranges the shell on every page, including the "+
				"ones that have no menu to arrange:\n  %s", line)
		}
	}
}

// The menu's ceiling leaves room for wherever the page has put it.
//
// A box capped at the height of the window but positioned below the bar ends
// below the window by however far down it starts. Measured, that was 44px,
// with the last item in the menu sitting in the strip — the oldest bug in this
// area, arrived at from a third direction.
//
// So the cap is the window less 6rem rather than less 2rem: enough for the
// menu to fit at the top of a page, where it starts under the bar, and when it
// is stuck, where it starts at 1rem. The cost is that the stuck menu is 80px
// shorter than the window rather than 32px; it scrolls inside itself either
// way, so that is a slightly smaller window onto the same menu.
//
// # Why this is checked rather than asserted
//
// 6rem has to be at least as tall as the bar plus the gap above the menu, and
// that is the shape of thing this file exists to distrust: "a length that has
// to agree with content, kept in a place that does not know what the content
// is". The difference is that nothing checked the last one. This reads the
// bar's own padding, the tallest control the bar is allowed to hold, and the
// menu column's padding, adds them up, and fails when 6rem stops covering
// them — so the next control that goes in the bar is a failing test rather
// than a strip of menu nobody can reach.
func TestTheMenuCeilingClearsTheBar(t *testing.T) {
	css := readStyle(t)

	cap := remValue(t, ruleBody(t, css,
		"body:has(> .sidenav) > .sidenav > .navgroups"), `max-height: calc\(100dvh - ([\d.]+)rem\)`)

	// The bar: padding above and below, plus the tallest thing it may hold.
	barPad := remValue(t, ruleBody(t, css, ".bar"), `padding: ([\d.]+)rem`)
	control := pxValue(t, ruleBody(t, css, ".findbar input"), `min-height: (\d+)px`)
	// The menu column's own padding, which is where the menu starts from.
	navPad := remValue(t, ruleBody(t, css, "body:has(> .sidenav) > .sidenav"), `padding: ([\d.]+)rem`)

	const px = 16.0                                 // 1rem, which this stylesheet does not change
	needed := barPad*2*px + control + navPad*px + 1 // +1 for the bar's border

	if cap*px < needed {
		t.Errorf("the menu's ceiling is %.2frem (%.0fpx of the window) and the "+
			"bar plus the gap above the menu now comes to %.0fpx. The menu "+
			"starts that far down the page, so a box the window's height less "+
			"the ceiling ends %.0fpx below the fold — with the last item in "+
			"it. Raise the ceiling, or take something out of the bar.",
			cap, cap*px, needed, needed-cap*px)
	}
}

// remValue pulls a rem length out of a declaration.
func remValue(t *testing.T, rule, pattern string) float64 {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(rule)
	if m == nil {
		t.Fatalf("no %q in:\n  %s", pattern, rule)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// pxValue pulls a pixel length out of a declaration.
func pxValue(t *testing.T, rule, pattern string) float64 {
	t.Helper()
	return remValue(t, rule, pattern)
}
