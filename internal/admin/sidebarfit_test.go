// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// The last group in the menu can be reached, and no length here is a number
// somebody wrote down.
//
// # Three bugs, one cause, and then a fourth
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
// place that does not know what the content is. The second says the first fix
// was never going to hold — the constant would have been wrong again the next
// time anything joined the bar, and wrong the same silent way.
//
// The answer to both was a screen-height grid with the content scrolling in
// its own row, which removed every constant and brought the fourth: the window
// became a frame. A long page had a short scrollbar in the middle of the
// screen with the footer parked underneath it, and the browser's own scroll —
// the one the wheel, the space bar, Home, End and find-in-page act on — was
// not the one moving the text.
//
// So the page scrolls, and the menu is the only thing pinned. What this checks
// is the three properties that keep the first bug fixed without the constant
// coming back: the menu is measured against the window, it scrolls inside
// itself, and where it sticks does not depend on how tall the bar is.
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
	// The menu column starts where the window starts. A box that begins below
	// the top of the window and is sized against the whole of it hangs off the
	// bottom by however far down it began — which is this area's original bug,
	// exactly. With the bar spanning both columns the menu began below it and
	// its last 44px sat under the fold until somebody scrolled, and "fine once
	// you scroll" is how that bug was justified the first time.
	//
	// Subtracting the bar's height would also fix it, and is the constant this
	// file exists to keep out.
	if !strings.Contains(body, `grid-template-areas: "nav bar"`) {
		t.Errorf("the menu column no longer starts at the top of the window, "+
			"so it hangs below the fold by the height of whatever is above "+
			"it and the last group is unreachable until the page is "+
			"scrolled:\n  %s", body)
	}

	// The menu, pinned. The column is a stretched grid item so its edge rule
	// runs the height of the page; the list inside it is what sticks, because
	// an element with no room to move inside its own area cannot stick.
	menu := ruleFor(t, wide, "body:has(> .sidenav) > .sidenav > .navgroups {")
	if !strings.Contains(menu, "position: sticky") {
		t.Errorf("the menu is not pinned, so it scrolls away with the "+
			"page:\n  %s", menu)
	}
	// The two that make the last group reachable. Either alone is the old bug:
	// a pinned box with no ceiling runs past the bottom of the window, and a
	// ceiling with nothing scrolling inside it cuts the end off.
	if !strings.Contains(menu, "100dvh") {
		t.Errorf("the menu is not measured against the window, so a long one "+
			"runs past the bottom of it:\n  %s", menu)
	}
	if !strings.Contains(menu, "overflow-y: auto") {
		t.Errorf("the menu does not scroll inside itself, so anything past "+
			"its ceiling is cut off rather than reachable:\n  %s", menu)
	}
	// A column that scrolls is not a column that wraps. .navgroups is
	// flex-wrap: wrap in the base rule, for the arrangement where the groups
	// sit in a row — and giving a *column* flex container a height it cannot
	// exceed makes wrap do what it is for: start a second column. The moment
	// this gained a ceiling, half the menu moved into a second column that
	// 14rem could not hold, and Assurance, Administration and Reference were
	// sliced down the middle at the edge of the sidebar. Nothing overflowed
	// anywhere a scrollbar could appear, so it looked deliberate.
	if !strings.Contains(menu, "flex-wrap: nowrap") {
		t.Errorf("the menu can wrap again, so its ceiling turns it into two "+
			"columns in a 14rem space and the group names are cut off:\n  %s",
			menu)
	}
	// The groups keep their height rather than being squeezed into that
	// ceiling. .navgroups is a flex column and a flex item shrinks to fit by
	// default, so a menu longer than the window compressed instead of
	// scrolling — the same bug reached from the other direction, and one a
	// short menu never shows. Measured: the container's scrollHeight equalled
	// its clientHeight with 1800px of content in it.
	if !strings.Contains(ruleFor(t, wide,
		"body:has(> .sidenav) > .sidenav > .navgroups > * {"), "flex-shrink: 0") {
		t.Error("the menu groups can shrink again, so a menu taller than the " +
			"window compresses instead of scrolling and the last group is " +
			"still not reachable")
	}

	// And where it sticks is not derived from the bar. That subtraction is
	// exactly what put the end of the menu one bar-height under the fold.
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
