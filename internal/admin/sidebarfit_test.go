// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// The menu column is whatever is left, not a number somebody wrote down.
//
// # Two bugs, one cause
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
// place that does not know what the content is. The second one is the one that
// matters, because it says the first fix was never going to hold — the
// constant would have been wrong again the next time anything joined the bar,
// and wrong the same silent way.
//
// So this no longer checks the arithmetic. It checks that there is none.
func TestTheMenuColumnIsWhateverIsLeft(t *testing.T) {
	css := readStyle(t)

	if strings.Contains(css, "--bar-h") {
		t.Error("the bar's height is declared as a constant again. Whatever " +
			"reads it has to agree with what the bar actually contains, and " +
			"nothing makes that true — it was wrong within one release of " +
			"being introduced, and silently")
	}

	wide := mediaBlock(t, css, "@media (min-width: 60rem)")
	body := ruleFor(t, wide, "body { display: grid;")
	// A viewport-height grid, not a minimum. With min-height the middle row
	// grows with its content and the sidebar stops being "the space between
	// the bar and the footer".
	if !strings.Contains(body, "height: 100dvh") || strings.Contains(body, "min-height: 100vh") {
		t.Errorf("the wide layout is not a screen-height grid, so the row the "+
			"menu sits in is not what is left over:\n  %s", body)
	}
	if !strings.Contains(body, "grid-template-rows: auto 1fr auto") {
		t.Errorf("the rows are not auto/1fr/auto, so the bar and the footer do "+
			"not take what they need and give the rest to the menu:\n  %s", body)
	}

	side := ruleFor(t, wide, "body > .sidenav {")
	main := ruleFor(t, wide, "body > main {")
	for what, rule := range map[string]string{"the menu": side, "the content": main} {
		// A grid item's automatic minimum size is its content, so without this
		// a long menu makes its own row taller than 1fr and pushes the footer
		// off the screen instead of scrolling.
		if !strings.Contains(rule, "min-height: 0") {
			t.Errorf("%s can grow its own row instead of scrolling inside "+
				"it:\n  %s", what, rule)
		}
		if !strings.Contains(rule, "overflow-y: auto") {
			t.Errorf("%s does not scroll, so the screen-height grid clips "+
				"it:\n  %s", what, rule)
		}
	}

	// And nothing is pinned over anything. The overhang was only expressible
	// because the sidebar was sticky; as a grid row it cannot be.
	if strings.Contains(side, "position: sticky") {
		t.Errorf("the menu is sticky again, which is what let it hang past "+
			"the bottom of the screen:\n  %s", side)
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
