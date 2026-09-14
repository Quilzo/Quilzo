// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// The stylesheet parses, which is not the same as compiling.
//
// Nothing compiles CSS. An unterminated comment is not an error anywhere — the
// browser reads to the next */ and throws away whatever was in between, so a
// missing /* silently deletes every rule after it and the page renders with
// half a stylesheet and no message in any log.
//
// It happened while writing the rules below. A comment gained a paragraph, the
// paragraph's opening /* was lost in the edit, and every rule after that point
// stopped applying: the fix that had just been measured as working measured as
// not working, and the stylesheet still served, still looked mostly right, and
// said nothing. The only reason it was caught is that something downstream was
// being measured in a browser at the time.
//
// Braces for the same reason, one level up: an unclosed rule swallows the ones
// after it.
func TestTheStylesheetIsNotSilentlyTruncated(t *testing.T) {
	for _, name := range []string{"assets/style.css", "assets/preview.css"} {
		b, err := assets.ReadFile(name)
		if err != nil {
			continue // not every build ships both
		}
		css := string(b)

		if opens, closes := strings.Count(css, "/*"), strings.Count(css, "*/"); opens != closes {
			t.Errorf("%s has %d /* and %d */. An unbalanced comment deletes "+
				"every rule between the stray marker and the next one, with "+
				"no error anywhere", name, opens, closes)
		}
		// Text outside a comment that is not a rule. The specific failure was
		// prose sitting between a */ and the next selector, which the parser
		// then tries to read as a selector and discards along with the rule
		// that follows it.
		if i := strings.Index(stripComments(css), "*/"); i >= 0 {
			t.Errorf("%s has a */ outside a comment, near %q. The prose before "+
				"it is being parsed as a selector", name,
				excerptAround(stripComments(css), i))
		}
		if opens, closes := strings.Count(css, "{"), strings.Count(css, "}"); opens != closes {
			t.Errorf("%s has %d { and %d }. An unclosed rule swallows the ones "+
				"after it", name, opens, closes)
		}
	}
}

func excerptAround(s string, i int) string {
	start := i - 60
	if start < 0 {
		start = 0
	}
	return strings.TrimSpace(s[start:i])
}

// A wide table scrolls inside its wrapper and not with the page.
//
// overflow-x: auto is not enough, and that took a browser to find: the wrapper
// clips — clientWidth 443 against the table's 685 — and the document still
// scrolled 148px sideways on a phone, into blank space. contain: paint is what
// stops it, and neither overflow-x: clip on main nor on body did.
func TestAWideTableDoesNotTakeThePageWithIt(t *testing.T) {
	css := readStylesheet(t)
	rule := ruleBody(t, css, ".table-wrap")
	for _, want := range []string{"overflow-x: auto", "contain: paint"} {
		if !strings.Contains(rule, want) {
			t.Errorf(".table-wrap has lost %q. Without it the page itself "+
				"scrolls sideways by the width the table overflows by, into "+
				"blank space, on every screen with a wide table: %s", want, rule)
		}
	}
}

// A fieldset can be narrower than its content wants to be.
//
// Every browser gives a fieldset min-inline-size: min-content in its own
// stylesheet, and that beats max-width and beats anything inside it. The
// listings form's .grid2 is repeat(auto-fit, minmax(18rem, 1fr)) and collapses
// to one column everywhere else; inside a fieldset it stayed three columns —
// 864px of form on a 420px phone, and 481px of sideways scroll.
func TestAFieldsetCanShrink(t *testing.T) {
	rule := ruleBody(t, readStylesheet(t), "fieldset")
	if !strings.Contains(rule, "min-inline-size: 0") {
		t.Errorf("fieldset has lost min-inline-size: 0, so the browser's own "+
			"min-content floor applies again and any grid inside one stops "+
			"collapsing on a narrow screen: %s", rule)
	}
}

// ruleBody is the declarations of the top-level rule whose selector list
// names sel exactly.
//
// Exactly, and not "contains": the stylesheet has .focusgrid and .table-wrap
// and fieldset legend, and a search for a substring finds whichever of those
// happens to be last in the file, then reports that the rule it never looked
// at has lost a property it never had.
func ruleBody(t *testing.T, css, sel string) string {
	t.Helper()
	for _, chunk := range strings.Split(stripComments(css), "}") {
		head, body, ok := strings.Cut(chunk, "{")
		if !ok {
			continue
		}
		for _, s := range strings.Split(head, ",") {
			if strings.TrimSpace(s) == sel {
				return strings.Join(strings.Fields(body), " ")
			}
		}
	}
	t.Fatalf("no rule whose selector is exactly %q", sel)
	return ""
}

func readStylesheet(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
