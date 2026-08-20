package admin

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// `display: flex` on a <td> stops it being a table cell.
//
// The table wraps it in an anonymous cell, the element no longer stretches
// with its row, and a `margin` that a real cell would ignore starts applying.
// The pages table had exactly that, from reusing a class named for a row of
// buttons under a block of content: every actions cell sat a rem out of line
// with the two beside it, so the row borders ran in a visible staircase down
// the table.
//
// Nothing fails when this happens. The page renders, every test passed, and it
// looks like a table with slightly odd borders rather than like a rule being
// misapplied — which is why it survived until somebody looked at a screenshot.
//
// # Why the check is derived from the templates
//
// The first version of this test asked whether a selector *could* reach a
// cell, and counted every bare class as a maybe. That flagged .nav, .brand and
// a dozen other rules that are correct where they are used, and the only way
// to satisfy it would have been to element-scope the whole stylesheet.
//
// So it reads the markup instead: these are the classes actually put on a cell,
// and those are the ones whose display must not change. It grows on its own as
// templates do, and it says nothing about rules that never meet a cell.
func TestNoClassOnATableCellChangesWhatKindOfBoxItIs(t *testing.T) {
	css := readStyle(t)
	classes := classesOnTableCells(t)
	if len(classes) == 0 {
		t.Skip("no template puts a class on a td or th")
	}

	rules := regexp.MustCompile(`(?s)([^{}]+)\{([^{}]*)\}`).
		FindAllStringSubmatch(css, -1)
	if len(rules) < 100 {
		t.Fatalf("parsed %d rules from a stylesheet of %d bytes; the pattern "+
			"is matching almost nothing and this test proves nothing",
			len(rules), len(css))
	}

	// Values that keep an element a table cell. `contents` is not one — it
	// removes the box entirely.
	fine := map[string]bool{"table-cell": true}

	checked := 0
	for _, rule := range rules {
		selector := strings.TrimSpace(rule[1])
		class, ok := bareClassTarget(selector)
		if !ok || !classes[class] {
			continue
		}
		checked++
		for _, decl := range strings.Split(rule[2], ";") {
			name, value, ok := strings.Cut(decl, ":")
			if !ok || strings.TrimSpace(name) != "display" {
				continue
			}
			if v := strings.TrimSpace(value); !fine[v] {
				t.Errorf("`%s` sets display: %s, and %q is on a table cell in "+
					"the templates.\n"+
					"  A cell that is not a table-cell leaves table layout: it "+
					"stops stretching with its row and starts honouring "+
					"margins, which draws the row borders out of line. Scope "+
					"the rule to the elements it is for.",
					selector, v, "."+class)
			}
		}
	}
	// Count what was examined. A predicate matching nothing finds no problems
	// and looks exactly like a pass.
	if checked == 0 {
		t.Fatalf("no rule was examined for any of the %d classes found on a "+
			"table cell, so this test checked nothing", len(classes))
	}
	t.Logf("%d rule(s) examined for %d class(es) used on a cell: %s",
		checked, len(classes), sorted(classes))
}

// classesOnTableCells reads the markup for classes put on a td or th.
func classesOnTableCells(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := assets.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	cellRE := regexp.MustCompile(`<t[dh]\b[^>]*\bclass="([^"]*)"`)

	out := map[string]bool{}
	files := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		files++
		b, err := assets.ReadFile("assets/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range cellRE.FindAllStringSubmatch(string(b), -1) {
			for _, c := range strings.Fields(m[1]) {
				// Template expressions inside a class attribute are not class
				// names. Skipped rather than guessed at.
				if strings.Contains(c, "{{") || strings.Contains(c, "}}") {
					continue
				}
				out[c] = true
			}
		}
	}
	if files == 0 {
		t.Fatal("no templates were read, so no class could be found")
	}
	return out
}

// bareClassTarget returns the class a rule targets when — and only when — the
// rule is a single unqualified class.
//
// `.actions { }` is the shape that goes wrong: it lands wherever somebody
// finds the name useful, which is how a rule written for a row of buttons
// ended up on a table cell.
//
// Three shapes are deliberately out of scope, because each is already
// restricted to somewhere its author looked at:
//
//   - `td.actions` names the element it is for.
//   - `.grid2 .hint` needs an ancestor, so it only reaches cells inside one.
//   - `p > input + .hint` needs a sibling that a cell cannot have.
//
// So this does not prove no rule in the stylesheet can ever reach a cell. It
// proves no rule reaches every element carrying a name that a cell also
// carries, which is the failure that actually happened and the one that
// happens silently.
func bareClassTarget(selector string) (string, bool) {
	for _, part := range strings.Split(selector, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "@") {
			continue
		}
		fields := strings.Fields(strings.NewReplacer(
			">", " ", "+", " ", "~", " ").Replace(part))
		// One compound only. A combinator means the rule already needs
		// context, and context is a restriction its author chose.
		if len(fields) != 1 {
			continue
		}
		last := fields[0]
		if !strings.HasPrefix(last, ".") {
			continue
		}
		// Just the class name: stop at a pseudo-class or a second class, so
		// `.actions:hover` and `.actions.wide` both report `actions`.
		name := strings.TrimPrefix(last, ".")
		if i := strings.IndexAny(name, ".:[ "); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			return name, true
		}
	}
	return "", false
}

// A row-header cell is a <th> inside <tbody>, so a rule about body rows that
// names only td applies to three quarters of a row.
//
// `tbody tr:last-child td { border-bottom: 0 }` did exactly that: the last
// row's <th> kept its border, leaving a short line ending in the middle of the
// table. It reads as a rendering fault rather than as a rule naming one
// element too few, which is why nobody looked for a rule.
func TestARuleAboutBodyRowsNamesBothKindsOfCell(t *testing.T) {
	css := readStyle(t)
	rules := regexp.MustCompile(`(?s)([^{}]+)\{[^{}]*\}`).
		FindAllStringSubmatch(css, -1)

	checked := 0
	for _, rule := range rules {
		selector := strings.TrimSpace(rule[1])
		if !strings.Contains(selector, "tbody") {
			continue
		}
		checked++
		// Word-boundary matching, so "td" in a class name is not a cell.
		hasTD := regexp.MustCompile(`\btd\b`).MatchString(selector)
		hasTH := regexp.MustCompile(`\bth\b`).MatchString(selector)
		if hasTD != hasTH {
			missing := "th"
			if hasTH {
				missing = "td"
			}
			t.Errorf("`%s` names one kind of cell and not the other.\n"+
				"  A tbody row can hold both — a row header is a <th> inside "+
				"<tbody> — so this applies to part of a row and leaves the "+
				"rest looking broken. Add %s.", selector, missing)
		}
	}
	if checked == 0 {
		t.Fatal("no tbody rule was examined, so this test checked nothing")
	}
	t.Logf("%d tbody rule(s) examined", checked)
}

// The class that caused it, named directly. The rule above catches a repeat in
// general; this says what specifically must not come back, so somebody
// reintroducing it reads why rather than a generic complaint.
func TestTheActionsClassDoesNotFlexATableCell(t *testing.T) {
	css := readStyle(t)
	if regexp.MustCompile(`(?m)^\s*\.actions\s*[,{]`).MatchString(css) {
		t.Error("`.actions` is declared unscoped. It is applied to a <td> in " +
			"pages.html, and its flex and margin declarations take that cell " +
			"out of table layout. Scope it to the elements it is for.")
	}
}

func sorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, "."+k)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// readStyle returns the stylesheet with comments already removed, so a
// comment sitting above a rule is never read as part of its selector.
// stripComments lives in classes_test.go, which does the same for its own
// reasons.
func readStyle(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	return stripComments(string(b))
}
