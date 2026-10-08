// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// No word is broken in two to make a table column narrower.
//
// overflow-wrap: anywhere counts every character as a place a line may end
// when a table works out how narrow a column may go. Code had it, so a
// column of short identifiers shrank to a character or two and "catalogue"
// came out as "catalogu" over "e": 930 words on 20 screens, in Chromium at
// 390, 768 and 1,280 wide. In prose it is right (a word breaks only when it
// is wider than the whole line, and cards still shrink to a phone), so it
// is allowed there and nowhere in a table. word-break: break-all breaks
// every word, always, and is allowed nowhere.
func TestNoWordIsBrokenToNarrowAColumn(t *testing.T) {
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := stripComments(string(b))
	anywhere := regexp.MustCompile(`(overflow-wrap|line-break)\s*:\s*anywhere|word-break\s*:\s*break-all`)
	inTable := regexp.MustCompile(`(^|[\s>+~(,])(td|th|table|tr)\b|\.owner-of|\.run-steps`)
	checked := 0
	for _, m := range cssRule.FindAllStringSubmatch(css, -1) {
		sel := strings.Join(strings.Fields(m[1]), " ")
		bad := anywhere.FindString(m[2])
		if bad == "" {
			continue
		}
		checked++
		if strings.Contains(bad, "break-all") || inTable.MatchString(sel) {
			t.Errorf("%s has %q, which breaks short words to make a column narrower; "+
				"keep identifiers whole and use overflow-wrap: break-word for text", sel, bad)
		}
	}
	if checked == 0 {
		t.Fatal("no rule breaks long words at all, so this proves nothing")
	}
}

var cssRule = regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)

// A status, a tag and a button's label each read as one thing.
func TestAStatusIsOneLine(t *testing.T) {
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	nowrap := map[string]bool{}
	for _, m := range cssRule.FindAllStringSubmatch(stripComments(string(b)), -1) {
		if !regexp.MustCompile(`white-space:\s*nowrap`).MatchString(m[2]) {
			continue
		}
		for _, sel := range strings.Split(m[1], ",") {
			nowrap[strings.Join(strings.Fields(sel), " ")] = true
		}
	}
	for _, sel := range []string{".tag", ".pill", ".chip", ".chip-small", ".chips a", ".wf-band",
		".wf-word", ".wf-task", "button", ".btn", "td code", "th code"} {
		if !nowrap[sel] {
			t.Errorf("%s may wrap: a status or a label over two lines reads as two", sel)
		}
	}
}

// An identifier in a table cell is kept whole and, when long, cut short with
// an ellipsis. A command is not an identifier: cut short, its arguments
// would be the part hidden. So a command in a cell says it is one.
func TestACommandInATableCellWraps(t *testing.T) {
	cell := regexp.MustCompile(`(?s)<(td|th)\b[^>]*>(.*?)</(td|th)>`)
	code := regexp.MustCompile(`(?s)<code\b([^>]*)>(.*?)</code>`)
	action := regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	found := 0
	err := fs.WalkDir(assets, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		for _, c := range cell.FindAllStringSubmatch(string(b), -1) {
			for _, k := range code.FindAllStringSubmatch(c[2], -1) {
				literal := strings.TrimSpace(action.ReplaceAllString(k[2], "x"))
				if !strings.Contains(literal, " ") {
					continue
				}
				found++
				if !strings.Contains(k[1], `class="cmd"`) {
					t.Errorf("%s: %s is words in a table cell and would be cut short; give it class=\"cmd\"",
						path, k[0])
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no command in any table cell was found, so this proves nothing")
	}
}
