// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// A negative length is a value, not a flag.
//
// tracking-display is documented as "negative tightens", and every useful value
// for it starts with a minus. Splitting arguments at the first dash sent that
// value to the flag package, which refused it: the one token that wants a
// negative number was the one token that could not be set.
func TestANegativeValueIsNotMistakenForAFlag(t *testing.T) {
	cases := []struct {
		args, pos, flags []string
	}{
		{
			args:  []string{"tracking-display", "-0.02em"},
			pos:   []string{"tracking-display", "-0.02em"},
			flags: nil,
		},
		{
			args:  []string{"tracking-display", "-0.02em", "--dir", "templates"},
			pos:   []string{"tracking-display", "-0.02em"},
			flags: []string{"--dir", "templates"},
		},
		{
			args:  []string{"radius", "10px", "-force"},
			pos:   []string{"radius", "10px"},
			flags: []string{"-force"},
		},
	}
	for _, c := range cases {
		pos, flags := splitThemeArgs(c.args)
		if !reflect.DeepEqual(pos, c.pos) || !reflect.DeepEqual(flags, c.flags) {
			t.Errorf("splitThemeArgs(%q)\n got pos %q flags %q\nwant pos %q flags %q",
				c.args, pos, flags, c.pos, c.flags)
		}
	}
}

// A summary in `quilzo theme tokens` wraps at its width, not one word to a
// line. It is printed at column 38 and wrapped to 44, and the wrap counted
// the indent of every line after the first against those 44, so "links,
// filled buttons, the accent everything" was followed by "else",
// "answers" and "to", each on a line of its own.
func TestATokensSummaryWrapsAtItsWidth(t *testing.T) {
	_, printed := captureStdout(t)
	old := w
	w = out.New(false)
	t.Cleanup(func() { w = old })
	if err := themeTokens(nil); err != nil {
		t.Fatal(err)
	}
	text := printed()
	lines := strings.Split(text, "\n")
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" || !strings.HasPrefix(line, strings.Repeat(" ", 38)) ||
			strings.Contains(line, "light ") {
			continue
		}
		// A continuation of a summary: it holds more than a word, or it is
		// the last of the summary and the line above it was full.
		words := strings.Fields(line)
		above := strings.TrimSpace(lines[i-1][min(38, len(lines[i-1])):])
		if len(words) == 1 && len(above)+1+len(words[0]) <= 44 {
			t.Errorf("%q is on a line of its own under %q", words[0], above)
		}
	}
	if !strings.Contains(text, "links, filled buttons, the accent everything") {
		t.Fatalf("no summary to look at:\n%s", text)
	}

	// The same for every caller: no line of the text is wider than asked,
	// and none but the last could have taken the next word.
	summary := "links, filled buttons, the accent everything else answers to"
	for _, c := range []struct{ width, indent int }{{44, 38}, {62, 12}, {70, 4}, {74, 0}} {
		got := strings.Split(wrapIndent(summary, c.width, c.indent), "\n")
		for j, l := range got {
			l = strings.TrimPrefix(l, strings.Repeat(" ", min(c.indent, len(l))))
			if j > 0 && len(l) > c.width {
				t.Errorf("wrapped to %d at %d, %q is wider", c.width, c.indent, l)
			}
			if j+1 < len(got) {
				next := strings.Fields(got[j+1])[0]
				if len(l)+1+len(next) <= c.width {
					t.Errorf("wrapped to %d at %d, %q could have taken %q", c.width, c.indent, l, next)
				}
			}
		}
	}
}
