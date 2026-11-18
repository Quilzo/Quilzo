// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import "testing"

// Every value this program ships has to be a value it accepts.
//
// text-base ships as 1.0625rem and the length pattern allowed three decimal
// places, so the default was a value the tool refused: setting it back by hand
// was impossible, and the error said the shipped design was malformed.
//
// This walks the catalogue rather than listing cases, so a default added later
// with a shape nothing accepts fails here instead of in somebody's terminal.
func TestEveryShippedDefaultIsAValueTheToolAccepts(t *testing.T) {
	th, problems := New(map[string]string{}, nil)
	for _, p := range problems {
		t.Fatalf("the shipped theme did not load cleanly: %s", p.Detail)
	}
	for _, tok := range Tokens() {
		for scheme, value := range map[string]string{
			"light": tok.Light, "dark": tok.Dark,
		} {
			if value == "" {
				continue
			}
			if err := th.validate(tok, value); err != nil {
				t.Errorf("the %s default for %s is %q, which this tool refuses:"+
					"\n\t%v", scheme, tok.Name, value, err)
			}
		}
	}
}

// A size nobody can read is refused, as a colour nobody can read is.
//
// `theme set` took body text at 4px, a line height of 0.5, a measure of 5ch
// and 40px borders, and the contrast check, the accessibility gate and the
// publish all passed the page: body text two pixels tall between lines, and
// a paragraph thirteen pixels wide. The help says a token is refused if
// unreadable, and only the glow and the veil had a range. So does every
// token that sizes or spaces text now, and every value this program and its
// styles and starters use is inside it (the test above, and the presets'
// own).
func TestASizeNobodyCanReadIsRefused(t *testing.T) {
	for name, bad := range map[string][]string{
		"text-base":        {"4px", "0.5rem", "50%", "12px", "3rem", "60px", "2ch", "16"},
		"line":             {"0.5", "1", "1.2", "4"},
		"measure":          {"5ch", "10ch", "200ch", "4rem", "100px", "0", "120%"},
		"border":           {"40px", "8px", "1rem", "-1px", "10%", "2ch", "3"},
		"page-width":       {"5rem", "100px", "10%", "20ch", "0"},
		"scale":            {"0.1", "0.9", "3"},
		"density":          {"0.1", "4"},
		"tracking-display": {"-1em", "-0.5em", "2em", "-20px"},
	} {
		for _, v := range bad {
			if _, problems := New(map[string]string{name: v}, nil); !Blocks(problems) {
				t.Errorf("%s %s was accepted", name, v)
			}
		}
	}
	// And what somebody would reasonably choose is still theirs to choose.
	for name, good := range map[string][]string{
		"text-base":        {"14px", "0.875rem", "1rem", "1.125rem", "18px", "1.5rem", "100%", "1.0625em"},
		"line":             {"1.3", "1.5", "1.65", "2"},
		"measure":          {"30ch", "45ch", "68ch", "100ch", "40rem", "720px", "100%"},
		"border":           {"0", "0px", "1px", "2px", "4px", "0.125rem"},
		"page-width":       {"40rem", "64rem", "78rem", "1200px", "100%"},
		"scale":            {"1", "1.2", "1.333", "1.5"},
		"density":          {"0.82", "1", "1.15", "1.5"},
		"tracking-display": {"0", "-0.04em", "0.02em", "-1px"},
	} {
		for _, v := range good {
			if _, problems := New(map[string]string{name: v}, nil); Blocks(problems) {
				t.Errorf("%s %s was refused: %v", name, v, problems)
			}
		}
	}
	for _, style := range Styles {
		if _, problems := New(map[string]string{"style": style}, nil); Blocks(problems) {
			t.Errorf("the %s style sets a size this tool refuses: %v", style, problems)
		}
	}
}
