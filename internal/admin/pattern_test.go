// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestEveryPatternCompilesInChrome.
//
// Chromium compiles the pattern attribute with the v flag, which refuses a
// bare hyphen at the edge of a character class. [a-z0-9-] is fine in every
// regular expression most of us have written and is a syntax error there —
// and the browser's answer to a syntax error is to log it and skip the
// validation, so the field silently accepts anything. Found by driving the
// Chatbots screen in Chrome, where the console said so and the form did not.
func TestEveryPatternCompilesInChrome(t *testing.T) {
	files, err := filepath.Glob("assets/*.html")
	if err != nil || len(files) == 0 {
		t.Fatal("no templates")
	}
	pattern := regexp.MustCompile(`pattern="([^"]*)"`)
	// A hyphen immediately before the closing bracket, not escaped.
	bare := regexp.MustCompile(`[^\\]-\]`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(b), -1) {
			if bare.MatchString(m[1]) {
				t.Errorf("%s: pattern %q has an unescaped hyphen at the end "+
					"of a class, which Chrome refuses and then ignores; "+
					"write \\-", f, m[1])
			}
		}
	}
}
