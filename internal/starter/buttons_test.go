// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package starter

import (
	"regexp"
	"strings"
	"testing"
)

// A filled button keeps the label colour the theme checked it against.
//
// The theme checks on-primary against primary, which is what a filled button
// is. A rule handing links the surrounding text colour — ".tone-primary a {
// color: inherit }" — outranks ".btn", so on every tinted band the label
// took the band's text colour instead: dark navy on blue, pale on pale. No
// check saw it, because each colour pair was legible; the pairing was not.
func TestTintedSurfacesDoNotRecolourFilledButtons(t *testing.T) {
	css := Components()
	// Comments out, so a rule quoted in one is not read as a rule.
	css = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, "")
	rules := regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(css, -1)
	if len(rules) < 100 {
		t.Fatalf("read %d rules; the parse is wrong", len(rules))
	}
	// The last compound of a selector names an anchor: "a", "a:hover",
	// "a:not(.x)".
	anchor := regexp.MustCompile(`(^|[\s>+~])a(:[^\s>+~]*)?$`)
	checked := 0
	for _, r := range rules {
		if !regexp.MustCompile(`(^|;)\s*color:\s*inherit`).MatchString(r[2]) {
			continue
		}
		for _, sel := range strings.Split(r[1], ",") {
			sel = strings.TrimSpace(sel)
			if !anchor.MatchString(sel) {
				continue
			}
			checked++
			if !strings.Contains(sel, ":not(.btn)") {
				t.Errorf("%q gives every link the surrounding colour, filled "+
					"buttons included; exclude them with :not(.btn)", sel)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no rule recolours links at all; this test is checking nothing")
	}
}
