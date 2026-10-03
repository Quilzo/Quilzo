// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package icons

import (
	"regexp"
	"strings"
	"testing"
)

// Every icon in every style is path data and nothing else: whatever names
// an icon, the markup that reaches a page is one this package wrote.
func TestEveryIconIsOnlyPathData(t *testing.T) {
	safe := regexp.MustCompile(`^[0-9MmLlHhVvCcSsQqTtAaZz .,-]+$`)
	if len(paths) < 80 {
		t.Fatalf("the set has %d icons", len(paths))
	}
	for name, styles := range paths {
		for _, s := range Styles {
			p, ok := styles[s]
			if !ok || p == "" || !safe.MatchString(p) {
				t.Errorf("%s in %s is missing or is not path data", name, s)
			}
		}
	}
}

func TestAnIconIsDrawnInTheStyleChosen(t *testing.T) {
	r, f := SVG("bolt", "rounded"), SVG("bolt", "rounded-filled")
	if r == "" || r == f || !strings.Contains(r, `aria-hidden="true"`) {
		t.Errorf("bolt: %q %q", r, f)
	}
	if SVG("bolt", "comic-sans") != r {
		t.Error("an unknown style did not fall back to the default")
	}
	for _, bad := range []string{"", "nonesuch", `bolt"><script>`, "../bolt"} {
		if SVG(bad, "rounded") != "" {
			t.Errorf("%q drew something", bad)
		}
	}
}
