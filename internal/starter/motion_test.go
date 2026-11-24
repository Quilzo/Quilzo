// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package starter

import (
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/theme"
)

// viewTransition is one @view-transition rule in a stylesheet: what it says,
// and the @media it is inside, empty when it is inside none.
type viewTransition struct {
	media, body string
}

// viewTransitions lists a stylesheet's @view-transition rules in order. The
// last one that applies is the one a browser uses, so the order is the
// answer, not a detail.
func viewTransitions(css string) []viewTransition {
	css = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, "")
	var out []viewTransition
	var stack []string
	prelude := 0
	for i := 0; i < len(css); i++ {
		switch css[i] {
		case '{':
			head := strings.TrimSpace(css[prelude:i])
			if head == "@view-transition" {
				end := strings.IndexByte(css[i:], '}')
				media := ""
				for _, s := range stack {
					if strings.HasPrefix(s, "@media") {
						media = s
					}
				}
				out = append(out, viewTransition{media: media, body: strings.Join(strings.Fields(css[i+1:i+end]), " ")})
				i += end
				prelude = i + 1
				continue
			}
			stack = append(stack, head)
			prelude = i + 1
		case '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			prelude = i + 1
		case ';':
			prelude = i + 1
		}
	}
	return out
}

// navigation is what the last @view-transition rule that applies says, for
// a visitor who has asked for less motion or has not.
func navigation(rules []viewTransition, reduced bool) string {
	got := ""
	for _, r := range rules {
		switch r.media {
		case "":
		case "@media (prefers-reduced-motion: reduce)":
			if !reduced {
				continue
			}
		default:
			continue
		}
		got = r.body
	}
	return got
}

// motion: none set every transition and animation to nothing and left the
// browser cross-fading from one page to the next: a page transition is
// animated by pseudo-elements the universal selector does not reach, and
// nothing said navigation: none. A site set to motion none now moves
// nothing, page transitions included, whether or not the visitor has asked.
//
// The component sheet carried two @view-transition rules and two
// reduced-motion blocks, and the second navigation: auto came after the
// block that said none, so it won for the visitors who had asked for less
// motion as well. There is one of each now, in that order.
func TestNothingMovesWhenMotionIsNone(t *testing.T) {
	still, _ := theme.New(map[string]string{"motion": "none"}, nil)
	for _, reduced := range []bool{false, true} {
		if got := navigation(viewTransitions(Stylesheet(still)), reduced); got != "navigation: none;" {
			t.Errorf("motion none, reduced motion %v: the page transition is %q", reduced, got)
		}
	}
	moving, _ := theme.New(nil, nil)
	rules := viewTransitions(Stylesheet(moving))
	if got := navigation(rules, false); got != "navigation: auto;" {
		t.Errorf("a site that chose its motion has no page transition: %q", got)
	}
	if got := navigation(rules, true); got != "navigation: none;" {
		t.Errorf("a visitor who asked for less motion is given %q", got)
	}

	sheet, _ := assets.ReadFile("assets/components.css")
	if n := len(viewTransitions(string(sheet))); n != 2 {
		t.Errorf("the components carry %d @view-transition rules; one, and one under reduced motion", n)
	}
	if n := strings.Count(string(sheet), "@media (prefers-reduced-motion: reduce)"); n != 1 {
		t.Errorf("the components carry %d reduced-motion blocks, not one", n)
	}
}

// The meter's fill moved by animating width, which lays the page out again
// on every frame. It is scaled now, which the compositor does alone, from
// the start of the line in either direction.
func TestTheMeterMovesWithoutLayingThePageOut(t *testing.T) {
	sheet, _ := assets.ReadFile("assets/components.css")
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(sheet), "")
	rule := regexp.MustCompile(`(?s)\n\.bar > span \{([^}]*)\}`).FindStringSubmatch(css)
	if rule == nil {
		t.Fatal("no rule for the meter's fill")
	}
	body := rule[1]
	if strings.Contains(body, "width") || !strings.Contains(body, "transition: transform") ||
		!strings.Contains(body, "scaleX(") {
		t.Errorf("the meter's fill is not scaled:%s", body)
	}
	if !strings.Contains(css, ".bar > span:dir(rtl) { transform-origin: right; }") {
		t.Error("a right-to-left page's meter fills from the left")
	}
}
