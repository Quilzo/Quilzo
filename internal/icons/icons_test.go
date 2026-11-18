// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package icons

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
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

// Every icon draws inside the box it is served in. Two came from the source
// in its older 24-unit drawing, without a viewBox, and were served in the
// 960-unit box every other icon is drawn in: insights in every style and
// auto_awesome in every style drew a speck in the corner, off the visible
// box, so the third card of every product site's home page showed an empty
// tile where its icon should have been.
func TestEveryIconDrawsInsideItsBox(t *testing.T) {
	// A tenth of the box either side. The source's own drawings reach a
	// little past it in places, handshake in sharp by 44 units, which clips
	// the tip of a corner and is how it is drawn; a drawing in another unit
	// is off by the whole box.
	const slack = 96.0
	for _, name := range Names() {
		for _, style := range Styles {
			minX, minY, maxX, maxY, err := extent(Path(name, style))
			if err != nil {
				t.Errorf("%s in %s: %v", name, style, err)
				continue
			}
			if minX < -slack || maxX > 960+slack || minY < -960-slack || maxY > slack {
				t.Errorf("%s in %s spans x %g to %g and y %g to %g, outside the box 0 -960 960 960",
					name, style, minX, maxX, minY, maxY)
			}
			// And is drawn at the size of the set, not a speck in it.
			if maxX-minX < 240 && maxY-minY < 240 {
				t.Errorf("%s in %s is %g by %g of a 960 box", name, style, maxX-minX, maxY-minY)
			}
		}
	}
}

// extent walks a path's commands and returns the box its points lie in:
// every end point and control point, which contains the curves they draw.
func extent(d string) (minX, minY, maxX, maxY float64, err error) {
	tokens := regexp.MustCompile(`[A-Za-z]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?`).FindAllString(d, -1)
	minX, minY, maxX, maxY = math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	see := func(x, y float64) {
		minX, maxX = math.Min(minX, x), math.Max(maxX, x)
		minY, maxY = math.Min(minY, y), math.Max(maxY, y)
	}
	arity := map[byte]int{'M': 2, 'L': 2, 'T': 2, 'H': 1, 'V': 1, 'C': 6, 'S': 4, 'Q': 4, 'Z': 0}
	var x, y, startX, startY float64
	var cmd byte
	for i := 0; i < len(tokens); {
		if c := tokens[i][0]; c >= 'A' && c <= 'z' && (c <= 'Z' || c >= 'a') {
			cmd = c
			i++
			if cmd == 'Z' || cmd == 'z' {
				x, y = startX, startY
				continue
			}
		}
		upper := cmd &^ 0x20
		n, known := arity[upper]
		if !known || n == 0 {
			return 0, 0, 0, 0, fmt.Errorf("a command this test cannot read: %q", string(cmd))
		}
		if i+n > len(tokens) {
			return 0, 0, 0, 0, fmt.Errorf("%q is short of numbers", string(cmd))
		}
		v := make([]float64, n)
		for k := range v {
			if v[k], err = strconv.ParseFloat(tokens[i+k], 64); err != nil {
				return 0, 0, 0, 0, err
			}
		}
		i += n
		relative := cmd != upper
		switch upper {
		case 'H':
			if relative {
				v[0] += x
			}
			x = v[0]
		case 'V':
			if relative {
				v[0] += y
			}
			y = v[0]
		default:
			for k := 0; k < n; k += 2 {
				px, py := v[k], v[k+1]
				if relative {
					px, py = px+x, py+y
				}
				see(px, py)
				if k == n-2 {
					x, y = px, py
				}
			}
		}
		see(x, y)
		if upper == 'M' {
			startX, startY = x, y
			// Pairs after a move are lines.
			cmd = map[bool]byte{true: 'l', false: 'L'}[relative]
		}
	}
	if math.IsInf(minX, 1) {
		return 0, 0, 0, 0, fmt.Errorf("draws nothing")
	}
	return minX, minY, maxX, maxY, nil
}
