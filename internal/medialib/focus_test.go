// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package medialib

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
)

func id(c byte) string { return strings.Repeat(string(c), 64) }

// A file with no focus produces nothing.
//
// A site that has never used this carries no extra bytes, and — more
// importantly — no declaration lands on an image whose layout deliberately set
// its own object-position.
func TestNoFocusMeansNoRule(t *testing.T) {
	css := FocusCSS([]media.File{
		{ID: id('a'), Kind: media.Image},
		{ID: id('b'), Kind: media.Image},
	}, "/media")
	if css != "" {
		t.Errorf("a library with no focus produced:\n%s", css)
	}
}

// Every address the picture has is named, including each narrower copy.
//
// A rendition is a file in its own right with its own id, so its address
// shares nothing with its parent's. The first version of this used a prefix
// selector, which would have matched neither — and would have done nothing to
// exactly the copies a crop happens to.
func TestEveryRenditionIsNamed(t *testing.T) {
	css := FocusCSS([]media.File{{
		ID: id('a'), Kind: media.Image,
		Focus: &media.Focus{X: 30, Y: 20},
		Renditions: []media.Rendition{
			{Width: 480, ID: id('b')},
			{Width: 960, ID: id('c')},
		},
	}}, "/media")

	for _, want := range []string{
		`img[src="/media/` + id('a') + `"]`,
		`img[src="/media/` + id('b') + `"]`,
		`img[src="/media/` + id('c') + `"]`,
	} {
		if !strings.Contains(css, want) {
			t.Errorf("the rule does not name %s:\n%s", want, css)
		}
	}
	if !strings.Contains(css, "object-position: 30% 20%;") {
		t.Errorf("the rule does not carry the point:\n%s", css)
	}
	// One declaration for the set, not three.
	if n := strings.Count(css, "object-position"); n != 1 {
		t.Errorf("the picture got %d declarations; its addresses share one", n)
	}
}

// The same library produces the same bytes every time.
//
// A stylesheet that reorders between builds cannot be cached, diffed, or
// checked against a hash — and this one is served from a store whose entire
// argument is that bytes are addressable.
func TestTheRulesAreInAStableOrder(t *testing.T) {
	files := []media.File{
		{ID: id('c'), Kind: media.Image, Focus: &media.Focus{X: 1, Y: 1}},
		{ID: id('a'), Kind: media.Image, Focus: &media.Focus{X: 2, Y: 2}},
		{ID: id('b'), Kind: media.Image, Focus: &media.Focus{X: 3, Y: 3}},
	}
	first := FocusCSS(files, "/media")
	for i := 0; i < 20; i++ {
		if again := FocusCSS(files, "/media"); again != first {
			t.Fatalf("run %d produced different bytes", i)
		}
	}
	// And in id order, so the file is readable rather than in whatever order
	// the library happened to list.
	a := strings.Index(first, id('a'))
	b := strings.Index(first, id('b'))
	c := strings.Index(first, id('c'))
	if !(a < b && b < c) {
		t.Errorf("the rules are not in id order:\n%s", first)
	}
}

// Nothing that is not a media id reaches the stylesheet.
//
// This writes CSS. An id is a SHA-256 in hex and cannot carry a quote or a
// bracket, and ValidID is what enforces that — but a record can reach the disk
// by a hand edit or an import, so the check is made where the selector is
// built rather than trusted to have happened.
func TestAnIDThatIsNotAnIDIsNotWrittenIntoTheStylesheet(t *testing.T) {
	css := FocusCSS([]media.File{
		{ID: `"] { display: none } img[src="`, Kind: media.Image,
			Focus: &media.Focus{X: 10, Y: 10}},
		{ID: "../../etc/passwd", Kind: media.Image,
			Focus: &media.Focus{X: 10, Y: 10}},
		{ID: id('a'), Kind: media.Image, Focus: &media.Focus{X: 10, Y: 10},
			Renditions: []media.Rendition{{Width: 480, ID: "not-an-id"}}},
	}, "/media")

	if strings.Contains(css, "display: none") || strings.Contains(css, "passwd") {
		t.Errorf("a bad id reached the stylesheet:\n%s", css)
	}
	if strings.Contains(css, "not-an-id") {
		t.Errorf("a bad rendition id reached the stylesheet:\n%s", css)
	}
	// The good one is still there: one bad record does not silence the rest.
	if !strings.Contains(css, id('a')) {
		t.Errorf("the usable file was dropped:\n%s", css)
	}
	// And every selector is a complete, quoted attribute match.
	if strings.Count(css, `img[src="`) != strings.Count(css, `"]`) {
		t.Errorf("a selector is not closed:\n%s", css)
	}
}

// A point outside the picture is brought back inside it.
//
// The value goes into a stylesheet, so the only thing this may produce is two
// integers between 0 and 100. A record written by hand, or by an older build,
// must not be able to put anything else there.
func TestAPointOutsideThePictureIsClamped(t *testing.T) {
	for _, c := range []struct {
		in   media.Focus
		want string
	}{
		{media.Focus{X: 30, Y: 20}, "30% 20%"},
		{media.Focus{X: 0, Y: 0}, "0% 0%"},
		{media.Focus{X: 100, Y: 100}, "100% 100%"},
		{media.Focus{X: -5, Y: 200}, "0% 100%"},
		{media.Focus{X: 1 << 30, Y: -1 << 30}, "100% 0%"},
	} {
		if got := c.in.Position(); got != c.want {
			t.Errorf("%+v rendered as %q, want %q", c.in, got, c.want)
		}
	}
	// Nil is the centre, which is what every file that nobody has touched
	// means and what the browser already does.
	var none *media.Focus
	if got := none.Position(); got != "50% 50%" {
		t.Errorf("no focus rendered as %q, want the centre", got)
	}
}

// The base path is where the site actually serves media from.
func TestTheRuleUsesTheAddressTheSiteServes(t *testing.T) {
	f := []media.File{{ID: id('a'), Kind: media.Image,
		Focus: &media.Focus{X: 50, Y: 10}}}

	if css := FocusCSS(f, "/assets/media/"); !strings.Contains(css,
		`img[src="/assets/media/`+id('a')+`"]`) {
		t.Errorf("a trailing slash was not handled:\n%s", css)
	}
	if css := FocusCSS(f, ""); !strings.Contains(css,
		`img[src="/media/`+id('a')+`"]`) {
		t.Errorf("an empty base did not fall back to /media:\n%s", css)
	}
}
