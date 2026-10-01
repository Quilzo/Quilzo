// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

// The mark.
//
// # What it is
//
// A Q in two parts: the loop in blue, and the tail in violet, drawn as a
// separate stroke that crosses the loop's open gap. The loop is an agent
// going round — decide, act, look, decide again — and the tail is the
// pause before the act: the point where a person, or a declaration, stands
// between the loop and what it would do. The two colours are what make the
// two parts read as two.
//
// It replaced a quill nib, from when this was a content management system
// and nothing else, and then two Qs drawn as a single ring, the first too
// close to a well-known company's registered mark.
//
// # Why separate paths, and why nonzero
//
// The loop with its two rounded ends is one path and the tail another, so
// each can be its own colour. The tail is drawn after the loop and over it
// where they cross; within each path every shape runs the same direction
// and fills with the nonzero rule, so nothing is cut out where shapes meet.
//
// # Why it is in Go rather than in the template
//
// Four surfaces draw it: the header on every screen, the sign-in page, the
// favicon and the installed application's icon. Four copies of a path string
// is four things to keep in step, and the one that falls behind is always the
// one nobody looks at. The template and the icon route both read this.
//
// Coordinates are absolute in a 24×24 box, so a consumer that only reads
// the `d` attribute — an icon pipeline, an SVG favicon — gets the same
// shape as the browser does.
const MarkPath = MarkLoop + " " + MarkTail

// MarkLoop is the open ring, and MarkTail the stroke that crosses its gap.
const (
	MarkLoop = "M16.34 17.89A9.00 9.00 0 1 1 19.14 7.43A1.70 1.70 0 0 1 15.99 8.70A5.60 5.60 0 1 0 14.25 15.21A1.70 1.70 0 0 1 16.34 17.89Z"
	MarkTail = "M14.80 12.40L22.40 20.00A1.70 1.70 0 0 1 20.00 22.40L12.40 14.80A1.70 1.70 0 0 1 14.80 12.40Z"
)

// The mark's colours, for the files that cannot take them from a
// stylesheet: the favicon and the installed application's icon. The
// stylesheet has the same pair, with lighter tones for the dark theme.
const (
	MarkLoopColour = "#0b57d0"
	MarkTailColour = "#7b4dff"
)

// MarkSVG is the mark as a standalone document, for the favicon and the
// installed icon.
//
// currentColor is deliberately NOT used here. A file fetched as an icon has no
// inherited colour to take, so it needs a literal one — and the brand's, when
// the operator set a valid one, so an installed window and a browser tab carry
// the same accent as the interface they belong to.
func MarkSVG(colour string) string {
	if colour == "" {
		colour = MarkLoopColour
	}
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` +
		`<path fill="` + colour + `" d="` + MarkLoop + `"/>` +
		`<path fill="` + MarkTailColour + `" d="` + MarkTail + `"/></svg>`
}
