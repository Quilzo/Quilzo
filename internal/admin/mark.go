// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

// The mark.
//
// # What it is
//
// A Q left open, whose tail is a tick. The ring is a run going round —
// decide, act, look, decide again — and it does not close on itself: the
// tick passes through the gap. That is the product in one shape. An agent
// works in a loop, and what leaves the loop is what somebody agreed to.
//
// The two marks before it were a quill nib, from when this was a content
// management system and nothing else, and a ring with a dot at its centre,
// replaced within a day because a well-known software company's registered
// mark is a Q built the same way.
//
// # Why one path, and why nonzero
//
// Three subpaths: the ring with its two rounded ends, and the tick as two
// strokes meeting at a rounded corner. The tick's short stroke starts
// inside the ring and its long one crosses the ring's gap, so the shapes
// overlap. They are all drawn in the same direction and filled with the
// nonzero rule, under which an overlap is simply filled; the evenodd rule
// the earlier marks used would cut a hole wherever two parts meet.
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
const MarkPath = "M15.04 18.59A8.60 8.60 0 1 1 19.08 8.06A1.60 1.60 0 0 1 16.07 9.15A5.40 5.40 0 1 0 13.54 15.77A1.60 1.60 0 0 1 15.04 18.59Z " +
	"M12.73 12.27L16.03 15.57A1.60 1.60 0 0 1 13.77 17.83L10.47 14.53A1.60 1.60 0 0 1 12.73 12.27Z " +
	"M13.72 15.62L20.22 8.52A1.60 1.60 0 0 1 22.58 10.68L16.08 17.78A1.60 1.60 0 0 1 13.72 15.62Z"

// MarkSVG is the mark as a standalone document, for the favicon and the
// installed icon.
//
// currentColor is deliberately NOT used here. A file fetched as an icon has no
// inherited colour to take, so it needs a literal one — and the brand's, when
// the operator set a valid one, so an installed window and a browser tab carry
// the same accent as the interface they belong to.
func MarkSVG(colour string) string {
	if colour == "" {
		colour = "#0842a0"
	}
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` +
		`<path fill="` + colour + `" d="` + MarkPath +
		`"/></svg>`
}
