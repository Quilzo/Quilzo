// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

// The mark.
//
// # What it is
//
// A Q drawn as a loop with something at its centre: a ring, a dot inside
// it, and a short tail leaving at the lower right.
//
// The ring is a run going round — decide, act, look, decide again. The dot
// is what the loop goes round: the person an agent stops for, and the
// declaration it cannot leave. The tail is what makes the ring a letter,
// and it is drawn just clear of the ring so that it reads at sixteen
// pixels as a Q and not as a magnifying glass with a thick handle.
//
// The mark it replaced was a quill nib, from when this was a content
// management system and nothing else.
//
// # Why one path and not several
//
// The hole in the ring is a hole, not a white shape. Drawn with
// fill-rule="evenodd" in a single path, the ground shows through it — so
// the mark works on the light theme, the dark theme and whatever accent an
// operator has configured, without a second colour or a second copy for
// dark mode. The dot is a third subpath inside the hole, and the same rule
// turns it solid again. The tail does not touch the ring for the same
// reason: where two subpaths overlap, that rule would cut a notch.
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
const MarkPath = "M12 2.5A9.5 9.5 0 1 0 12 21.5A9.5 9.5 0 1 0 12 2.5Z " +
	"M12 6.7A5.3 5.3 0 1 0 12 17.3A5.3 5.3 0 1 0 12 6.7Z " +
	"M12 9.9A2.1 2.1 0 1 0 12 14.1A2.1 2.1 0 1 0 12 9.9Z " +
	"M20.23 17.97L22.13 19.87A1.6 1.6 0 0 1 19.87 22.13L17.97 20.23Z"

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
		`<path fill-rule="evenodd" fill="` + colour + `" d="` + MarkPath +
		`"/></svg>`
}
