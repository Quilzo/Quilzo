package admin

// The mark.
//
// # What it is
//
// An asymmetric squircle — rounded on three corners and square on the fourth —
// with a quill nib knocked out of it as negative space, pointing into the
// square corner.
//
// The container is Material 3 Expressive's own shape move: the design system's
// shape scale deliberately breaks corner symmetry, and almost nothing uses that
// as a logo silhouette, which is most of why this does not look like anything
// else. The nib is the product's name. The tip points at the one sharp corner
// because that is where a nib would be putting the ink, so the shape explains
// its own asymmetry rather than being asymmetric decoratively.
//
// # Why one path and not two
//
// The nib is a hole, not a white shape. Drawn with fill-rule="evenodd" in a
// single path, the ground shows through it — so the mark works on the light
// theme, the dark theme and whatever accent an operator has configured,
// without a second colour or a second copy for dark mode. The vent hole inside
// the nib is a third subpath, and the same rule turns it solid again, which is
// where the dot comes from.
//
// # Why it is in Go rather than in the template
//
// Four surfaces draw it: the header on every screen, the sign-in page, the
// favicon and the installed application's icon. Four copies of a path string
// is four things to keep in step, and the one that falls behind is always the
// one nobody looks at. The template and the icon route both read this.
//
// Coordinates are absolute in a 24×24 box, baked from the construction
// transform rather than left as a nested <g transform>, so a consumer that
// only reads the `d` attribute — an icon pipeline, an SVG favicon — gets the
// same shape as the browser does.
const MarkPath = "M2.5 8.5A6 6 0 0 1 8.5 2.5H15.5A6 6 0 0 1 21.5 8.5V15.5" +
	"A6 6 0 0 1 15.5 21.5H2.5Z " +
	"M18.93 12.61 L14.63 16.91 A2.73 2.73 135 0 1 10.77 16.91 " +
	"L8.05 8.58 A0.46 0.46 135 0 1 8.58 8.05 Z " +
	"M14.06 14.15 A1.18 1.18 135 1 0 12.39 12.48 " +
	"A1.18 1.18 135 1 0 14.06 14.15 Z"

// MarkSVG is the mark as a standalone document, for the favicon and the
// installed icon.
//
// currentColor is deliberately NOT used here. A file fetched as an icon has no
// inherited colour to take, so it needs a literal one — and the brand's, when
// the operator set a valid one, so an installed window and a browser tab carry
// the same accent as the interface they belong to.
func MarkSVG(colour string) string {
	if colour == "" {
		colour = "#00515f"
	}
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` +
		`<path fill-rule="evenodd" fill="` + colour + `" d="` + MarkPath +
		`"/></svg>`
}
