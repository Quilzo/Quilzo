// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package icons is the set of icons a site's pages may show: Material
// Symbols, by Google, under the Apache License 2.0, in the six styles a
// theme can choose between.
//
// A closed set, kept in the program (icons_gen.go, made by
// scripts/genicons) and never fetched: a name in content is one of these or
// it draws nothing. Each icon is only path data — numbers and drawing
// commands, checked when generated and again by a test — so whatever names
// one, what reaches the page is an SVG this package wrote.
package icons

import "sort"

// Styles are the looks a theme may choose for every icon on the site.
var Styles = []string{"rounded", "outlined", "sharp", "rounded-filled", "outlined-filled", "sharp-filled"}

// DefaultStyle is the style when a theme names none.
const DefaultStyle = "rounded"

// Valid reports whether a style is one of Styles.
func Valid(style string) bool {
	for _, s := range Styles {
		if s == style {
			return true
		}
	}
	return false
}

// Has reports whether name is an icon in the set.
func Has(name string) bool { _, ok := paths[name]; return ok }

// Names lists the icons, sorted.
func Names() []string {
	out := make([]string, 0, len(paths))
	for k := range paths {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SVG is the icon as inline SVG in a style, or "" when the name is not in
// the set. Decorative: the words beside an icon say what it means, so it is
// hidden from assistive technology rather than read out as a second label.
func SVG(name, style string) string {
	p, ok := paths[name]
	if !ok {
		return ""
	}
	if !Valid(style) {
		style = DefaultStyle
	}
	return `<svg class="icon" viewBox="0 -960 960 960" width="24" height="24" aria-hidden="true" focusable="false"><path d="` +
		p[style] + `"/></svg>`
}

// Path is the icon's path data in a style, or "" when the name is not in
// the set: for a script that draws the icon itself.
func Path(name, style string) string {
	p, ok := paths[name]
	if !ok {
		return ""
	}
	if !Valid(style) {
		style = DefaultStyle
	}
	return p[style]
}
