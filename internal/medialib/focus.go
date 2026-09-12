// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package medialib

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/media"
)

// Making a crop keep the part that matters.
//
// # The problem
//
// Renditions are narrower copies of the same picture. The crop happens in the
// browser, where a layout says `object-fit: cover` — the gallery, the
// portraits and both aspect-ratio helpers all do — and the default is dead
// centre. A wide photograph in a square frame keeps its middle and loses its
// edges, so a face standing to one side is the thing that goes.
//
// # Why this is a stylesheet and not a template change
//
// A template would have to know the focus, and it only has a path: layouts
// write `<img src="{{ item.image }}">`, and the media record is not in scope
// where the image is rendered. Getting it there means every layout — including
// every one an operator wrote themselves — changing to look it up.
//
// A rule keyed on the image's own address needs none of that:
//
//	img[src="/media/ab12…"],
//	img[src="/media/7f03…"] { object-position: 30% 20%; }
//
// Every template that already renders the image starts cropping correctly,
// including templates written before this existed and templates nobody here
// has seen. That is the whole argument for doing it this way.
//
// # Why every rendition is named
//
// A rendition is a file in its own right — "decoded and hashed on the way in",
// with its own id — so its address shares nothing with its parent's. A prefix
// selector would match neither, which is the first version of this and would
// have silently done nothing to exactly the narrow copies a crop happens to.
// So the parent and each rendition are listed.
//
// # Why it does not apply to everything
//
// Only files somebody actually placed a point on get a rule. A site with none
// carries no extra bytes, and a site with three carries three rules — rather
// than a declaration on every image, which would also override a layout that
// had deliberately set its own.

// FocusCSS returns the rules for every file with a focus, or "".
//
// Sorted by id so the same library produces the same bytes every time: a
// stylesheet that reorders between builds is one that cannot be cached, diffed
// or checked against a hash.
func FocusCSS(files []media.File, base string) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		base = "/media"
	}

	placed := make([]media.File, 0, len(files))
	for _, f := range files {
		if f.Focus != nil {
			placed = append(placed, f)
		}
	}
	if len(placed) == 0 {
		return ""
	}
	sort.Slice(placed, func(i, j int) bool { return placed[i].ID < placed[j].ID })

	var b strings.Builder
	b.WriteString("\n/* Where each picture is cropped from. " +
		"Written by quilzo media focus; see internal/medialib/focus.go. */\n")
	for _, f := range placed {
		// Every address this picture has: itself, and each narrower copy.
		//
		// The id is a SHA-256 in hex, so it cannot carry a quote, a bracket or
		// anything else that ends a selector, and ValidID is what enforces
		// that. Checked again here anyway, because this writes a stylesheet
		// and the cost of being sure is one comparison per file.
		ids := make([]string, 0, 1+len(f.Renditions))
		if ValidID(f.ID) == nil {
			ids = append(ids, f.ID)
		}
		for _, r := range f.Renditions {
			if ValidID(r.ID) == nil {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) == 0 {
			continue
		}
		sels := make([]string, 0, len(ids))
		for _, id := range ids {
			sels = append(sels, fmt.Sprintf("img[src=%q]", base+"/"+id))
		}
		fmt.Fprintf(&b, "%s { object-position: %s; }\n",
			strings.Join(sels, ",\n"), f.Focus.Position())
	}
	return b.String()
}
