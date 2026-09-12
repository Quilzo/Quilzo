// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strconv"
)

// Lists that do not render the whole store.
//
// # What was wrong
//
// The pages screen built every page into one response. So did media, and
// records, and the structure screens. At a few hundred it is slow; at ten
// thousand it is a page nobody can use, and the browser is not the place to
// find that out.
//
// internal/api has paged since it existed — parsePaging, an offset and a limit
// with a maximum. The interface had none of it except the audit log, which
// grew its own inline and only goes one way: "Older entries" and no way back
// except the browser's own button.
//
// # Why offset and not a cursor
//
// A cursor is the right answer for a feed that changes underneath the reader,
// and the wrong one for a sorted list of a site's own pages. These lists are
// sorted by name, the reader is the person editing them, and "page 3 of 7"
// with a way to reach page 2 is what somebody actually wants — which a cursor
// cannot offer at all.
//
// # Why the size is fixed
//
// A per-page control is a preference, and a preference is a thing to store,
// show, and get wrong. Fifty rows is more than fits on a screen and far less
// than makes one slow, and anybody who wants everything at once has the
// command line, which is where a list of ten thousand belongs.

// PageSize is how many rows a list shows at once.
const PageSize = 50

// paging is where a reader is in a list, and how to move.
type paging struct {
	Offset int
	Size   int
	Total  int

	// From and To are 1-based and inclusive, for "showing 51 to 100 of 312".
	// Computed here rather than in a template, because off-by-one arithmetic
	// in a template is arithmetic nothing can test.
	From int
	To   int

	HasPrev bool
	HasNext bool
	Prev    int
	Next    int

	// Query is the rest of the request's query string, so a link keeps the
	// filter somebody is inside. Without it, turning the page silently drops
	// what they searched for — which looks like the search being cleared.
	Query string

	// Needed says whether to draw the controls at all. A list that fits on one
	// page should not carry "showing 1 to 7 of 7" and two disabled buttons.
	Needed bool
}

// paginate works out where in a list this request is.
//
// A negative or unparseable offset is the start, and an offset past the end is
// the last page rather than an empty one: a link that somebody kept after
// deleting things should show them the end of the list, not a blank screen
// that reads as everything having gone.
func paginate(r *http.Request, total, size int) paging {
	if size <= 0 {
		size = PageSize
	}
	offset := 0
	if v := r.URL.Query().Get("from"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	if offset >= total && total > 0 {
		// The last page, aligned to the page boundary, so the offsets a reader
		// walks through are the same ones going back as coming forward.
		offset = ((total - 1) / size) * size
	}
	if total == 0 {
		offset = 0
	}

	end := offset + size
	if end > total {
		end = total
	}
	p := paging{
		Offset: offset, Size: size, Total: total,
		HasPrev: offset > 0, HasNext: end < total,
		Prev: offset - size, Next: end,
		Query:  otherQuery(r, "from"),
		Needed: total > size,
	}
	if p.Prev < 0 {
		p.Prev = 0
	}
	if total > 0 {
		p.From, p.To = offset+1, end
	}
	return p
}

// slice cuts a list down to this page.
//
// Bounds-checked here rather than at every call site, because a slice
// expression written out four times is a panic waiting for the fourth one.
func (p paging) slice(n int) (int, int) {
	start := p.Offset
	if start > n {
		start = n
	}
	end := start + p.Size
	if end > n {
		end = n
	}
	return start, end
}

// otherQuery rebuilds the query string without one parameter.
//
// So a page link carries whatever else the reader had set — a filter, a search
// — and changes only where they are in the list.
func otherQuery(r *http.Request, drop string) string {
	q := r.URL.Query()
	q.Del(drop)
	if len(q) == 0 {
		return ""
	}
	return "&" + q.Encode()
}
