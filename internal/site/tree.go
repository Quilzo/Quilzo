// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package site

import (
	"sort"
	"strings"
)

// The tree that was already there.
//
// # Why this is derived and not stored
//
// Page names have allowed a slash since the store did: `blog/first` is a legal
// name, the public server answers it at /blog/first, and auth.covers already
// reads names as paths — "/blog" covers "/blog/first" and deliberately not
// "/blog-drafts". Three separate systems have been treating the slash as
// structure. Nothing showed it to anybody.
//
// So the alternative — a parent field on each page, or a second file holding
// an arrangement — would be a fourth notion of hierarchy that has to be kept
// in agreement with the other three by hand. internal/menu is exactly that,
// and it is hand-maintained for a reason: a menu's order and labels are an
// editorial decision, not a fact about the content. Where a page *is* is a
// fact about the content, and it is in its name.
//
// Deriving it means a move is a rename, a permission on a branch already works,
// and the URL a reader sees and the place an editor sees are the same thing.
// There is nothing to get out of step because there is only one copy.
//
// # What a node is
//
// Every segment of every name, whether or not a page is written there. A site
// with `blog/first` and no `blog` has a blog branch all the same — readers can
// see it in the address bar, and an editor looking for "the blog posts" should
// find them under something. Exists says which kind of node it is, so a screen
// can offer to write the missing one rather than pretending it is there.

// A Node is one name in the tree.
type Node struct {
	// Name is the whole page name, so it can be used directly.
	Name string
	// Segment is the last part of it, which is what a nested list shows.
	Segment string
	// Depth is how many slashes are above it. Zero is the top.
	Depth int
	// Exists says whether a page is written at this name, as against a branch
	// that only exists because something below it does.
	Exists bool
	// Children is how many pages are under it, at any depth. Pages, not
	// nodes: a branch nobody wrote is not something a screen can offer to
	// show you, and counting it would make "and 4 below" a number that does
	// not match what follows.
	//
	// A count rather than the nodes, because the list is flat and already in
	// order.
	Children int
}

// Tree is every page and every branch above one, in the order a nested list
// shows them: a parent immediately before its children, siblings sorted.
//
// Flat rather than nested, because the template language cannot recurse. Depth
// is what a screen indents by, which is the same thing one level down.
func Tree(pages map[string]any) []Node {
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}

	// Every branch above every page, whether or not anybody wrote it.
	all := map[string]bool{}
	for _, name := range names {
		all[name] = true
		for _, branch := range ancestorsOf(name) {
			if !all[branch] {
				all[branch] = false
			}
		}
	}

	ordered := make([]string, 0, len(all))
	for name := range all {
		ordered = append(ordered, name)
	}
	// Segment by segment, so `blog` sorts before `blog/first` and `blogging`
	// sorts after both — a plain string sort puts `blog/first` before
	// `blogging` and `blog-drafts` in the middle of the blog, which reads as
	// the tree being wrong rather than as the sort being naive.
	sort.Slice(ordered, func(i, j int) bool {
		return lessByPath(ordered[i], ordered[j])
	})

	out := make([]Node, 0, len(ordered))
	for _, name := range ordered {
		out = append(out, Node{
			Name:     name,
			Segment:  name[strings.LastIndexByte(name, '/')+1:],
			Depth:    strings.Count(name, "/"),
			Exists:   all[name],
			Children: countUnder(name, names),
		})
	}
	return out
}

// Under is every page at or below a name.
//
// At *or* below, because moving a branch moves the page written at it too, and
// a caller that had to remember to add it separately is a caller that will
// forget once.
func Under(pages map[string]any, name string) []string {
	var out []string
	for page := range pages {
		if page == name || strings.HasPrefix(page, name+"/") {
			out = append(out, page)
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessByPath(out[i], out[j]) })
	return out
}

// ancestorsOf lists the branches above a name, outermost first.
func ancestorsOf(name string) []string {
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return nil
	}
	out := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// countUnder counts the pages strictly below a name.
func countUnder(name string, names []string) int {
	n := 0
	for _, page := range names {
		if strings.HasPrefix(page, name+"/") {
			n++
		}
	}
	return n
}

// lessByPath orders two names segment by segment.
//
// A plain string comparison gets this wrong in a way that shows: "/" is 0x2f
// and "-" is 0x2d, so `blog-drafts` sorts between `blog` and `blog/first` and
// appears to be inside the blog. Comparing segments puts every child of a
// branch together, which is what a tree is.
func lessByPath(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}
