// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package site

import "testing"

func namesOf(nodes []Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	return out
}

func sample() map[string]any {
	set := map[string]any{}
	for _, n := range []string{
		"index", "about", "blog", "blog/first", "blog/second",
		"blog-drafts", "shop/pens/brass", "shop/paper",
	} {
		set[n] = map[string]any{"title": n}
	}
	return set
}

// A parent comes immediately before its children, and a name that merely looks
// like one does not land in the middle of them.
//
// A plain string sort gets this wrong in a way that shows: "/" is 0x2f and "-"
// is 0x2d, so blog-drafts sorts between blog and blog/first and appears to be
// inside the blog. That reads as the tree being wrong rather than as the sort
// being naive, which is worse — somebody trusts it.
func TestTheTreeIsInTheOrderANestedListShows(t *testing.T) {
	got := namesOf(Tree(sample()))
	want := []string{
		"about",
		"blog", "blog/first", "blog/second",
		"blog-drafts",
		"index",
		"shop", "shop/paper", "shop/pens", "shop/pens/brass",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d nodes, want %d:\n  %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d got %q, want %q:\n  %v", i, got[i], want[i], got)
		}
	}
}

// A branch nobody wrote a page at is still a branch.
//
// `shop/pens/brass` with no `shop` and no `shop/pens` is a site where a reader
// can see both in the address bar, and an editor looking for the pens should
// find them under something. Exists says which kind of node it is, so a screen
// can offer to write the missing one rather than pretending it is there.
func TestABranchWithNoPageIsStillInTheTree(t *testing.T) {
	byName := map[string]Node{}
	for _, n := range Tree(sample()) {
		byName[n.Name] = n
	}

	shop, there := byName["shop"]
	if !there {
		t.Fatal("shop/paper and shop/pens/brass exist and there is no shop " +
			"branch, so neither is reachable from a list")
	}
	if shop.Exists {
		t.Error("shop says a page is written at it, and none is")
	}
	// Two pages — shop/paper and shop/pens/brass. shop/pens is a branch
	// nobody wrote, and counting it would make the number mean "nodes"
	// rather than "pages", which is not what a screen saying "and 2 below"
	// is offering to show you.
	if shop.Children != 2 {
		t.Errorf("shop says %d pages are under it, want 2", shop.Children)
	}
	if blog := byName["blog"]; !blog.Exists {
		t.Error("a page is written at blog and the tree says otherwise")
	}
}

// Depth is what a screen indents by.
func TestDepthCountsTheSlashes(t *testing.T) {
	for _, n := range Tree(sample()) {
		want := 0
		for _, c := range n.Name {
			if c == '/' {
				want++
			}
		}
		if n.Depth != want {
			t.Errorf("%s is at depth %d, want %d", n.Name, n.Depth, want)
		}
	}
}

// Under is at or below, because moving a branch moves the page written at it
// too — and a caller that had to remember to add it separately is a caller
// that will forget once.
func TestUnderIncludesThePageAtTheBranch(t *testing.T) {
	got := Under(sample(), "blog")
	want := []string{"blog", "blog/first", "blog/second"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// And a name that only looks like a prefix is not under it.
	for _, n := range got {
		if n == "blog-drafts" {
			t.Error("blog-drafts is under blog, which is the bug " +
				"auth.covers avoids by comparing segments")
		}
	}
}
