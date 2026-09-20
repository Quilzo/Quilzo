// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"strings"
	"testing"
)

// The dimension Narrow used to skip.
//
// Capability and autonomy were intersected while the ref, the types, the
// locales and the path were taken from the narrowed side wholesale — so a
// child scoped to the draft, or to types its parent may not read, was
// narrower in every respect the code checked and wider in the one it did not.
func TestNarrowBoundsTheRetrievalScope(t *testing.T) {
	parent := Manifest{
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     AutonomyDraft,
		Retrieval: Retrieval{
			Ref:     "live",
			Types:   []string{"article", "policy"},
			Locales: []string{"en", "fr"},
			Path:    "/help",
		},
	}
	child := Manifest{
		Capabilities: []string{"read_page"},
		Autonomy:     AutonomyPropose,
		Retrieval: Retrieval{
			Ref:     "draft",
			Types:   []string{"article", "product"},
			Locales: []string{"en", "de"},
			Path:    "/help/billing",
		},
	}

	got := parent.Narrow(child)

	if got.Retrieval.Ref != "live" {
		t.Errorf("the child kept the draft: ref is %q", got.Retrieval.Ref)
	}
	if strings.Join(got.Retrieval.Types, ",") != "article" {
		t.Errorf("types are %v", got.Retrieval.Types)
	}
	if strings.Join(got.Retrieval.Locales, ",") != "en" {
		t.Errorf("locales are %v", got.Retrieval.Locales)
	}
	if got.Retrieval.Path != "/help/billing" {
		t.Errorf("path is %q; the deeper subtree is the narrower one",
			got.Retrieval.Path)
	}
}

// Live is narrower than draft, in both directions, because everything at live
// has been published and an agent reading it cannot disclose something nobody
// released.
func TestLiveIsNarrowerThanDraft(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"live", "draft", "live"},
		{"draft", "live", "live"},
		{"live", "live", "live"},
		{"draft", "draft", "draft"},
		{"", "draft", "draft"},
		{"live", "", "live"},
		{"", "", ""},
	} {
		if got := narrowerRef(tc.a, tc.b); got != tc.want {
			t.Errorf("narrowerRef(%q, %q) = %q, wanted %q",
				tc.a, tc.b, got, tc.want)
		}
	}
}

// Empty means all on both sides, which is what makes this not a set
// intersection: a bound that restricts nothing must not narrow a list to
// nothing, and a list that restricts nothing must take the bound whole.
func TestEmptyMeansAllInBothDirections(t *testing.T) {
	if got := intersect(nil, []string{"a", "b"}); strings.Join(got, ",") != "a,b" {
		t.Errorf("an unrestricted bound narrowed the list to %v", got)
	}
	if got := intersect([]string{"a", "b"}, nil); strings.Join(got, ",") != "a,b" {
		t.Errorf("an unrestricted list ignored the bound: %v", got)
	}
	if got := intersect(nil, nil); got != nil {
		t.Errorf("two unrestricted sides produced %v", got)
	}
}

// Two restrictions that do not overlap permit nothing, and must say so with a
// non-nil empty list: nil means "all" everywhere else in this struct, so
// returning it here would widen the very thing being narrowed.
func TestDisjointListsPermitNothingAndSayItNonNil(t *testing.T) {
	got := intersect([]string{"a"}, []string{"b"})
	if got == nil {
		t.Fatal("disjoint lists produced nil, which reads as unrestricted")
	}
	if len(got) != 0 {
		t.Errorf("disjoint lists produced %v", got)
	}
}

// A path restriction is narrowed to the deeper subtree when one contains the
// other, and to nothing when they diverge.
func TestPathsNarrowToTheDeeperSubtree(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"/help", "/help/billing", "/help/billing"},
		{"/help/billing", "/help", "/help/billing"},
		{"", "/help", "/help"},
		{"/help", "", "/help"},
		{"/help", "/legal", pathNothing},
	} {
		if got := longerPath(tc.a, tc.b); got != tc.want {
			t.Errorf("longerPath(%q, %q) = %q, wanted %q",
				tc.a, tc.b, got, tc.want)
		}
	}
}

// A child naming a host its parent does not hold must not reach it. Otherwise
// delegation is a way to reach the network through a supervisor that cannot.
func TestNarrowBoundsTheToolHosts(t *testing.T) {
	parent := Manifest{Tools: []Tool{{Host: "api.example.com"}}}
	child := Manifest{Tools: []Tool{
		{Host: "api.example.com"}, {Host: "evil.example.net"}}}

	got := parent.Narrow(child)

	if len(got.Tools) != 1 || got.Tools[0].Host != "api.example.com" {
		t.Errorf("tools are %+v", got.Tools)
	}
}

// A parent with no tools at all grants none.
func TestAParentWithNoToolsGrantsNone(t *testing.T) {
	got := Manifest{}.Narrow(Manifest{Tools: []Tool{{Host: "api.example.com"}}})
	if len(got.Tools) != 0 {
		t.Errorf("tools are %+v", got.Tools)
	}
}
