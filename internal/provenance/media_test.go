// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package provenance

import (
	"strings"
	"testing"
)

func indexWith(t *testing.T, pages map[string]SourceType) *Index {
	t.Helper()
	idx := NewIndex()
	for page, st := range pages {
		if err := idx.Set(page, Record{
			ContentHash: "h-" + page, SourceType: st, Author: "somebody",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return idx
}

// A page saying a person wrote it, carrying a picture a model made, is making
// a claim its own library contradicts.
//
// This is the hole: the publish gate refused a page that declared nothing, and
// nothing looked at the pictures. So a page could publish a meta tag asserting
// human authorship over a document containing generated content. The mark was
// not missing. It was wrong, which this package's own opening argument calls
// the more dangerous of the two.
func TestAHumanMarkOverGeneratedMediaIsAConflict(t *testing.T) {
	idx := indexWith(t, map[string]SourceType{"about": HumanEdits})
	got := Conflicts(idx, []MediaClaim{
		{Page: "about", Asset: "hero.png",
			SourceType: string(TrainedAlgorithmicMedia)},
	})
	if len(got) != 1 {
		t.Fatalf("%d conflict(s), want 1", len(got))
	}
	if got[0].Page != "about" || got[0].Asset != "hero.png" {
		t.Errorf("the conflict names %s / %s", got[0].Page, got[0].Asset)
	}
	// The refusal has to carry the fix. A gate that only says no teaches
	// people to look for the flag that turns it off — and this one has none.
	if !strings.Contains(got[0].Detail(), string(CompositeWithTrainedAlgorithmicMedia)) {
		t.Errorf("the refusal does not name the term that fixes it: %s",
			got[0].Detail())
	}
}

// The term for human content with generated elements is not a conflict. It is
// the answer.
func TestTheCompositeTermSatisfiesIt(t *testing.T) {
	idx := indexWith(t, map[string]SourceType{
		"about": CompositeWithTrainedAlgorithmicMedia,
		"news":  TrainedAlgorithmicMedia,
	})
	claims := []MediaClaim{
		{Page: "about", Asset: "a.png", SourceType: string(TrainedAlgorithmicMedia)},
		{Page: "news", Asset: "b.png", SourceType: string(TrainedAlgorithmicMedia)},
	}
	if got := Conflicts(idx, claims); len(got) != 0 {
		t.Errorf("%d conflict(s) on pages that already disclose: %+v", len(got), got)
	}
}

// Undeclared media is not a conflict.
//
// Almost every library is in that state, because nothing could set the field
// until recently. A gate on it would refuse the first publish of every
// existing site, which is the mistake the page-level gate made once and undid.
func TestUndeclaredMediaIsNotAConflict(t *testing.T) {
	idx := indexWith(t, map[string]SourceType{"about": HumanEdits})
	if got := Conflicts(idx, []MediaClaim{
		{Page: "about", Asset: "photo.jpg", SourceType: ""},
	}); len(got) != 0 {
		t.Errorf("undeclared media was treated as a contradiction: %+v", got)
	}
}

// algorithmicMedia is deliberately on the other side of the line.
//
// Calling a database import AI-generated devalues the mark that matters, which
// is why RequiresDisclosure says no to it — and this must follow that decision
// rather than make a second one.
func TestSoftwareGeneratedMediaIsNotAConflict(t *testing.T) {
	idx := indexWith(t, map[string]SourceType{"about": HumanEdits})
	if got := Conflicts(idx, []MediaClaim{
		{Page: "about", Asset: "chart.png", SourceType: string(AlgorithmicMedia)},
	}); len(got) != 0 {
		t.Errorf("a software-drawn chart was treated as a contradiction: %+v", got)
	}
}

// A page with no record at all is left to the gate that already refuses it.
//
// Reporting it here as well would name the same page in two vocabularies and
// send somebody to fix the wrong thing first.
func TestAPageWithNoRecordIsNotReportedHere(t *testing.T) {
	idx := NewIndex()
	if got := Conflicts(idx, []MediaClaim{
		{Page: "about", Asset: "a.png", SourceType: string(TrainedAlgorithmicMedia)},
	}); len(got) != 0 {
		t.Errorf("an unrecorded page was reported as a contradiction: %+v", got)
	}
}

// The order is the same every time, because it is printed in a refusal and a
// list that reorders between runs reads as the content having changed.
func TestConflictsAreOrdered(t *testing.T) {
	idx := indexWith(t, map[string]SourceType{
		"about": HumanEdits, "news": HumanEdits,
	})
	claims := []MediaClaim{
		{Page: "news", Asset: "z.png", SourceType: string(TrainedAlgorithmicMedia)},
		{Page: "about", Asset: "b.png", SourceType: string(TrainedAlgorithmicMedia)},
		{Page: "about", Asset: "a.png", SourceType: string(TrainedAlgorithmicMedia)},
	}
	first := Conflicts(idx, claims)
	if len(first) != 3 {
		t.Fatalf("%d conflict(s), want 3", len(first))
	}
	want := []string{"about/a.png", "about/b.png", "news/z.png"}
	for i, w := range want {
		if first[i].Page+"/"+first[i].Asset != w {
			t.Fatalf("order is %s at %d, want %s",
				first[i].Page+"/"+first[i].Asset, i, w)
		}
	}
}

// The survey counts what the gate deliberately does not refuse.
func TestTheSurveyCountsEveryState(t *testing.T) {
	s := Survey([]MediaClaim{
		{Page: "a", Asset: "1", SourceType: string(TrainedAlgorithmicMedia)},
		{Page: "a", Asset: "2", SourceType: string(HumanEdits)},
		{Page: "b", Asset: "3", SourceType: ""},
		{Page: "b", Asset: "4", SourceType: ""},
		{Page: "c", Asset: "5", SourceType: string(CompositeWithTrainedAlgorithmicMedia)},
	})
	if s.Declared != 3 || s.Undeclared != 2 || s.Generated != 2 {
		t.Errorf("declared=%d undeclared=%d generated=%d, want 3/2/2",
			s.Declared, s.Undeclared, s.Generated)
	}
	if len(s.Pages) != 2 || s.Pages[0] != "a" || s.Pages[1] != "c" {
		t.Errorf("the pages carrying generated media are %v, want [a c]", s.Pages)
	}
}
