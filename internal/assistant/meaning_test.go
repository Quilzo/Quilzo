// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"errors"
	"strings"
	"testing"
)

// meaningOf is a stand-in model: a text's vector says which of three
// subjects it is about, or none.
func meaningOf(s string) []float64 {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "return") || strings.Contains(s, "send back") || strings.Contains(s, "refund"):
		return []float64{1, 0.05, 0, 0}
	case strings.Contains(s, "deliver") || strings.Contains(s, "post") || strings.Contains(s, "ship"):
		return []float64{0.05, 1, 0, 0}
	case strings.Contains(s, "leeds") || strings.Contains(s, "pigment"):
		return []float64{0, 0, 1, 0}
	}
	return []float64{0, 0, 0.1, 1}
}

func meaningIndex(floor float64, fail bool) *Index {
	ps := []Passage{
		{ID: "returns#0", Page: "returns", Title: "Returns", Text: "Unopened bottles come back within 30 days for a full refund."},
		{ID: "delivery#0", Page: "delivery", Title: "Delivery", Text: "Orders leave the workshop within two days by tracked post."},
		{ID: "about#0", Page: "about", Title: "About", Text: "We mix ink by hand in Leeds from pigments we grind ourselves."},
	}
	vecs := make([][]float64, len(ps))
	for i, p := range ps {
		vecs[i] = meaningOf(p.Title + " " + p.Text)
	}
	return NewIndex(ps).WithMeaning(&Meaning{Model: "stand-in", Vectors: vecs, Floor: floor,
		Question: func(q string) ([]float64, error) {
			if fail {
				return nil, errors.New("the route is resting")
			}
			return meaningOf(q), nil
		}})
}

// A question in other words than the page's finds it by meaning; one in
// the page's words still finds it by them; a question about nothing the
// pages are about finds nothing, by meaning or by words.
func TestAPassageIsFoundByWhatItMeans(t *testing.T) {
	idx := meaningIndex(0.8, false)
	if on, n := idx.Meant(); !on || n != 3 {
		t.Fatalf("%v %d", on, n)
	}
	hits := idx.Retrieve("can I send back opened ink", 3)
	if len(hits) == 0 || hits[0].Page != "returns" || hits[0].MeaningRank != 1 || hits[0].Similarity < 0.99 {
		t.Fatalf("%+v", hits)
	}
	if hits := idx.Retrieve("how long does delivery take", 3); len(hits) == 0 || hits[0].Page != "delivery" {
		t.Fatalf("%+v", hits)
	}
	if hits := idx.Retrieve("what is the weather tomorrow", 3); len(hits) != 0 {
		t.Fatalf("answered a question the pages are not about: %+v", hits)
	}
}

// Below its floor, meaning ranks and lets nothing through; when the
// question cannot be embedded, the index ranks by words as it always did.
func TestMeaningAloneNeedsItsFloor(t *testing.T) {
	if hits := meaningIndex(0, false).Retrieve("can I send back opened ink", 3); len(hits) != 0 {
		t.Fatalf("a floor of zero let meaning alone through: %+v", hits)
	}
	if hits := meaningIndex(0.8, true).Retrieve("can I send back opened ink", 3); len(hits) != 0 {
		t.Fatalf("%+v", hits)
	}
	words := NewIndex(meaningIndex(0.8, false).Passages).Retrieve("tracked delivery orders", 3)
	failing := meaningIndex(0.8, true).Retrieve("tracked delivery orders", 3)
	if len(words) == 0 || len(failing) != len(words) || failing[0].ID != words[0].ID {
		t.Fatalf("a failing embedding changed the ranking by words: %+v %+v", words, failing)
	}
}
