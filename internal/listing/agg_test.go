// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package listing

import (
	"testing"

	"github.com/quilzo/quilzo/internal/collection"
)

func stock(t *testing.T) *collection.Index {
	t.Helper()
	return &collection.Index{Collection: "products", Records: []collection.Record{
		{ID: "a", Updated: 10, Fields: map[string]any{
			"name": "Brass pen", "price": 1200.0, "range": "writing"}},
		{ID: "b", Updated: 30, Fields: map[string]any{
			"name": "Walnut ink", "price": 800.0, "range": "writing"}},
		{ID: "c", Updated: 20, Fields: map[string]any{
			"name": "Archive box", "price": 2400.0, "range": "storage"}},
		{ID: "d", Updated: 5, Fields: map[string]any{
			"name": "Nothing priced", "range": "storage"}},
	}}
}

// An aggregate is over everything that matched, not over the rows on the page.
//
// An aggregate of the page would change when somebody set `rows` to 10, which
// is the shape of wrong nobody reports because it always looks plausible.
func TestAnAggregateIsOverTheMatchedSetAndNotThePage(t *testing.T) {
	l := &Listing{
		Name: "everything", Collection: "products", Rows: 1,
		Agg: []Agg{
			{Op: Count, As: "how_many"},
			{Op: Sum, Field: "price", As: "worth"},
		},
	}
	res, err := Resolve(l, stock(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("the page shows %d rows, and the test needs it to show one",
			len(res.Rows))
	}
	if res.Agg["how_many"] != 4 {
		t.Errorf("count is %v over a page of one; it has to be 4",
			res.Agg["how_many"])
	}
	if res.Agg["worth"] != int64(4400) {
		t.Errorf("sum is %v, want 4400 — the three records that carry a price",
			res.Agg["worth"])
	}
}

// And it is over what the filter selected, not over the collection.
func TestAnAggregateRespectsTheFilter(t *testing.T) {
	l := &Listing{
		Name: "writing", Collection: "products",
		Where: []Condition{{Field: "range", Match: Is, Value: "writing"}},
		Agg: []Agg{
			{Op: Count, As: "how_many"},
			{Op: Max, Field: "price", As: "dearest"},
			{Op: Min, Field: "price", As: "cheapest"},
		},
	}
	res, err := Resolve(l, stock(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Agg["how_many"] != 2 {
		t.Errorf("count is %v, want 2", res.Agg["how_many"])
	}
	if res.Agg["dearest"] != 1200.0 {
		t.Errorf("max is %v, want 1200", res.Agg["dearest"])
	}
	if res.Agg["cheapest"] != 800.0 {
		t.Errorf("min is %v, want 800", res.Agg["cheapest"])
	}
}

// latest is the value on the most recently updated record, which is how a page
// says "the current price" rather than "a price".
func TestLatestReadsTheMostRecentlyUpdatedRecord(t *testing.T) {
	l := &Listing{Name: "recent", Collection: "products",
		Agg: []Agg{{Op: Latest, Field: "name", As: "newest"}}}
	res, err := Resolve(l, stock(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Agg["newest"] != "Walnut ink" {
		t.Errorf("latest is %v, want the record updated at 30",
			res.Agg["newest"])
	}
}

// Nothing to say is nothing, not zero.
//
// "The sum is 0" and "there is nothing to add up" are different sentences, and
// a template printing the first when it means the second is telling somebody
// the stock is worthless rather than that there is none.
func TestNothingToAggregateIsNotZero(t *testing.T) {
	l := &Listing{
		Name: "none", Collection: "products",
		Where: []Condition{{Field: "range", Match: Is, Value: "nothing"}},
		Agg: []Agg{
			{Op: Sum, Field: "price", As: "worth"},
			{Op: Count, As: "how_many"},
		},
	}
	res, err := Resolve(l, stock(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Agg["worth"] != nil {
		t.Errorf("sum over nothing is %v, and it has to be nothing",
			res.Agg["worth"])
	}
	// Count is the exception: no records is a real answer of zero.
	if res.Agg["how_many"] != 0 {
		t.Errorf("count over nothing is %v, want 0", res.Agg["how_many"])
	}
}

// An aggregate cannot read a field the listing does not expose.
//
// Listing.Fields is an allowlist because "adding a field to a content type
// must not change what a public page shows". The sum of a hidden cost is that
// field on a public page by another route.
func TestAnAggregateCannotReadAFieldTheListingHides(t *testing.T) {
	l := &Listing{
		Name: "public", Collection: "products",
		Fields: []string{"name"},
		Agg:    []Agg{{Op: Sum, Field: "cost", As: "worth"}},
	}
	if err := l.Validate(); err == nil {
		t.Error("a listing exposing only the name may aggregate a field it " +
			"does not expose, which puts that field on the page by another " +
			"route")
	}

	// And one that is exposed is fine.
	l.Agg = []Agg{{Op: Sum, Field: "name", As: "worth"}}
	if err := l.Validate(); err != nil {
		t.Errorf("aggregating an exposed field was refused: %v", err)
	}
}

// count is about records, so asking it to read a field is a mistake worth
// saying rather than silently ignoring.
func TestCountDoesNotTakeAField(t *testing.T) {
	l := &Listing{Name: "x", Collection: "products",
		Agg: []Agg{{Op: Count, Field: "price", As: "n"}}}
	if err := l.Validate(); err == nil {
		t.Error("count was given a field and nothing said so, so somebody " +
			"believes they are counting the priced ones")
	}
}

// Two aggregates cannot share a name, or a template asking for one gets
// whichever was declared last.
func TestTwoAggregatesCannotShareAName(t *testing.T) {
	l := &Listing{Name: "x", Collection: "products", Agg: []Agg{
		{Op: Count, As: "n"},
		{Op: Sum, Field: "price", As: "n"},
	}}
	if err := l.Validate(); err == nil {
		t.Error("two aggregates share a name and nothing said so")
	}
}

// An operation nobody implemented is refused, rather than answering nothing.
func TestAnUnknownOperationIsRefused(t *testing.T) {
	l := &Listing{Name: "x", Collection: "products",
		Agg: []Agg{{Op: "average", Field: "price", As: "mean"}}}
	if err := l.Validate(); err == nil {
		t.Error("a listing asking for an operation this does not have was " +
			"accepted, and would render an empty space where a number goes")
	}
}

// A price written as text adds up with one written as a number.
//
// Records arrive from JSON and from forms, and "12.00" and 12 are the same
// price — an answer that depended on how the record was written would be
// wrong in a way nobody could see from the page.
func TestANumberWrittenAsTextStillCounts(t *testing.T) {
	idx := &collection.Index{Collection: "products", Records: []collection.Record{
		{ID: "a", Fields: map[string]any{"price": "12.50"}},
		{ID: "b", Fields: map[string]any{"price": 7.5}},
	}}
	l := &Listing{Name: "x", Collection: "products",
		Agg: []Agg{{Op: Sum, Field: "price", As: "worth"}}}
	res, err := Resolve(l, idx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// int64 and not 20.0: a whole answer comes back whole, so a template
	// printing it does not render 20.000000 for a sum of prices.
	if res.Agg["worth"] != int64(20) {
		t.Errorf("sum is %#v, want int64(20)", res.Agg["worth"])
	}
}
