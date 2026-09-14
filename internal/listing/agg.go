// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package listing

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
)

// Saying something about the whole set, not just the rows on the page.
//
// # What was missing
//
// Result has carried Total since it existed — "how many matched before the row
// limit, so a template can say 'showing 20 of 340' without a second query" —
// and that is the only thing a page could say about a collection. Not the
// total value of what is in stock, not the earliest date, not the most recent
// change. Those are the sentences a catalogue, a changelog or a status page is
// made of, and every one of them had to be written by hand and kept true by
// somebody remembering.
//
// # Why this is not a formula language
//
// The whole argument of internal/schema is that a declaration is safe because
// it cannot compute: no combinators, no $ref, no expressions. The template
// language "cannot execute anything — there is no query to inject into and
// nothing to escape from". A formula field would be a new execution surface
// inside the one thing that was sold as having none.
//
// So this is a closed set of operations named by a Go constant, applied to one
// declared field. There is nothing to parse, nothing nests, there are no
// operators and no user-supplied syntax — the same shape Condition already
// has, where a filter is a field, a named comparison and a literal-or-param.
// `sum` is a word in a JSON file, not an expression somebody wrote.
//
// # Over the matched set, before the limit
//
// An aggregate of the rows on the page would be a number that changes when
// somebody sets `rows` to 10, which is the shape of wrong that nobody reports
// because it always looks plausible. collection.Matching is the walk Total
// already pays for, kept.

// Op is what an aggregate does. A closed set, named here and nowhere else.
type Op string

const (
	// Count is how many records matched, ignoring Field.
	Count Op = "count"
	// Sum adds a numeric field. Records where it is absent or not a number
	// are skipped rather than counted as zero — see the note on skipped.
	Sum Op = "sum"
	// Min and Max are the smallest and largest, comparing numbers as numbers
	// and everything else as text.
	Min Op = "min"
	Max Op = "max"
	// Latest is the value of the field on the most recently updated record,
	// which is how a page says "the current price" or "last changed by".
	Latest Op = "latest"
)

// MaxAgg bounds how many a listing may declare.
//
// Small, and for the same reason MaxConditions is: every one is a walk over
// the matched set, and a page that quietly costs twelve of them is a page that
// got slow without anybody choosing it. Eight is more than any real page has
// needed and few enough that the budget check can say so plainly.
const MaxAgg = 8

// An Agg is one number a listing works out about everything that matched.
type Agg struct {
	Op Op `json:"op"`
	// Field is what to read. Empty for count, which is about records rather
	// than about a value.
	Field string `json:"field,omitempty"`
	// As is the name the template reads it by, so a page can carry two sums
	// of different fields without either one being "the sum".
	As string `json:"as"`
}

// Validate checks one aggregate against the listing that declares it.
func (a Agg) Validate(exposed []string) error {
	switch a.Op {
	case Count, Sum, Min, Max, Latest:
	default:
		return fmt.Errorf(
			"%q is not something an aggregate does; the operations are "+
				"count, sum, min, max and latest", a.Op)
	}
	if !reName.MatchString(a.As) {
		return fmt.Errorf(
			"%q is not a usable name for an aggregate; lowercase letters, "+
				"digits and underscores, starting with a letter", a.As)
	}
	if a.Op == Count {
		if a.Field != "" {
			return fmt.Errorf(
				"count is about records rather than about %q; leave the "+
					"field out, or ask for something that reads one", a.Field)
		}
		return nil
	}
	if !reField.MatchString(a.Field) {
		return fmt.Errorf("%s needs a field to read, and %q is not the name "+
			"of one", a.Op, a.Field)
	}
	// An aggregate over a field the listing does not expose would put that
	// field's values on a public page by another route — the sum of a hidden
	// cost, the max of a hidden date. Listing.Fields is an allowlist for
	// exactly this reason, and an aggregate is a way of showing a field.
	if len(exposed) > 0 {
		for _, f := range exposed {
			if f == a.Field {
				return nil
			}
		}
		return fmt.Errorf(
			"%q is not one of the fields this listing exposes, and an "+
				"aggregate of it would put its values on the page by another "+
				"route. Add it to the field list, or aggregate something else",
			a.Field)
	}
	return nil
}

// aggregate works out every declared number over the matched records.
func aggregate(aggs []Agg, matched []collection.Record) map[string]any {
	if len(aggs) == 0 {
		return nil
	}
	out := make(map[string]any, len(aggs))
	for _, a := range aggs {
		out[a.As] = a.over(matched)
	}
	return out
}

// over is one aggregate's answer.
//
// nil when there is nothing to say — an empty collection, or a field no
// matching record carries. nil rather than zero, because "the sum is 0" and
// "there is nothing to add up" are different sentences and a template that
// prints the first when it means the second is telling somebody the stock is
// worthless rather than that there is none.
func (a Agg) over(records []collection.Record) any {
	if a.Op == Count {
		return len(records)
	}
	if len(records) == 0 {
		return nil
	}

	switch a.Op {
	case Sum:
		total, any := 0.0, false
		for _, r := range records {
			if n, ok := asNumber(r.Fields[a.Field]); ok {
				total, any = total+n, true
			}
		}
		if !any {
			return nil
		}
		return trimFloat(total)
	case Latest:
		var best *collection.Record
		for i := range records {
			if records[i].Fields[a.Field] == nil {
				continue
			}
			if best == nil || records[i].Updated > best.Updated ||
				(records[i].Updated == best.Updated && records[i].ID > best.ID) {
				best = &records[i]
			}
		}
		if best == nil {
			return nil
		}
		return best.Fields[a.Field]
	case Min, Max:
		var best any
		for _, r := range records {
			v := r.Fields[a.Field]
			if v == nil {
				continue
			}
			if best == nil {
				best = v
				continue
			}
			c := compareValues(v, best)
			if (a.Op == Min && c < 0) || (a.Op == Max && c > 0) {
				best = v
			}
		}
		return best
	}
	return nil
}

// asNumber reads a value as a number, JSON's way.
//
// A string that looks like a number counts. Records arrive from JSON and from
// forms, and a price stored as "12.00" by one route and 12 by another is the
// same price — refusing to add the first would make the answer depend on how
// the record was written rather than on what it says.
func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

// compareValues orders two field values: numbers as numbers, the rest as text.
func compareValues(a, b any) int {
	an, aok := asNumber(a)
	bn, bok := asNumber(b)
	if aok && bok {
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	}
	as, bs := fmt.Sprint(a), fmt.Sprint(b)
	return strings.Compare(as, bs)
}

// trimFloat gives back an integer when the answer is one, so a count of whole
// things does not print as 12.000000.
func trimFloat(f float64) any {
	if f == float64(int64(f)) {
		return int64(f)
	}
	return f
}
