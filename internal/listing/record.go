// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package listing

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/collection"
)

// One record, found through a listing rather than beside it.
//
// This lived in internal/public, where a detail route reads the record a URL
// names. The admin's preview needs the same answer for the same URL, and a
// second copy would be a second answer to "what of this record is public" —
// the thing internal/public/detail.go says a detail route must never have.
// So the lookup is here, and both servers call it.

// ErrNoRecord is a record that is not there, or that the listing excludes.
//
// One error for both, deliberately. Distinguishing them turns the route into
// an oracle for what is in the store: a different answer for "no such product"
// and "a product you may not see" tells anybody who asks which unpublished
// slugs exist.
var ErrNoRecord = fmt.Errorf("no such record")

// Record returns the one row of a listing whose field holds key.
//
// The listing does the filtering, so this is a scan of what the listing
// already decided is visible. There is no second query with second rules, and
// a record the listing excludes is not found here either.
func (r *Resolver) Record(name, field, key string, args map[string]string) (
	Row, error) {

	if r == nil || r.Set == nil {
		return nil, fmt.Errorf("no listings are declared")
	}
	l, ok := r.Set.Get(name)
	if !ok {
		return nil, fmt.Errorf(
			"this page reads records through the listing %q, which is not "+
				"declared", name)
	}
	idx, err := r.Index.For(r.Store, r.At(), l.Collection)
	if err != nil {
		return nil, err
	}
	return Find(l, idx, args, field, key)
}

// Find is the one record a listing keeps whose field holds key.
//
// Its conditions decide, and its number of rows does not. A listing's rows
// are how many a page shows at once, not which records have a page: reading
// only those, the fifty-first product in a shop and every post but the
// newest fifty answered "not found" at their own addresses, linked from the
// feed and from search results. So every record the conditions keep is
// looked at, and the one with the key is shown through the listing's
// allow-list, as it always was.
func Find(l *Listing, idx *collection.Index, args map[string]string, field, key string) (Row, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if idx == nil || idx.Collection != l.Collection {
		return nil, fmt.Errorf("%q has no index of %q to read", l.Name, l.Collection)
	}
	q, ok, err := l.query(args)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoRecord
	}
	var rows []Row
	for _, rec := range idx.Matching(q) {
		v, _ := rec.Fields[field].(string)
		if field == "id" {
			v = rec.ID
		}
		if v == key {
			rows = append(rows, project(l, rec))
		}
	}
	return MatchOne(rows, field, key)
}

// MatchOne finds the single row whose key field holds a value.
//
// Separate from the lookup so the three answers — none, one, several — can be
// tested without building a store to produce each. The several case is the
// one that matters: answering it by taking the first is a decision made by
// whatever order the index happened to return, which nobody reviewed, and the
// two pages would swap places on a reindex.
func MatchOne(rows []Row, field, want string) (Row, error) {
	var found Row
	var n int
	for _, row := range rows {
		if v, _ := row[field].(string); v == want {
			found = row
			n++
		}
	}
	switch n {
	case 0:
		return nil, ErrNoRecord
	case 1:
		return found, nil
	default:
		return nil, fmt.Errorf(
			"%d records share the %s %q, so this address does not name one "+
				"of them", n, field, want)
	}
}
