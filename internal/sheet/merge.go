// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// Rows becoming records of a collection.
//
// A row is a record already there when its id column names one, or when
// its key field (a page link, a product code) has the value one has; it
// is then that record, changed by the row's cells and keeping its other
// fields. Any other row is a new record, with an id worked out from what
// names it, so a sheet brought in twice is the same records, not twice
// as many.

// Merge is how rows become records.
type Merge struct {
	Collection string
	// Key is the field that says which record already here a row is,
	// such as slug or sku. Empty matches rows by their id column alone.
	Key string
	// Existing is the collection's records now.
	Existing []collection.Record
	// Check is the collection's type, as every write is checked by it.
	Check func(fields map[string]any) error
	// Slug, when set, is a field a record has to have and a row may leave
	// empty: it is made from the Title field, and kept apart from other
	// records' as a page link has to be.
	Slug, Title string
	// SkipBad brings the rows that can be and reports the rest, rather
	// than refusing them all.
	SkipBad bool
}

// Problem is one row that cannot be brought, and why.
type Problem struct {
	Line int `json:"line,omitempty"`
	// Where names a row that is not a line, such as an event of a calendar.
	Where string `json:"where,omitempty"`
	Text  string `json:"problem"`
}

func (p Problem) String() string {
	if p.Where != "" {
		return p.Where + ": " + p.Text
	}
	if p.Line == 0 {
		return p.Text
	}
	return fmt.Sprintf("line %d: %s", p.Line, p.Text)
}

// Plan is what bringing the rows in would do.
type Plan struct {
	Records []collection.Record `json:"-"`
	// Lines is the line each record came from.
	Lines    []int     `json:"-"`
	New      int       `json:"new"`
	Updated  int       `json:"updated"`
	Problems []Problem `json:"problems,omitempty"`
}

// Refused says whether nothing should be brought: a row could not be, and
// the rest were not asked for without it.
func (p *Plan) Refused() bool { return len(p.Problems) > 0 && len(p.Records) == 0 }

// Summary is the problems as a sentence or two, the first few of them.
func (p *Plan) Summary() string {
	var out []string
	for i, pr := range p.Problems {
		if i == maxProblems {
			out = append(out, fmt.Sprintf("and %d more", len(p.Problems)-maxProblems))
			break
		}
		out = append(out, pr.String())
	}
	return strings.Join(out, "; ")
}

// StableID is the id a record brought from elsewhere keeps: the same
// thing brought twice is the same record.
func StableID(coll, kind, value string) string {
	sum := sha256.Sum256([]byte("sheet\x00" + coll + "\x00" + kind + "\x00" + value))
	return hex.EncodeToString(sum[:16])
}

// keyOf is a field's value as a key: words, or a number as it reads.
func keyOf(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case nil:
		return ""
	case float64:
		return strings.TrimSpace(fmt.Sprint(x))
	}
	return ""
}

// Plan works out what bringing rows in would do. Nothing is written: the
// records it returns are for the caller to put, in one commit.
func (m Merge) Plan(rows []Row) *Plan {
	plan := &Plan{}
	byID := map[string]*collection.Record{}
	byKey := map[string]string{}
	slugs := map[string]string{}
	for i := range m.Existing {
		r := &m.Existing[i]
		byID[r.ID] = r
		if m.Key != "" {
			if k := keyOf(r.Fields[m.Key]); k != "" {
				byKey[k] = r.ID
			}
		}
		if m.Slug != "" {
			if s := keyOf(r.Fields[m.Slug]); s != "" {
				slugs[s] = r.ID
			}
		}
	}
	seen := map[string]int{}
	// fileSlugs are the page links this sheet has given so far.
	fileSlugs := map[string]int{}
	// next is, for a page link taken, the number to try first: every one
	// below it is taken (as in webimport's postSlugs). It is the number a
	// row was last given rather than the one after, because a row given
	// it may yet be refused, and its number is then free again.
	next := map[string]int{}
	var bad []Problem
	for _, row := range rows {
		fail := func(text string) { bad = append(bad, Problem{Line: row.Line, Where: row.Where, Text: text}) }
		if len(row.Problems) > 0 {
			fail(strings.Join(row.Problems, "; "))
			continue
		}
		row.Fields = maps.Clone(row.Fields)
		if row.Fields == nil {
			row.Fields = map[string]any{}
		}
		id := ""
		switch raw := strings.ToLower(strings.TrimSpace(row.ID)); {
		case raw == "":
		case collection.ValidID(raw) == nil:
			id = raw
		default:
			id = StableID(m.Collection, "id", row.ID)
		}
		byKeyField := func() {
			if id != "" || m.Key == "" {
				return
			}
			if k := keyOf(row.Fields[m.Key]); k != "" {
				if found, ok := byKey[k]; ok {
					id = found
				}
			}
		}
		if m.Key != m.Slug {
			byKeyField()
		}

		// A page link made from the title, when the row has none and the
		// record it is has none either.
		if m.Slug != "" && keyOf(row.Fields[m.Slug]) == "" &&
			(byID[id] == nil || keyOf(byID[id].Fields[m.Slug]) == "") {
			base := keyOf(row.Suggest[m.Slug])
			if base == "" {
				base = Slug(keyOf(row.Fields[m.Title]))
			}
			if base != "" {
				// Kept apart from this sheet's other page links, and from
				// other records' too, unless rows are matched to records by
				// their page link, when the record with it is the one this
				// row is.
				taken := func(s string) bool {
					return fileSlugs[s] > 0 || (m.Key != m.Slug && slugs[s] != "" && slugs[s] != id)
				}
				// One count from where the last row of this name stopped.
				// Each row counted up from 2, once for the sheet and again
				// for the records, so 10,000 rows of one name took 35
				// seconds to plan.
				slug := base
				for k := max(2, next[base]); taken(slug); k++ {
					slug = fmt.Sprintf("%s-%d", base, k)
					next[base] = k
				}
				row.Fields[m.Slug] = slug
			}
		}
		if m.Key == m.Slug {
			byKeyField()
		}
		if id == "" && m.Key != "" {
			if k := keyOf(row.Fields[m.Key]); k != "" {
				id = StableID(m.Collection, m.Key, k)
			}
		}
		if id == "" {
			var err error
			if id, err = collection.NewID(); err != nil {
				fail(err.Error())
				continue
			}
		}
		if first, dup := seen[id]; dup {
			fail(fmt.Sprintf("it is the same record as line %d", first))
			continue
		}

		existing := byID[id]
		fields := map[string]any{}
		if existing != nil {
			for k, v := range existing.Fields {
				fields[k] = v
			}
		}
		for k, v := range row.Fields {
			fields[k] = v
		}
		for _, k := range row.Clear {
			delete(fields, k)
		}
		for k, v := range row.Suggest {
			if keyOf(fields[k]) == "" && k != m.Slug {
				fields[k] = v
			}
		}
		if m.Slug != "" {
			if s := keyOf(fields[m.Slug]); s != "" {
				if line := fileSlugs[s]; line > 0 {
					fail(fmt.Sprintf("its %s, %s, is line %d's too", m.Slug, s, line))
					continue
				}
				if other := slugs[s]; other != "" && other != id {
					fail(fmt.Sprintf("its %s, %s, is another record's", m.Slug, s))
					continue
				}
			}
		}
		if m.Check != nil {
			if err := m.Check(fields); err != nil {
				fail(problemText(err))
				continue
			}
		}
		seen[id] = row.Line
		if m.Slug != "" {
			if s := keyOf(fields[m.Slug]); s != "" {
				fileSlugs[s] = row.Line
				slugs[s] = id
			}
		}
		if m.Key != "" {
			if k := keyOf(fields[m.Key]); k != "" {
				byKey[k] = id
			}
		}
		plan.Records = append(plan.Records, collection.Record{ID: id, Fields: fields})
		plan.Lines = append(plan.Lines, row.Line)
		if existing != nil {
			plan.Updated++
		} else {
			plan.New++
		}
	}
	plan.Problems = bad
	if len(bad) > 0 && !m.SkipBad {
		plan.Records, plan.Lines, plan.New, plan.Updated = nil, nil, 0, 0
	}
	return plan
}

// problemText is a type's refusal on one line.
func problemText(err error) string {
	if inv, ok := err.(*schema.Invalid); ok {
		var parts []string
		for _, p := range inv.Problems {
			parts = append(parts, p.String())
		}
		return strings.Join(parts, "; ")
	}
	return err.Error()
}

// Pictures are the fields holding a picture from the library, each with
// the field saying what it shows: a field another is the alt text of.
func Pictures(t *schema.Type) map[string]string {
	out := map[string]string{}
	if t == nil {
		return out
	}
	for _, f := range t.Fields {
		if f.AltFor != "" {
			out[f.AltFor] = f.Name
		}
	}
	return out
}

// IsMediaID says whether a value names a file in the library as it is.
func IsMediaID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Fetch puts the pictures the records name by address into the library,
// with get, leaving out any that cannot be and saying why. Names already
// in the library are kept as they are.
func (p *Plan) Fetch(pictures map[string]string, get func(raw, alt string) (string, error)) []Problem {
	var notes []Problem
	for i := range p.Records {
		f := p.Records[i].Fields
		for field, altField := range pictures {
			raw, _ := f[field].(string)
			raw = strings.TrimSpace(raw)
			if raw == "" || IsMediaID(raw) {
				continue
			}
			alt, _ := f[altField].(string)
			id, err := get(raw, alt)
			if err != nil {
				delete(f, field)
				notes = append(notes, Problem{Line: p.Lines[i], Text: fmt.Sprintf("its %s was left out: %v", field, err)})
				continue
			}
			f[field] = id
		}
	}
	return notes
}
