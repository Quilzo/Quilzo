// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/schema"
)

// A feature from raw data: a spreadsheet or a JSON list of records becomes
// a type, a collection, a listing and a page that shows it, with the rows
// kept apart so they are imported into the collection after the feature is
// installed. A package carries definitions and never data: what was in the
// file stays on this installation.
//
// Every kind is inferred from the values, never from what the column is
// called, and only when every value in the column fits it: a column with one
// non-number in it is text. A column whose values repeat among a few
// choices is a choice. A column with nothing missing is required.

// Bounds on what is read.
const (
	MaxRows    = 50000
	MaxColumns = 60
)

// Inferred is a package made from data, with the rows to import.
type Inferred struct {
	Package *Package
	// Collection is where Rows go once the package is installed.
	Collection string
	Rows       []map[string]any
	// Notes say what was decided and why, for the person reading the card.
	Notes []string
}

var reNonWord = regexp.MustCompile(`[^a-z0-9]+`)

// fieldName turns a column heading into a field name the store accepts.
func fieldName(h string, taken map[string]bool) string {
	n := strings.Trim(reNonWord.ReplaceAllString(strings.ToLower(strings.TrimSpace(h)), "_"), "_")
	if n == "" {
		n = "field"
	}
	if n[0] < 'a' || n[0] > 'z' {
		n = "f_" + n
	}
	if len(n) > 40 {
		n = strings.TrimRight(n[:40], "_")
	}
	base, i := n, 2
	for taken[n] {
		n = fmt.Sprintf("%s_%d", base, i)
		i++
	}
	taken[n] = true
	return n
}

// slug is a name for a page: words joined by hyphens.
func slug(s string) string {
	n := strings.Trim(reNonWord.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		n = "data-" + n
	}
	if len(n) > 40 {
		n = strings.TrimRight(n[:40], "-")
	}
	return strings.Trim(n, "-")
}

// Infer makes a package from a CSV file or a JSON array of objects. name is
// what the feature is called, usually the file's name without its suffix.
func Infer(name string, body []byte) (*Inferred, error) {
	headers, rows, err := readTable(body)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("there are no rows to learn the fields from")
	}
	pageName := slug(name)
	base := strings.ReplaceAll(pageName, "-", "_")
	if len(base) > 40 {
		base = base[:40]
	}

	taken := map[string]bool{}
	type column struct {
		heading, field string
		kind           schema.Kind
		choices        []string
		required       bool
	}
	var cols []column
	for _, h := range headers {
		cols = append(cols, column{heading: h, field: fieldName(h, taken)})
	}
	var notes []string
	for i := range cols {
		var values []string
		missing := false
		for _, r := range rows {
			v := strings.TrimSpace(r[cols[i].heading])
			if v == "" {
				missing = true
				continue
			}
			values = append(values, v)
		}
		cols[i].kind, cols[i].choices = inferKind(values, len(rows))
		// A column about people is never a choice: its values would travel
		// in the package as the choices, and a package is shared.
		if cols[i].kind == schema.Choice && fieldClass(schema.Field{Name: cols[i].field, Label: cols[i].heading}) != "" {
			cols[i].kind, cols[i].choices = schema.Text, nil
		}
		cols[i].required = !missing && len(values) > 0
		if cols[i].field != strings.ToLower(cols[i].heading) {
			notes = append(notes, fmt.Sprintf("column %q is the field %s", cols[i].heading, cols[i].field))
		}
	}

	t := schema.Type{Name: base, Description: "One row of " + name}
	for _, c := range cols {
		f := schema.Field{Name: c.field, Kind: c.kind, Required: c.required, Label: c.heading}
		if c.kind == schema.Choice {
			f.Choices = c.choices
		}
		t.Fields = append(t.Fields, f)
	}
	if err := schema.NewRegistry().Add(t); err != nil {
		return nil, fmt.Errorf("the inferred type is not usable: %w", err)
	}

	// The listing shows the first few fields that read well in a row.
	var shown []string
	for _, c := range cols {
		if c.kind != schema.LongText && len(shown) < 6 {
			shown = append(shown, c.field)
		}
	}
	listName := "all_" + base
	if len(listName) > 48 {
		listName = listName[:48]
	}
	l := listing.Listing{Name: listName, Label: titleOf(name), Collection: base, Fields: shown, Rows: 50}
	if len(shown) > 0 {
		l.Sort = shown[0]
	}

	p := &Package{
		Format:      Format,
		Name:        pageName,
		Version:     "1.0.0",
		Title:       titleOf(name),
		Purpose:     fmt.Sprintf("Keep the %d records from %s, and show them to signed-in members.", len(rows), name),
		Types:       []schema.Type{t},
		Collections: []Collection{{Name: base, Type: base}},
		Listings:    []listing.Listing{l},
		Pages: []Page{{Name: pageName, Body: map[string]any{
			"title":        titleOf(name),
			"members_only": true,
			"sections":     []any{map[string]any{"listing": map[string]any{"name": listName}}},
		}}},
	}
	notes = append(notes, "the page is for signed-in members; set members_only to false in the package to make it public")

	out := &Inferred{Package: p, Collection: base, Notes: notes}
	for _, r := range rows {
		rec := map[string]any{}
		for _, c := range cols {
			v := strings.TrimSpace(r[c.heading])
			if v == "" {
				continue
			}
			rec[c.field] = typedValue(v, c.kind)
		}
		out.Rows = append(out.Rows, rec)
	}
	return out, nil
}

func titleOf(name string) string {
	words := strings.Fields(reNonWord.ReplaceAllString(strings.ToLower(name), " "))
	if len(words) == 0 {
		return "Records"
	}
	words[0] = strings.ToUpper(words[0][:1]) + words[0][1:]
	t := strings.Join(words, " ")
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

// readTable reads CSV or a JSON array of objects into headings and rows.
func readTable(body []byte) ([]string, []map[string]string, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var objs []map[string]any
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&objs); err != nil {
			return nil, nil, fmt.Errorf("this is not a JSON array of objects: %w", err)
		}
		seen := map[string]bool{}
		var headers []string
		var rows []map[string]string
		for i, o := range objs {
			if i >= MaxRows {
				return nil, nil, fmt.Errorf("at most %d rows", MaxRows)
			}
			row := map[string]string{}
			keys := make([]string, 0, len(o))
			for k := range o {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if !seen[k] {
					seen[k] = true
					headers = append(headers, k)
				}
				switch v := o[k].(type) {
				case nil:
				case string:
					row[k] = v
				case json.Number:
					row[k] = v.String()
				case bool:
					row[k] = strconv.FormatBool(v)
				default:
					return nil, nil, fmt.Errorf("row %d: %q holds a list or an object; a record is flat", i+1, k)
				}
			}
			rows = append(rows, row)
		}
		if len(headers) > MaxColumns {
			return nil, nil, fmt.Errorf("%d fields; at most %d", len(headers), MaxColumns)
		}
		return headers, rows, nil
	}
	r := csv.NewReader(bytes.NewReader(trimmed))
	r.FieldsPerRecord = -1
	headers, err := r.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("this is not CSV with a heading row: %w", err)
	}
	if len(headers) > MaxColumns {
		return nil, nil, fmt.Errorf("%d columns; at most %d", len(headers), MaxColumns)
	}
	seen := map[string]bool{}
	for i, h := range headers {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			h = fmt.Sprintf("column %d", i+1)
		}
		seen[h] = true
		headers[i] = h
	}
	var rows []map[string]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("row %d is not CSV: %w", len(rows)+2, err)
		}
		if len(rows) >= MaxRows {
			return nil, nil, fmt.Errorf("at most %d rows", MaxRows)
		}
		row := map[string]string{}
		for i, h := range headers {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return headers, rows, nil
}

var reISODate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// inferKind is the narrowest kind every value fits.
func inferKind(values []string, rows int) (schema.Kind, []string) {
	if len(values) == 0 {
		return schema.Text, nil
	}
	all := func(ok func(string) bool) bool {
		for _, v := range values {
			if !ok(v) {
				return false
			}
		}
		return true
	}
	switch {
	case all(func(v string) bool {
		switch strings.ToLower(v) {
		case "true", "false", "yes", "no":
			return true
		}
		return false
	}):
		return schema.Boolean, nil
	case all(func(v string) bool { _, err := strconv.ParseFloat(v, 64); return err == nil }):
		return schema.Number, nil
	case all(func(v string) bool { return reISODate.MatchString(v) }):
		return schema.Date, nil
	case all(func(v string) bool {
		a, err := mail.ParseAddress(v)
		return err == nil && a.Address == v && !strings.ContainsAny(v, " <>")
	}):
		return schema.Email, nil
	case all(func(v string) bool { return strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") }):
		return schema.URL, nil
	}
	distinct := map[string]bool{}
	longest := 0
	for _, v := range values {
		distinct[v] = true
		if len(v) > longest {
			longest = len(v)
		}
	}
	if len(values) >= 3 && len(distinct) < len(values) && len(distinct) <= 12 &&
		2*len(distinct) <= len(values)+1 && longest <= 60 {
		var choices []string
		for v := range distinct {
			choices = append(choices, v)
		}
		sort.Strings(choices)
		return schema.Choice, choices
	}
	if longest > 200 {
		return schema.LongText, nil
	}
	return schema.Text, nil
}

func typedValue(v string, k schema.Kind) any {
	switch k {
	case schema.Number:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
		f, _ := strconv.ParseFloat(v, 64)
		return f
	case schema.Boolean:
		l := strings.ToLower(v)
		return l == "true" || l == "yes"
	}
	return v
}

// CheckRows says whether rows fit a collection the package declares, by the
// package's own type, before anything is installed: rows that would be
// refused after the install are refused now, with the install.
func (p *Package) CheckRows(name string, rows []map[string]any) error {
	var typeName string
	for _, c := range p.Collections {
		if c.Name == name {
			typeName = c.Type
		}
	}
	if typeName == "" {
		return fmt.Errorf("the package declares no collection %q to put these records in", name)
	}
	reg := schema.NewRegistry()
	for _, t := range p.Types {
		if err := reg.Add(t); err != nil {
			return err
		}
	}
	st := &schema.Store{Registry: reg, Collections: map[string]string{name: typeName}}
	var bad []string
	for i, r := range rows {
		for _, prob := range st.CheckRecord(name, r) {
			bad = append(bad, fmt.Sprintf("record %d: %s", i+1, prob))
			break
		}
		if len(bad) == 5 {
			break
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("these records do not fit %s:\n  %s", typeName, strings.Join(bad, "\n  "))
	}
	return nil
}

// Rows are records to import with a package, into one of its collections.
type Rows struct {
	Collection string           `json:"collection"`
	Records    []map[string]any `json:"records"`
}
