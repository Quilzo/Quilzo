// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// WriteOptions says how a sheet is written.
type WriteOptions struct {
	// BOM starts the file with UTF-8's mark, without which Excel reads
	// accents as two strange letters each.
	BOM bool
	// Picture is where a picture in the library can be fetched from, so a
	// sheet taken to another site brings its pictures with it. Nil writes
	// each picture's id.
	Picture func(id string) string
}

// Write writes records as a sheet: their ids first, then the type's
// fields in the order it declares them, then any other field a record
// has. Headings are field names, which is what reading matches first, so a
// sheet written here comes back in as it went out.
func Write(t *schema.Type, recs []collection.Record, opts WriteOptions) []byte {
	cols := columns(t, recs)
	pictures := Pictures(t)
	var buf bytes.Buffer
	if opts.BOM {
		buf.WriteString("\ufeff")
	}
	w := csv.NewWriter(&buf)
	w.UseCRLF = true
	_ = w.Write(append([]string{"id"}, cols...))
	sorted := append([]collection.Record(nil), recs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Created != sorted[j].Created {
			return sorted[i].Created < sorted[j].Created
		}
		return sorted[i].ID < sorted[j].ID
	})
	row := make([]string, len(cols)+1)
	for _, r := range sorted {
		row[0] = r.ID
		for i, c := range cols {
			v := r.Fields[c]
			if _, isPicture := pictures[c]; isPicture && opts.Picture != nil {
				if id, ok := v.(string); ok && IsMediaID(id) {
					v = opts.Picture(id)
				}
			}
			row[i+1] = guardFormula(cell(v))
		}
		_ = w.Write(row)
	}
	w.Flush()
	return buf.Bytes()
}

// columns are the fields a sheet of these records has.
func columns(t *schema.Type, recs []collection.Record) []string {
	var cols []string
	have := map[string]bool{"id": true}
	if t != nil {
		for _, f := range t.Fields {
			if !have[f.Name] {
				cols = append(cols, f.Name)
				have[f.Name] = true
			}
		}
	}
	var extra []string
	for _, r := range recs {
		for k := range r.Fields {
			if !have[k] {
				extra = append(extra, k)
				have[k] = true
			}
		}
	}
	sort.Strings(extra)
	// With no type, the field naming a record leads, as it does on the
	// Data screen.
	if t == nil {
		for i, k := range extra {
			if k == "title" || k == "name" {
				extra = append(append([]string{k}, extra[:i]...), extra[i+1:]...)
				break
			}
		}
	}
	return append(cols, extra...)
}

// cell is a value as a sheet shows it, which reading reads back as it was.
func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []any:
		items := make([]string, 0, len(x))
		plain := true
		for _, it := range x {
			s := cell(it)
			if strings.ContainsAny(s, ";|\n") || strings.TrimSpace(s) != s || s == "" {
				plain = false
			}
			items = append(items, s)
		}
		if plain {
			return strings.Join(items, "; ")
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// guardFormula keeps a cell from being run as a formula by the spreadsheet
// it is opened in (GuardCell).
func guardFormula(s string) string { return GuardCell(s) }
