// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package sheet reads a spreadsheet saved as CSV into a collection's
// records, and writes records out as one: what moves a catalogue, a list of
// events or a directory between Quilzo and anything else that keeps rows
// (Excel, Google Sheets, Numbers, Airtable, Notion, Shopify, Wix and the
// rest), and back.
//
// Reading is forgiving about how a sheet is written and strict about what
// it says. A comma, a semicolon or a tab between cells; UTF-8 with or
// without its mark, UTF-16 as Excel saves "Unicode text", or Windows-1252
// as older Excel saves CSV; a date as 2026-11-14, 14/11/2026 or 14 Nov
// 2026; a price as £1,250.00. Each value is read as the kind its field
// declares, and one that cannot be is reported with its line, never
// guessed at: a date that could be either the 3rd of April or the 4th of
// March is asked about rather than read one way.
//
// Writing escapes what a spreadsheet would run. A cell beginning = + - or
// @ is a formula to Excel, so one that is not a plain decimal number is
// written with an apostrophe first (OWASP's CSV injection), which reading
// takes off again. guard.go is that rule, for every CSV Quilzo writes.
package sheet

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/schema"
)

// Limits on one sheet.
const (
	MaxBytes   = 64 << 20
	MaxRows    = 50000
	MaxColumns = 256
	// maxProblems is how many problems one sheet reports before saying how
	// many more there are.
	maxProblems = 10
)

// Options says how a sheet is read.
type Options struct {
	// Type is the collection's type: the columns are matched to its fields
	// and each value is read as its field's kind. Nil reads a collection
	// with no type, where each column is a field of its own name.
	Type *schema.Type
	// Map matches columns to fields by hand, a column's heading to a field
	// name, before anything is matched by name. A field of "" leaves the
	// column out.
	Map map[string]string
	// Dates says which comes first in a date written 03/04/2026: DayFirst
	// or MonthFirst. Empty works it out from the column, and asks when it
	// cannot.
	Dates string
}

// Which comes first in a date written with slashes.
const (
	DayFirst   = "dmy"
	MonthFirst = "mdy"
)

// Column is how one column is read.
type Column struct {
	Header string `json:"header"`
	// Field is the field it fills; empty when it is left out.
	Field string `json:"field,omitempty"`
	// ID marks the column naming each record.
	ID bool `json:"id,omitempty"`
	// Note says how it was matched when not by its name, or why it was
	// left out.
	Note string `json:"note,omitempty"`
}

// Row is one line of a sheet, as fields.
type Row struct {
	// Line is where it starts in the file, counting the headings as 1.
	Line int
	// Where names a row that is not a line of a sheet, for its problems.
	Where string
	// ID is what its id column says, as written.
	ID     string
	Fields map[string]any
	// Clear names the fields whose cells were empty: an update takes them
	// away, which is what a sheet exported, emptied and brought back means.
	Clear []string
	// Suggest holds values a record is given only when it has none.
	Suggest map[string]any
	// Problems are its values that could not be read.
	Problems []string
}

// Sheet is a sheet, read.
type Sheet struct {
	Columns []Column
	Rows    []Row
	// Notes say how it was read when that is worth knowing: its encoding.
	Notes []string
}

// AmbiguousDates is the error for a column of dates that could be read
// day first or month first, and does not say which.
type AmbiguousDates struct {
	Column, Example string
}

func (e *AmbiguousDates) Error() string {
	return fmt.Sprintf("the dates in %q, such as %s, could be day first or month first: say which", e.Column, e.Example)
}

// Read reads a sheet.
func Read(body []byte, opts Options) (*Sheet, error) {
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("larger than %d MB", MaxBytes>>20)
	}
	text, comma, enc := Decode(body)
	sh := &Sheet{}
	if enc != "" {
		sh.Notes = append(sh.Notes, "read as "+enc)
	}
	if rec, line, cells := TooWide(text, comma, MaxColumns); rec == 0 {
		return nil, fmt.Errorf("it has %d columns, and at most %d are read", cells, MaxColumns)
	} else if rec > 0 {
		return nil, fmt.Errorf("line %d has %d cells, and at most %d are read", line, cells, MaxColumns)
	}
	r := csv.NewReader(strings.NewReader(text))
	r.Comma = comma
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("it is empty")
	}
	if err != nil {
		return nil, fmt.Errorf("its first line cannot be read: %w", err)
	}
	if len(header) > MaxColumns {
		return nil, fmt.Errorf("it has %d columns, and at most %d are read", len(header), MaxColumns)
	}
	sh.Columns = match(header, opts)
	used := false
	for _, c := range sh.Columns {
		used = used || c.Field != "" || c.ID
	}
	if !used {
		return nil, errors.New("none of its columns is a field of this collection: " + leftOut(sh.Columns))
	}

	var raw [][]string
	var lines []int
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("it cannot be read past %w", err)
		}
		if blank(rec) {
			continue
		}
		if len(raw) == MaxRows {
			return nil, fmt.Errorf("it has more than %d rows: bring it in parts", MaxRows)
		}
		line, _ := r.FieldPos(0)
		raw = append(raw, rec)
		lines = append(lines, line)
	}
	if len(raw) == 0 {
		return nil, errors.New("it has headings and no rows under them")
	}

	fields := map[string]schema.Field{}
	if opts.Type != nil {
		for _, f := range opts.Type.Fields {
			fields[f.Name] = f
		}
	}
	orders := make([]string, len(sh.Columns))
	for ci, c := range sh.Columns {
		if f, ok := fields[c.Field]; ok && f.Kind == schema.Date {
			o, err := dateOrder(c.Header, raw, ci, opts.Dates)
			if err != nil {
				return nil, err
			}
			orders[ci] = o
		}
	}
	decimalComma := comma == ';'
	for i, rec := range raw {
		row := Row{Line: lines[i], Fields: map[string]any{}}
		for ci, c := range sh.Columns {
			cell := ""
			if ci < len(rec) {
				cell = rec[ci]
			}
			cell = unformula(cell)
			switch {
			case c.ID:
				row.ID = strings.TrimSpace(cell)
				continue
			case c.Field == "":
				continue
			case strings.TrimSpace(cell) == "":
				row.Clear = append(row.Clear, c.Field)
				continue
			}
			f, typed := fields[c.Field]
			if !typed {
				row.Fields[c.Field] = guess(cell)
				continue
			}
			v, problem := value(f, cell, orders[ci], decimalComma)
			if problem != "" {
				row.Problems = append(row.Problems, fmt.Sprintf("%s: %s", c.Header, problem))
				continue
			}
			row.Fields[c.Field] = v
		}
		if len(rec) > len(sh.Columns) && !blank(rec[len(sh.Columns):]) {
			row.Problems = append(row.Problems, "it has more cells than there are headings")
		}
		sh.Rows = append(sh.Rows, row)
	}
	return sh, nil
}

func blank(rec []string) bool {
	for _, c := range rec {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

// leftOut names the columns left out, for an error.
func leftOut(cols []Column) string {
	var names []string
	for _, c := range cols {
		if c.Field == "" && !c.ID {
			names = append(names, fmt.Sprintf("%q", c.Header))
		}
	}
	if len(names) > 8 {
		names = append(names[:8], "…")
	}
	return strings.Join(names, ", ")
}

// -- How the file is written ------------------------------------------------------

// Text is a sheet's bytes as text, and what is between its cells, worked
// out as Read works them out: for a reader of its own, such as the one
// that infers a type from a sheet.
func Text(body []byte) (string, rune) {
	text, comma, _ := Decode(body)
	return text, comma
}

// Decode is Text, and the encoding the bytes were read as when that was
// not UTF-8 ("UTF-16", "Windows-1252, as older Excel saves CSV"), for a
// reader of its own to say so as Read does. It is the one reading of a
// CSV's bytes: the newsletter's import had its own, which took off a UTF-8
// mark and nothing else, so a list Excel saved as Unicode Text had no
// address column and one saved as Windows-1252 kept every é as U+FFFD.
func Decode(body []byte) (text string, comma rune, encoding string) {
	text, encoding = decode(body)
	comma, text = delimiter(text)
	return text, comma, encoding
}

// TooWide finds the first row of a CSV text with more than max cells, as
// encoding/csv splits it with LazyQuotes: which row it is, counting the
// first as 0, the line it starts on, and how many cells it has. row is -1
// when no row has more than max.
//
// It is for before encoding/csv reads the text, which builds each row
// whole however many cells it has. Only the headings were compared with a
// limit, and only once built: a row of 32 million commas, in a 32 MB
// upload, took 2.9 GB of heap. Counting takes one pass and no memory.
func TooWide(text string, comma rune, max int) (row, line, cells int) {
	sep := string(comma)
	at, row := 1, 0
	for i := 0; i < len(text); row++ {
		// Lines with nothing on them are not rows, and the line break
		// that ends a row is passed here.
		for n := lineBreak(text[i:]); n > 0; n = lineBreak(text[i:]) {
			i += n
			at++
		}
		if i == len(text) {
			break
		}
		start, n := at, 0
	cell:
		for {
			n++
			if i < len(text) && text[i] == '"' {
				// A quoted cell ends at a quote before a separator or a
				// line break; "" is a quote, and any other quote is kept
				// as it is.
				i++
				for {
					j := strings.IndexByte(text[i:], '"')
					if j < 0 {
						i = len(text)
						break cell
					}
					at += strings.Count(text[i:i+j], "\n")
					i += j + 1
					switch {
					case strings.HasPrefix(text[i:], `"`):
						i++
					case strings.HasPrefix(text[i:], sep):
						i += len(sep)
						continue cell
					case i == len(text) || lineBreak(text[i:]) > 0:
						break cell
					}
				}
			}
			for {
				switch {
				case i == len(text) || lineBreak(text[i:]) > 0:
					break cell
				case strings.HasPrefix(text[i:], sep):
					i += len(sep)
					continue cell
				}
				i++
			}
		}
		if n > max {
			return row, start, n
		}
	}
	return -1, 0, 0
}

// lineBreak is how long the line break that s starts with is, as
// encoding/csv reads one: \n, \r\n, or a \r that ends the file.
func lineBreak(s string) int {
	switch {
	case strings.HasPrefix(s, "\n"), s == "\r":
		return 1
	case strings.HasPrefix(s, "\r\n"):
		return 2
	}
	return 0
}

// decode is the file as text, and the encoding it was read as when that
// was not UTF-8.
func decode(b []byte) (string, string) {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return string(b[3:]), ""
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return fromUTF16(b[2:], false), "UTF-16"
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		return fromUTF16(b[2:], true), "UTF-16"
	case utf8.Valid(b):
		return string(b), ""
	}
	return fromWindows1252(b), "Windows-1252, as older Excel saves CSV"
}

func fromUTF16(b []byte, bigEndian bool) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			units = append(units, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return string(utf16.Decode(units))
}

// cp1252 is what Windows-1252 puts at 0x80 to 0x9F, where Latin-1 has
// control characters; the rest of it is Latin-1, which is Unicode's first
// 256.
var cp1252 = [32]rune{
	'€', '�', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '�', 'Ž', '�',
	'�', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '�', 'ž', 'Ÿ',
}

func fromWindows1252(b []byte) string {
	var s strings.Builder
	s.Grow(len(b))
	for _, c := range b {
		switch {
		case c < 0x80:
			s.WriteByte(c)
		case c < 0xA0:
			s.WriteRune(cp1252[c-0x80])
		default:
			s.WriteRune(rune(c))
		}
	}
	return s.String()
}

// delimiter is what is between cells: whichever of a comma, a semicolon
// and a tab the headings use most, or what Excel's "sep=" first line says.
func delimiter(text string) (rune, string) {
	first, rest, _ := strings.Cut(text, "\n")
	if f := strings.TrimSpace(first); strings.HasPrefix(strings.ToLower(f), "sep=") && len(f) == 5 {
		return rune(f[4]), rest
	}
	counts := map[rune]int{}
	quoted := false
	for _, r := range first {
		switch {
		case r == '"':
			quoted = !quoted
		case !quoted && (r == ',' || r == ';' || r == '\t'):
			counts[r]++
		}
	}
	best := ','
	for _, r := range []rune{';', '\t'} {
		if counts[r] > counts[best] {
			best = r
		}
	}
	return best, text
}

// unformula takes off the apostrophe a writer put before a cell that would
// otherwise be a formula (UnguardCell).
func unformula(s string) string { return UnguardCell(s) }

// -- Which column is which field --------------------------------------------------

var reFieldName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// norm is a heading as a field name might be written: lower case, words
// joined by underscores.
func norm(s string) string {
	var b strings.Builder
	under := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			under = false
		} else if !under && b.Len() > 0 {
			b.WriteByte('_')
			under = true
		}
	}
	return strings.TrimRight(b.String(), "_")
}

// alike are headings other platforms write for the fields Quilzo's ready
// made features have, tried after a field's own name and label.
var alike = map[string][]string{
	"name": {"title"}, "heading": {"title"}, "post_title": {"title"}, "event_name": {"title"},
	"event_title": {"title"}, "product_name": {"title"},
	"handle": {"slug"}, "permalink": {"slug"}, "url_slug": {"slug"}, "post_name": {"slug"},
	"description": {"summary", "body"}, "about": {"summary"}, "excerpt": {"summary"},
	"content": {"body"}, "post_content": {"body"},
	"start_date": {"date"}, "day": {"date"}, "event_date": {"date"},
	"start_time": {"time"}, "starts": {"time"}, "end_time": {"until"}, "finishes": {"until"},
	"place": {"venue"}, "address": {"location"}, "where": {"location"},
	"picture": {"image"}, "photo": {"image"}, "image_url": {"image"}, "image_src": {"image"},
	"featured_image": {"image"},
	"image_alt":      {"alt"}, "alt_text": {"alt"}, "image_alt_text": {"alt"},
	"author": {"byline"}, "post_author": {"byline"}, "date_published": {"published"},
	"publish_date": {"published"}, "post_date": {"published"}, "categories": {"tags"},
	"cost": {"price"}, "ticket_url": {"tickets"}, "tickets_url": {"tickets"},
}

// match says which field each column fills.
func match(header []string, opts Options) []Column {
	cols := make([]Column, len(header))
	taken := map[string]int{}
	byNorm := map[string]string{}
	labels := map[string]string{}
	declared := map[string]bool{}
	if opts.Type != nil {
		for _, f := range opts.Type.Fields {
			declared[f.Name] = true
			byNorm[f.Name] = f.Name
			if l := norm(f.Label); l != "" {
				labels[l] = f.Name
			}
		}
	}
	mapped := map[string]string{}
	for k, v := range opts.Map {
		mapped[norm(k)] = strings.TrimSpace(v)
	}
	idTaken := false
	for i, h := range header {
		if i == 0 {
			h = strings.TrimPrefix(h, "\ufeff")
		}
		h = strings.TrimSpace(h)
		c := Column{Header: h}
		n := norm(h)
		field, how := "", ""
		if to, ok := mapped[n]; ok {
			field, how = to, "as asked"
			if field == "" {
				c.Note = "left out, as asked"
				cols[i] = c
				continue
			}
		} else if n == "id" && !declared["id"] && !idTaken {
			c.ID, idTaken = true, true
			c.Note = "names each record"
			cols[i] = c
			continue
		}
		if field == "" && opts.Type != nil {
			switch {
			case byNorm[n] != "":
				field = byNorm[n]
			case labels[n] != "":
				field, how = labels[n], "by its label"
			default:
				for _, a := range alike[n] {
					if declared[a] {
						field, how = a, "a name other platforms give it"
						break
					}
				}
			}
		}
		if field == "" && opts.Type == nil && reFieldName.MatchString(n) {
			field = n
		}
		switch {
		case field == "":
			if opts.Type != nil {
				c.Note = "left out: no field of " + opts.Type.Name + " is called this"
			} else {
				c.Note = "left out: it cannot be a field's name"
			}
		case opts.Type != nil && !declared[field]:
			c.Note = "left out: " + opts.Type.Name + " has no field " + field
		case opts.Type == nil && !reFieldName.MatchString(field):
			c.Note = "left out: " + field + " cannot be a field's name"
		case taken[field] > 0:
			c.Note = fmt.Sprintf("left out: column %d already fills %s", taken[field], field)
		default:
			c.Field, c.Note = field, how
			taken[field] = i + 1
		}
		cols[i] = c
	}
	return cols
}
