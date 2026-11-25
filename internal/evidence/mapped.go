// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sheet"
	"github.com/quilzo/quilzo/internal/xlsx"
)

// The generic mapped importer: a table, as CSV, a workbook or a JSON list,
// read into one kind of record through a column map a person confirmed.
//
// It is how another GRC tool's export comes in, and a person's own list of
// laptops, and anything else that is rows: the map says which column each
// field of the record is read from, and the person who confirmed it saw
// what it reads from a sample first. A map that names the tool whose export
// it reads makes its facts "imported"; one that does not, "uploaded".
//
// A row that cannot be made into a record is named, and nothing is written:
// a partial import is a register that is wrong without saying so. A blank
// cell is no value, and a fact with no value is not a fact. A formula's
// result is read as the result the saving program cached, never worked out
// here, and is marked as a formula's; a CSV cell a spreadsheet would run as
// a formula is marked the same.

const (
	maxColumns = 1_000
	maxCell    = 32 << 10
)

func init() {
	readers[FormatCSV] = readMapped
	readers[FormatXLSX] = readMapped
	readers[FormatJSON] = readMapped
}

// cell is one value of a table, where it was, and what was hidden about it.
type cell struct {
	text   string
	value  register.Scalar
	place  string
	taint  register.Taint
	isDate bool
	date   time.Time
}

// table is the rows of a file under its headings.
type table struct {
	headings []string
	rows     []tableRow
}

type tableRow struct {
	place string // where the row is: a row number, a JSON pointer
	cells map[string]cell
}

func readMapped(rd *reader) error {
	m := rd.in.Map
	var (
		t   *table
		err error
	)
	switch rd.in.Format {
	case FormatCSV:
		t, err = csvTable(rd.in.Body, int(m.Header))
	case FormatXLSX:
		t, err = xlsxTable(rd, rd.in.Body, m.Sheet, int(m.Header))
	case FormatJSON:
		t, err = jsonTable(rd.in.Body, m.Rows, mapColumns(m))
	}
	if err != nil {
		return err
	}
	for _, c := range m.Columns {
		if c.Column != "" && !contains(t.headings, c.Column) {
			return fmt.Errorf("%w: the map reads the column %q, which the file does not have", ErrUnreadable, label(c.Column))
		}
		if c.Name != "" && !contains(t.headings, c.Name) {
			return fmt.Errorf("%w: the map reads names from the column %q, which the file does not have", ErrUnreadable, label(c.Name))
		}
	}
	for _, f := range m.Facts {
		if !contains(t.headings, f.Column) {
			return fmt.Errorf("%w: the map reads the fact %s from the column %q, which the file does not have", ErrUnreadable, f.Fact, label(f.Column))
		}
	}
	spec, _ := register.SpecOf(m.Makes)
	for _, row := range t.rows {
		if spec.Kind == register.KindObservation {
			err = rd.observationRow(m, row)
		} else {
			err = rd.recordRow(m, spec, row)
		}
		if err != nil {
			return err
		}
	}
	if len(t.rows) == 0 {
		rd.note("the table has headings and no rows")
	}
	return nil
}

// mapColumns is every column a map reads.
func mapColumns(m *register.ColumnMap) []string {
	var out []string
	for _, c := range m.Columns {
		out = append(out, c.Column, c.Name)
	}
	for _, f := range m.Facts {
		out = append(out, f.Column)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// pointsAt is the identifier a column's value stands for: an asset the
// source reports by it, a record whose natural key it is, or an identifier
// already.
func (rd *reader) pointsAt(c register.MapColumn, row tableRow) (register.ID, register.Taint, bool, error) {
	v, ok := row.cells[c.Column]
	if !ok || v.text == "" {
		return "", "", false, nil
	}
	switch {
	case c.Asset != "":
		name := ""
		if c.Name != "" {
			name = row.cells[c.Name].text
		}
		id, err := rd.asset(c.Asset, v.text, name, v.place)
		return id, firstTaint(v.taint, row.cells[c.Name].taint), true, err
	case c.Of != "":
		spec, _ := register.SpecOf(c.Of)
		id, err := register.DeriveID(spec.Kind, register.Local, strings.TrimSpace(v.text))
		return id, v.taint, true, err
	case c.ID:
		id := register.ID(strings.ToLower(strings.TrimSpace(v.text)))
		if !id.Valid() {
			return "", "", false, fmt.Errorf("%w: at %s, %q is not a register identifier", ErrUnreadable, v.place, label(v.text))
		}
		return id, v.taint, true, nil
	}
	return "", "", false, nil
}

// observationRow is a row of facts about one thing: the about column names
// the thing, and each fact the map names is a column of its value.
func (rd *reader) observationRow(m *register.ColumnMap, row tableRow) error {
	var about register.ID
	var aboutTaint register.Taint
	found := false
	for _, c := range m.Columns {
		if c.Field != "about" {
			continue
		}
		var err error
		if c.Value != "" {
			about, found = register.ID(c.Value), true
			continue
		}
		about, aboutTaint, found, err = rd.pointsAt(c, row)
		if err != nil {
			return err
		}
	}
	if !found {
		if m.Columns == nil || !hasField(m, "about") {
			return fmt.Errorf("%w: a map of observations says which column names what the facts are about", ErrUnreadable)
		}
		return nil // a row that names nothing holds no facts
	}
	for _, f := range m.Facts {
		v, ok := row.cells[f.Column]
		if !ok || v.text == "" {
			continue
		}
		if err := rd.observe(about, f.Fact, v.value, v.place, firstTaint(v.taint, aboutTaint)); err != nil {
			return err
		}
	}
	return nil
}

func hasField(m *register.ColumnMap, field string) bool {
	for _, c := range m.Columns {
		if c.Field == field {
			return true
		}
	}
	return false
}

// recordRow is a row as one record of the map's kind: each field read from
// its column as the kind's schema types it, and the importer's own fields
// (the source, the grade, the raw digest, the place and the taint) set by
// the importer wherever the kind has them.
func (rd *reader) recordRow(m *register.ColumnMap, spec register.Spec, row tableRow) error {
	fields := map[string]register.Field{}
	for _, f := range spec.Fields {
		fields[f.Name] = f
	}
	fieldsOf := map[string]any{}
	var taint register.Taint
	read := false
	for _, c := range m.Columns {
		f := fields[c.Field]
		if c.Value != "" {
			v, err := typed(f, cell{text: c.Value, value: scalarOf(c.Value)})
			if err != nil {
				return fmt.Errorf("%w: the map's value for %s: %v", ErrUnreadable, c.Field, err)
			}
			fieldsOf[c.Field] = v
			continue
		}
		if c.Asset != "" || c.Of != "" || c.ID {
			id, t, ok, err := rd.pointsAt(c, row)
			if err != nil {
				return err
			}
			if ok {
				fieldsOf[c.Field], taint, read = string(id), firstTaint(taint, t), true
			}
			continue
		}
		v, ok := row.cells[c.Column]
		if !ok || v.text == "" {
			continue
		}
		val, err := typed(f, v)
		if err != nil {
			return fmt.Errorf("%w: at %s, the %s: %v", ErrUnreadable, v.place, c.Field, err)
		}
		fieldsOf[c.Field], taint, read = val, firstTaint(taint, v.taint), true
	}
	if !read {
		return nil // an empty row is no record
	}
	for name, f := range fields {
		switch {
		case name == "attested" && f.Ref == register.KindSubject && fieldsOf["run"] == nil:
			// A statement is the person's who brought the file.
			if rd.in.Subject == "" {
				return fmt.Errorf("%w: at %s, the record is a statement, which is the person's who brings the file, "+
					"and this surface does not know their pseudonym", ErrUnreadable, row.place)
			}
			fieldsOf[name], rd.stated = string(rd.in.Subject), rd.in.Subject
		case name == "source" && f.Ref == register.KindSource:
			fieldsOf[name] = string(rd.source)
		case name == "grade" && f.Type == "enum":
			fieldsOf[name] = string(rd.grade)
		case name == "raw" && f.Type == "digest":
			fieldsOf[name] = string(rd.digest)
		case name == "place" && f.Type == "label":
			fieldsOf[name] = label(row.place)
		case name == "taint" && taint != "":
			fieldsOf[name] = string(taint)
		}
	}
	b, _ := json.Marshal(fieldsOf)
	ptr := spec.New()
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(ptr); err != nil {
		return fmt.Errorf("%w: at %s: %v", ErrUnreadable, row.place, err)
	}
	rec := derefRecord(ptr)
	if rec == nil {
		return fmt.Errorf("%w: a %s cannot be made from a table", ErrUnreadable, spec.Kind)
	}
	_, err := rd.add(rec, row.place, taint, register.Label(rec), "")
	return err
}

// typed is a cell as the value a field of the given type takes in JSON.
func typed(f register.Field, c cell) (any, error) {
	switch strings.TrimPrefix(f.Type, "list of ") {
	case "time":
		t, err := timeOf(c)
		if err != nil {
			return nil, err
		}
		return t.Unix(), nil
	case "integer":
		n, err := strconv.ParseInt(strings.TrimSpace(c.text), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a whole number", label(c.text))
		}
		return n, nil
	case "number":
		n, err := strconv.ParseFloat(strings.TrimSpace(c.text), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("%q is not a number", label(c.text))
		}
		return n, nil
	case "boolean":
		switch strings.ToLower(strings.TrimSpace(c.text)) {
		case "true", "yes", "1":
			return true, nil
		case "false", "no", "0":
			return false, nil
		}
		return nil, fmt.Errorf("%q is not true or false", label(c.text))
	case "scalar":
		return c.value.Value(), nil
	case "object":
		return nil, fmt.Errorf("an object is not read from one cell")
	}
	if strings.HasPrefix(f.Type, "list of ") {
		var out []string
		for _, part := range strings.Split(c.text, ";") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, label(p))
			}
		}
		return out, nil
	}
	return label(c.text), nil
}

// timeOf is a cell as a moment: a workbook's date as it was saved, or text
// in one of the few ways a date is written in an export.
func timeOf(c cell) (time.Time, error) {
	if c.isDate {
		return c.date, nil
	}
	s := strings.TrimSpace(c.text)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 && n < 1<<35 {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%q is not a date written as 2006-01-02 or RFC 3339", label(s))
}

// derefRecord is the record a pointer from Spec.New points at.
func derefRecord(ptr any) register.Record {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil
	}
	rec, _ := v.Elem().Interface().(register.Record)
	return rec
}

// colName is a column's letters, as a spreadsheet names it: 1 is A, 27 AA.
func colName(c int) string {
	var b []byte
	for c > 0 {
		c--
		b = append([]byte{byte('A' + c%26)}, b...)
		c /= 26
	}
	return string(b)
}

func firstTaint(ts ...register.Taint) register.Taint {
	best := register.Taint("")
	order := register.Taint("").Values()
	rank := func(t register.Taint) int {
		for i, v := range order {
			if v == string(t) {
				return i
			}
		}
		return len(order)
	}
	for _, t := range ts {
		if t != "" && (best == "" || rank(t) < rank(best)) {
			best = t
		}
	}
	return best
}

// csvTable reads a CSV under the headings on its header row.
func csvTable(b []byte, header int) (*table, error) {
	if header < 1 {
		header = 1
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: it is not UTF-8 text", ErrUnreadable)
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	t := &table{}
	line := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
		}
		line++
		if len(rec) > maxColumns {
			return nil, fmt.Errorf("%w: row %d has %d columns, and the most read is %d", ErrUnreadable, line, len(rec), maxColumns)
		}
		if line < header {
			continue
		}
		if line == header {
			t.headings = headings(rec)
			continue
		}
		if len(t.rows) >= MaxRecords {
			return nil, fmt.Errorf("%w: it has more than %d rows", ErrUnreadable, MaxRecords)
		}
		row := tableRow{place: "row " + strconv.Itoa(line), cells: map[string]cell{}}
		for i, v := range rec {
			if i >= len(t.headings) || t.headings[i] == "" {
				continue
			}
			if len(v) > maxCell {
				return nil, fmt.Errorf("%w: a cell in row %d is longer than %d bytes", ErrUnreadable, line, maxCell)
			}
			c := cell{text: strings.TrimSpace(v), place: colName(i+1) + strconv.Itoa(line)}
			c.value = scalarOf(c.text)
			if sheet.IsFormula(v) || sheet.IsFormula(c.text) {
				// A spreadsheet would run it; nothing here does, and the
				// value is marked as one a person reading it did not see.
				// It is the cell as it is kept, without the spaces it
				// began with, that a spreadsheet would run later.
				c.taint, c.value = register.Taint(xlsx.Formula), register.TextValue(label(c.text))
			}
			row.cells[t.headings[i]] = c
		}
		t.rows = append(t.rows, row)
	}
	if t.headings == nil {
		return nil, fmt.Errorf("%w: it has no row %d to read the headings from", ErrUnreadable, header)
	}
	return t, nil
}

// headings are a header row's cells as column names, each a label, with a
// heading given twice refused by its second being dropped: a column map
// names a column by its heading, and two of one name are not two columns.
func headings(rec []string) []string {
	seen := map[string]bool{}
	out := make([]string, len(rec))
	for i, h := range rec {
		h = label(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out[i] = h
	}
	return out
}

// xlsxTable reads a worksheet under the headings on its header row, with
// what was hidden about each cell.
func xlsxTable(rd *reader, b []byte, sheetName string, header int) (*table, error) {
	if header < 1 {
		header = 1
	}
	wb, err := xlsx.Read(b, xlsx.Limits{File: MaxFile, Rows: MaxRecords + header})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	for _, f := range wb.Flags {
		rd.flag(register.Taint(f.Taint), f.Where)
	}
	if len(wb.Links) > 0 {
		rd.note("the workbook names %d link(s) to other files, none of which was followed", len(wb.Links))
	}
	if wb.Macros {
		rd.note("the workbook carries a macro project, which was not run")
	}
	var sh *xlsx.Sheet
	for _, s := range wb.Sheets {
		if sheetName == "" && s.State == "visible" || s.Name == sheetName {
			sh = s
			break
		}
	}
	if sh == nil {
		if sheetName == "" {
			return nil, fmt.Errorf("%w: the workbook has no sheet a person would see", ErrUnreadable)
		}
		return nil, fmt.Errorf("%w: the workbook has no sheet called %q", ErrUnreadable, label(sheetName))
	}
	t := &table{}
	byCol := map[int]string{}
	for _, row := range sh.Rows {
		if row.N < header {
			continue
		}
		if row.N == header {
			var hs []string
			maxCol := 0
			for _, c := range row.Cells {
				maxCol = max(maxCol, c.Col)
			}
			if maxCol > maxColumns {
				return nil, fmt.Errorf("%w: the header row has %d columns, and the most read is %d", ErrUnreadable, maxCol, maxColumns)
			}
			hs = make([]string, maxCol)
			for _, c := range row.Cells {
				hs[c.Col-1] = c.Text
			}
			t.headings = headings(hs)
			for i, h := range t.headings {
				if h != "" {
					byCol[i+1] = h
				}
			}
			continue
		}
		tr := tableRow{place: sh.Name + "!" + strconv.Itoa(row.N), cells: map[string]cell{}}
		for _, c := range row.Cells {
			h, ok := byCol[c.Col]
			if !ok {
				continue
			}
			if len(c.Text) > maxCell {
				return nil, fmt.Errorf("%w: the cell %s!%s is longer than %d bytes", ErrUnreadable, sh.Name, c.Ref, maxCell)
			}
			v := cell{text: strings.TrimSpace(c.Text), place: sh.Name + "!" + c.Ref}
			switch c.Kind {
			case xlsx.Bool:
				v.value = register.BoolValue(c.Text == "TRUE")
			case xlsx.Number:
				v.value = register.NumberValue(c.Number)
			case xlsx.Date:
				v.value, v.isDate, v.date = register.TextValue(c.Text), true, c.Date
			default:
				v.value = register.TextValue(label(c.Text))
			}
			var ts []register.Taint
			for _, tt := range c.Taints {
				ts = append(ts, register.Taint(tt))
			}
			v.taint = firstTaint(ts...)
			tr.cells[h] = v
		}
		t.rows = append(t.rows, tr)
	}
	if t.headings == nil {
		return nil, fmt.Errorf("%w: the sheet %q has no row %d to read the headings from", ErrUnreadable, label(sh.Name), header)
	}
	return t, nil
}

// jsonTable reads a JSON list of objects, at a pointer, as rows whose
// columns are the objects' keys. A column the map names with a JSON
// pointer, beginning with a slash, is read at that pointer in each object.
func jsonTable(b []byte, rows string, wanted []string) (*table, error) {
	var v any
	if err := decodeJSON(b, &v); err != nil {
		return nil, err
	}
	list, ok := pointer(v, rows)
	if !ok {
		return nil, fmt.Errorf("%w: the file has nothing at %q", ErrUnreadable, label(rows))
	}
	items := arr(list)
	if items == nil {
		return nil, fmt.Errorf("%w: what is at %q is not a list", ErrUnreadable, label(rows))
	}
	if len(items) > MaxRecords {
		return nil, fmt.Errorf("%w: it lists more than %d records", ErrUnreadable, MaxRecords)
	}
	t := &table{}
	seen := map[string]bool{}
	for _, w := range wanted {
		if strings.HasPrefix(w, "/") && !seen[w] {
			seen[w] = true
			t.headings = append(t.headings, w)
		}
	}
	for i, item := range items {
		o := obj(item)
		place := rows + "/" + strconv.Itoa(i)
		if o == nil {
			return nil, fmt.Errorf("%w: %s is not an object", ErrUnreadable, place)
		}
		row := tableRow{place: place, cells: map[string]cell{}}
		// Two keys that are one heading once each is a label would be read
		// in whichever order the object was walked, which is not the same
		// twice, and one of them can be a key nobody reading the file
		// would tell from the other.
		keyOf := map[string]string{}
		for k, val := range o {
			ok, text, native := scalarJSON(val)
			if !ok {
				continue
			}
			h := label(k)
			if was, twice := keyOf[h]; twice {
				a, b := was, k
				if b < a {
					a, b = b, a
				}
				return nil, fmt.Errorf("%w: %s gives the keys %q and %q, which read as the one column %q", ErrUnreadable,
					place, plaintext.Clip(a, 60, "…"), plaintext.Clip(b, 60, "…"), h)
			}
			keyOf[h] = k
			if !seen[h] {
				seen[h] = true
				t.headings = append(t.headings, h)
			}
			row.cells[h] = jsonCell(text, native, place+"/"+escapeToken(k))
		}
		for _, w := range wanted {
			if !strings.HasPrefix(w, "/") {
				continue
			}
			if val, found := pointer(o, w); found {
				if ok, text, native := scalarJSON(val); ok {
					row.cells[w] = jsonCell(text, native, place+w)
				}
			}
		}
		t.rows = append(t.rows, row)
	}
	sort.Strings(t.headings)
	return t, nil
}

func jsonCell(text string, native any, place string) cell {
	c := cell{text: strings.TrimSpace(text), place: place}
	switch n := native.(type) {
	case bool:
		c.value = register.BoolValue(n)
	case float64:
		c.value = register.NumberValue(n)
	default:
		c.value = register.TextValue(label(text))
	}
	return c
}

// Draft is a column map drafted from a table's headings, for a person to
// look at, change and confirm, with the first rows it would read. It is
// never used as it is: an import reads only a map in the register.
type Draft struct {
	Map      register.ColumnMap `json:"map"`
	Headings []string           `json:"headings"`
	// Sample is the first rows, as text, under the headings.
	Sample [][]string `json:"sample"`
	// Unmapped is the headings the draft reads nothing from.
	Unmapped []string `json:"unmapped,omitempty"`
}

// DraftMap drafts a column map for reading a table into a kind: each
// heading that is a field's name read into that field, and for
// observations the first heading that names a thing (a serial, a host, an
// identifier) as what the facts are about, and every other heading as a
// fact. What it guesses is a guess, and says so by being a draft.
func DraftMap(f Format, body []byte, kind, name, sheetName string) (*Draft, error) {
	if !f.mapped() {
		return nil, fmt.Errorf("%w: only a table is read through a column map, and %s is not one", ErrUnreadable, f)
	}
	spec, ok := register.SpecOf(kind)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a kind the register has", ErrUnreadable, label(kind))
	}
	if name == "" {
		name = slug(string(spec.Kind) + "-" + string(f))
	}
	rd := &reader{in: Input{Format: f, Body: body}, records: map[register.ID]*held{}}
	var (
		t   *table
		err error
	)
	switch f {
	case FormatCSV:
		t, err = csvTable(body, 1)
	case FormatXLSX:
		t, err = xlsxTable(rd, body, sheetName, 1)
	case FormatJSON:
		t, err = jsonTable(body, "", nil)
	}
	if err != nil {
		return nil, err
	}
	m := register.ColumnMap{Name: slug(name), Makes: string(spec.Kind), Format: register.MapFormat(f), Sheet: sheetName}
	d := &Draft{}
	for _, h := range t.headings {
		if h != "" {
			d.Headings = append(d.Headings, h)
		}
	}
	used := map[string]bool{}
	if spec.Kind == register.KindObservation {
		for _, h := range d.Headings {
			n := norm(h)
			if strings.Contains(n, "serial") || strings.Contains(n, "host") || strings.Contains(n, "device") ||
				n == "id" || strings.HasSuffix(n, "id") || strings.Contains(n, "asset") {
				typ := register.AssetType("other")
				if strings.Contains(n, "serial") || strings.Contains(n, "host") || strings.Contains(n, "device") {
					typ = "device"
				}
				m.Columns = append(m.Columns, register.MapColumn{Field: "about", Column: h, Asset: typ})
				used[h] = true
				break
			}
		}
		if len(m.Columns) == 0 && len(d.Headings) > 0 {
			m.Columns = append(m.Columns, register.MapColumn{Field: "about", Column: d.Headings[0], Asset: "other"})
			used[d.Headings[0]] = true
		}
		for _, h := range d.Headings {
			if !used[h] {
				m.Facts = append(m.Facts, register.MapFact{Fact: slug(h), Column: h})
				used[h] = true
			}
		}
	} else {
		byNorm := map[string]register.Field{}
		for _, fl := range spec.Fields {
			switch fl.Name {
			case "grade", "raw", "place", "taint", "attested":
				continue
			}
			if fl.Name == "source" && fl.Ref == register.KindSource {
				continue
			}
			byNorm[norm(fl.Name)] = fl
		}
		for _, h := range d.Headings {
			fl, ok := byNorm[norm(h)]
			if !ok || used[fl.Name] {
				continue
			}
			c := register.MapColumn{Field: fl.Name, Column: h}
			if fl.Type == "id" && fl.Ref != "" {
				c.Of = string(fl.Ref)
			}
			m.Columns = append(m.Columns, c)
			used[fl.Name], used[h] = true, true
		}
	}
	for _, h := range d.Headings {
		if !used[h] {
			d.Unmapped = append(d.Unmapped, h)
		}
	}
	for i, row := range t.rows {
		if i == 5 {
			break
		}
		line := make([]string, len(d.Headings))
		for j, h := range d.Headings {
			line[j] = label(row.cells[h].text)
		}
		d.Sample = append(d.Sample, line)
	}
	d.Map = m
	return d, nil
}

// norm is a heading or a field's name with only its letters and digits,
// in lower case, for matching one with the other.
func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
