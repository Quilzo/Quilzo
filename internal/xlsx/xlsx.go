// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package xlsx reads a workbook saved by Excel, LibreOffice, Numbers or
// Google Sheets, with the standard library's zip and XML readers and
// nothing else, and says what in it a person opening it would not see.
//
// A workbook is the form most evidence arrives in that nobody exported on
// purpose: a questionnaire somebody filled in, a list of laptops, a
// vendor's answers. It is also a file somebody else made, and a workbook is
// a good place to hide things. So this reads it as hostile:
//
//   - The zip is held to limits before anything is expanded: the file's
//     size, how many entries it has, how large each part may grow and how
//     far out of proportion to its compressed size (a zip bomb is a few
//     kilobytes that would be gigabytes), and the whole of what is read.
//     Two parts of one name are refused, because two readers would read
//     different ones.
//   - No part may declare a document type, which is how an XML bomb is
//     made and which no workbook needs, and none may nest deeper than any
//     real workbook does.
//   - A formula is never worked out. Its text is kept, and so is the result
//     the program that saved the file cached beside it, marked as a
//     formula's: a cached result is whatever that program, or whoever
//     edited the file after it, wrote there.
//   - A link to another workbook, or a hyperlink, is named and never
//     followed. This package makes no network call, and a test fails the
//     moment a read would.
//   - What is hidden is read and marked (tainted) wherever it is used, and
//     listed: hidden and very hidden sheets, hidden rows and columns,
//     comments, defined names, formulas and links. A value from a hidden
//     row is not a value a person answered; a comment is where words meant
//     for a model are put.
//
// What a cell says is read the way the workbook says it: shared and inline
// strings, rich text as its runs, numbers as the text that was saved, dates
// in the workbook's own 1900 or 1904 system, merged ranges as their
// top-left value, and a list a cell is limited to (a data validation) as
// the cell's answer options.
package xlsx

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Limits bound what one read may cost. A zero field takes its default.
type Limits struct {
	// File is the largest a workbook may be, as received.
	File int64
	// Entries is how many parts the zip may hold.
	Entries int
	// Entry is the largest one part may expand to, and Total the most all
	// the parts read may expand to together.
	Entry, Total int64
	// Ratio is how many times its compressed size a part may expand to,
	// past the first megabyte. Text compresses well; a thousandfold is not
	// text, it is a bomb.
	Ratio int64
	// Rows and Columns bound one sheet: Excel's own limits.
	Rows, Columns int
	// Depth is how deep the elements of a part may nest.
	Depth int
}

// DefaultLimits are those a read takes for a zero field.
var DefaultLimits = Limits{File: 64 << 20, Entries: 10_000, Entry: 256 << 20, Total: 512 << 20, Ratio: 100,
	Rows: 1_048_576, Columns: 16_384, Depth: 64}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	if l.File > 0 {
		d.File = l.File
	}
	if l.Entries > 0 {
		d.Entries = l.Entries
	}
	if l.Entry > 0 {
		d.Entry = l.Entry
	}
	if l.Total > 0 {
		d.Total = l.Total
	}
	if l.Ratio > 0 {
		d.Ratio = l.Ratio
	}
	if l.Rows > 0 {
		d.Rows = l.Rows
	}
	if l.Columns > 0 {
		d.Columns = l.Columns
	}
	if l.Depth > 0 {
		d.Depth = l.Depth
	}
	return d
}

// Taint is why a cell's value is not one a person opening the workbook
// would have seen as written. The names are the register's (register.Taint).
type Taint string

const (
	HiddenSheet  Taint = "hidden-sheet"
	HiddenRow    Taint = "hidden-row"
	HiddenColumn Taint = "hidden-column"
	Comment      Taint = "comment"
	Formula      Taint = "formula"
	DefinedName  Taint = "defined-name"
	ExternalLink Taint = "external-link"
)

// taintOrder is the order a cell's taints are listed in.
var taintOrder = []Taint{HiddenSheet, HiddenRow, HiddenColumn, Comment, Formula, DefinedName, ExternalLink}

// Kind is what sort of value a cell holds.
type Kind string

const (
	Empty  Kind = ""
	String Kind = "string"
	Number Kind = "number"
	Bool   Kind = "bool"
	Date   Kind = "date"
	Error  Kind = "error"
)

// Cell is one cell, as the workbook holds it.
type Cell struct {
	// Ref is the cell's reference, B12, and Col and Row its column and
	// row, counted from one.
	Ref      string
	Col, Row int
	Kind     Kind
	// Text is the value as a person reads it: the string, the number as it
	// was saved, TRUE or FALSE, a date as ISO 8601, an error's code.
	Text   string
	Number float64
	Date   time.Time
	// Formula is a formula's text, never worked out; Text is then the
	// result the saving program cached.
	Formula string
	// Comment is the words of a comment on the cell.
	Comment string
	// Merged says the value is its merged range's top-left cell's.
	Merged bool
	// Options are the answers a list validation limits the cell to.
	Options []string
	Taints  []Taint
}

// Row is one row that holds cells.
type Row struct {
	N      int
	Hidden bool
	Cells  []Cell
}

// Validation is a rule limiting what cells may hold. Options are a list
// rule's answers when the rule gives them itself; a list drawn from other
// cells keeps its formula in Source.
type Validation struct {
	Type    string
	Ranges  []string
	Options []string
	Source  string
}

// Sheet is one worksheet.
type Sheet struct {
	Name string
	// State is visible, hidden or veryHidden.
	State       string
	Rows        []Row
	Merged      []string
	Validations []Validation
}

// Flag is one thing a person opening the workbook would not see, said once
// for the workbook: what, and where.
type Flag struct {
	Taint Taint
	Where string
}

// Workbook is what was read.
type Workbook struct {
	Sheets   []*Sheet
	Date1904 bool
	// Names are its defined names, each with what it refers to.
	Names map[string]string
	// Links are the addresses its external links and hyperlinks name.
	// None was followed.
	Links []string
	// Macros says it carries a macro project, which is never run.
	Macros bool
	Flags  []Flag
}

// Read reads a workbook from its bytes.
func Read(b []byte, lim Limits) (*Workbook, error) {
	lim = lim.withDefaults()
	if int64(len(b)) > lim.File {
		return nil, fmt.Errorf("the workbook is %d bytes and the most read is %d", len(b), lim.File)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("this is not a workbook: %w", err)
	}
	if len(zr.File) > lim.Entries {
		return nil, fmt.Errorf("the workbook has %d entries and the most read is %d", len(zr.File), lim.Entries)
	}
	pk := &pkg{lim: lim, files: map[string]*zip.File{}}
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, "/")
		if _, dup := pk.files[name]; dup {
			return nil, fmt.Errorf("the workbook holds the part %q twice, and two readers would read different ones", clip(name))
		}
		pk.files[name] = f
	}
	return pk.workbook()
}

// pkg is the zip, read a part at a time under the limits.
type pkg struct {
	lim   Limits
	files map[string]*zip.File
	read  int64
}

// part is one part's bytes, or nil when the workbook does not have it.
func (p *pkg) part(name string) ([]byte, error) {
	f, ok := p.files[name]
	if !ok {
		return nil, nil
	}
	size := int64(f.UncompressedSize64)
	if f.UncompressedSize64 > uint64(p.lim.Entry) {
		return nil, fmt.Errorf("the part %s would be larger than %d bytes", clip(name), p.lim.Entry)
	}
	if size > 1<<20 && f.CompressedSize64 > 0 && size/int64(f.CompressedSize64) > p.lim.Ratio {
		return nil, fmt.Errorf("the part %s would expand %d times over, which is a zip bomb and not a workbook",
			clip(name), size/int64(f.CompressedSize64))
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("the part %s cannot be read: %w", clip(name), err)
	}
	defer rc.Close()
	// The sizes in the zip's directory are what the file says of itself;
	// what is read is held to the limits whatever they say.
	room := min(p.lim.Entry, p.lim.Total-p.read)
	out, err := io.ReadAll(io.LimitReader(rc, room+1))
	if err != nil {
		return nil, fmt.Errorf("the part %s cannot be read: %w", clip(name), err)
	}
	if int64(len(out)) > room {
		if int64(len(out)) > p.lim.Entry {
			return nil, fmt.Errorf("the part %s is larger than %d bytes", clip(name), p.lim.Entry)
		}
		return nil, fmt.Errorf("the workbook's parts together are larger than %d bytes", p.lim.Total)
	}
	p.read += int64(len(out))
	return out, nil
}

// rel is one relationship of a part.
type rel struct {
	ID, Type, Target string
	External         bool
}

// rels reads a part's relationships, with targets resolved within the
// package. A target outside it is refused: no part of a workbook is
// anywhere but in the workbook.
func (p *pkg) rels(of string) (map[string]rel, error) {
	dir, file := path.Split(of)
	b, err := p.part(dir + "_rels/" + file + ".rels")
	if err != nil || b == nil {
		return map[string]rel{}, err
	}
	out := map[string]rel{}
	err = p.walk(b, of+".rels", func(d *xml.Decoder, se xml.StartElement) error {
		if se.Name.Local != "Relationship" {
			return nil
		}
		r := rel{ID: attr(se, "Id"), Type: attr(se, "Type"), Target: attr(se, "Target"), External: attr(se, "TargetMode") == "External"}
		if !r.External {
			t := r.Target
			if !strings.HasPrefix(t, "/") {
				t = path.Join(dir, t)
			}
			t = path.Clean(strings.TrimPrefix(t, "/"))
			if t == "." || strings.HasPrefix(t, "../") || t == ".." {
				return fmt.Errorf("the part %s points outside the workbook", clip(of))
			}
			r.Target = t
		}
		out[r.ID] = r
		return nil
	})
	return out, err
}

func (p *pkg) workbook() (*Workbook, error) {
	const wbPart = "xl/workbook.xml"
	b, err := p.part(wbPart)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("this is a zip with no workbook in it (no xl/workbook.xml)")
	}
	wb := &Workbook{Names: map[string]string{}}
	type sheetRef struct{ name, state, rid string }
	var sheets []sheetRef
	var names []string
	err = p.walk(b, wbPart, func(d *xml.Decoder, se xml.StartElement) error {
		switch se.Name.Local {
		case "workbookPr":
			v := attr(se, "date1904")
			wb.Date1904 = v == "1" || v == "true"
		case "sheet":
			state := attr(se, "state")
			if state == "" {
				state = "visible"
			}
			sheets = append(sheets, sheetRef{name: attr(se, "name"), state: state, rid: rid(se)})
		case "definedName":
			text, err := innerText(d, p.lim.Depth)
			if err != nil {
				return err
			}
			name := attr(se, "name")
			wb.Names[name] = text
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rels, err := p.rels(wbPart)
	if err != nil {
		return nil, err
	}
	for _, r := range sortedRels(rels) {
		if strings.HasSuffix(r.Type, "/externalLink") {
			links, err := p.rels(r.Target)
			if err != nil {
				return nil, err
			}
			for _, l := range sortedRels(links) {
				wb.Links = append(wb.Links, l.Target)
				wb.Flags = append(wb.Flags, Flag{Taint: ExternalLink, Where: l.Target})
			}
		}
	}
	if _, ok := p.files["xl/vbaProject.bin"]; ok {
		wb.Macros = true
	}
	shared, err := p.sharedStrings()
	if err != nil {
		return nil, err
	}
	dates, err := p.dateStyles()
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		wb.Flags = append(wb.Flags, Flag{Taint: DefinedName, Where: n})
	}
	named := namedCells(wb.Names)
	for _, sr := range sheets {
		r, ok := rels[sr.rid]
		if !ok || r.External {
			return nil, fmt.Errorf("the sheet %q has no part in the workbook", clip(sr.name))
		}
		sh := &Sheet{Name: sr.name, State: sr.state}
		if sr.state != "visible" {
			wb.Flags = append(wb.Flags, Flag{Taint: HiddenSheet, Where: sr.name})
		}
		if err := p.sheet(r.Target, sh, wb, shared, dates, named[sr.name]); err != nil {
			return nil, err
		}
		wb.Sheets = append(wb.Sheets, sh)
	}
	return wb, nil
}

func sortedRels(m map[string]rel) []rel {
	out := make([]rel, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// sharedStrings is the workbook's table of strings: each item's text, its
// runs joined, without the phonetic guide that is not part of it.
func (p *pkg) sharedStrings() ([]string, error) {
	const part = "xl/sharedStrings.xml"
	b, err := p.part(part)
	if err != nil || b == nil {
		return nil, err
	}
	var out []string
	err = p.walk(b, part, func(d *xml.Decoder, se xml.StartElement) error {
		if se.Name.Local != "si" {
			return nil
		}
		s, err := stringItem(d, p.lim.Depth)
		if err != nil {
			return err
		}
		out = append(out, s)
		return nil
	})
	return out, err
}

// stringItem reads an si or an is element's text: its t elements, in any
// run, and not those inside a phonetic run (rPh).
func stringItem(d *xml.Decoder, depth int) (string, error) {
	var b strings.Builder
	level, inT, phonetic := 1, false, 0
	for level > 0 {
		tok, err := d.Token()
		if err != nil {
			return "", fmt.Errorf("a string cannot be read: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			level++
			if level > depth {
				return "", errTooDeep
			}
			switch t.Name.Local {
			case "rPh":
				phonetic = level
			case "t":
				inT = true
			}
		case xml.EndElement:
			if t.Name.Local == "t" {
				inT = false
			}
			if phonetic == level {
				phonetic = 0
			}
			level--
		case xml.CharData:
			if inT && phonetic == 0 {
				b.Write(t)
			}
		}
	}
	return b.String(), nil
}

// dateStyles is which cell styles show a number as a date or a time, by
// the style's index: the built-in date formats and any custom format whose
// code counts days, months, years, hours or seconds.
func (p *pkg) dateStyles() (map[int]bool, error) {
	const part = "xl/styles.xml"
	b, err := p.part(part)
	if err != nil || b == nil {
		return nil, err
	}
	custom := map[int]bool{}
	var xfs []int
	inXfs := false
	err = p.walkAll(b, part, func(tok xml.Token) error {
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "numFmt":
				id, _ := strconv.Atoi(attr(t, "numFmtId"))
				custom[id] = isDateFormat(attr(t, "formatCode"))
			case "cellXfs":
				inXfs = true
			case "xf":
				if inXfs {
					id, _ := strconv.Atoi(attr(t, "numFmtId"))
					xfs = append(xfs, id)
				}
			}
		case xml.EndElement:
			if t.Name.Local == "cellXfs" {
				inXfs = false
			}
		}
		return nil
	})
	out := map[int]bool{}
	for i, id := range xfs {
		if builtinDate(id) || custom[id] {
			out[i] = true
		}
	}
	return out, err
}

// builtinDate is the built-in number formats that are dates or times.
func builtinDate(id int) bool {
	return id >= 14 && id <= 22 || id >= 45 && id <= 47 || id >= 27 && id <= 36 || id >= 50 && id <= 58
}

// isDateFormat reports whether a format code shows a date or a time: it
// counts d, m, y, h or s outside quotes, brackets and escapes. A colour in
// brackets is not a date, and [h] is elapsed hours, which is.
func isDateFormat(code string) bool {
	inQuote := false
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '\\' || c == '_' || c == '*':
			i++
		case c == '[':
			end := strings.IndexByte(code[i:], ']')
			if end < 0 {
				return false
			}
			inner := strings.ToLower(code[i+1 : i+end])
			if inner == "h" || inner == "hh" || inner == "m" || inner == "mm" || inner == "s" || inner == "ss" {
				return true
			}
			i += end
		case strings.ContainsRune("dmyhsDMYHS", rune(c)):
			return true
		}
	}
	return false
}

// namedCells is the cells each sheet's defined names point at, by sheet
// and reference. A name Excel defines for itself (_xlnm., a print area, a
// filter) is listed in the flags and taints nothing: what it covers is
// what is shown.
func namedCells(names map[string]string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for name, ref := range names {
		if strings.HasPrefix(name, "_xlnm.") {
			continue
		}
		for _, part := range strings.Split(ref, ",") {
			sheet, rng, ok := strings.Cut(strings.TrimSpace(part), "!")
			if !ok {
				continue
			}
			sheet = strings.Trim(sheet, "'")
			rng = strings.ReplaceAll(rng, "$", "")
			lo, hi, ok := rangeOf(rng)
			if !ok || (hi.col-lo.col+1)*(hi.row-lo.row+1) > 100_000 {
				continue
			}
			if out[sheet] == nil {
				out[sheet] = map[string]bool{}
			}
			for r := lo.row; r <= hi.row; r++ {
				for c := lo.col; c <= hi.col; c++ {
					out[sheet][cellRef(c, r)] = true
				}
			}
		}
	}
	return out
}

func (p *pkg) sheet(part string, sh *Sheet, wb *Workbook, shared []string, dates map[int]bool, named map[string]bool) error {
	b, err := p.part(part)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("the sheet %q has no part in the workbook", clip(sh.Name))
	}
	rels, err := p.rels(part)
	if err != nil {
		return err
	}
	comments := map[string]string{}
	for _, r := range sortedRels(rels) {
		switch {
		case r.External:
			wb.Links = append(wb.Links, r.Target)
			wb.Flags = append(wb.Flags, Flag{Taint: ExternalLink, Where: r.Target})
		case strings.HasSuffix(r.Type, "/comments"):
			if err := p.comments(r.Target, comments); err != nil {
				return err
			}
		}
	}
	hiddenCols := map[int]bool{}
	var row *Row
	var cell *Cell
	inV, inF, inIs := false, false, false
	var v, f strings.Builder
	var cellType string
	var style int
	var validation *Validation
	inFormula1 := false
	var formula1 strings.Builder
	lastRow := 0

	finishCell := func() error {
		c := cell
		raw := v.String()
		c.Formula = f.String()
		switch cellType {
		case "s":
			i, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || i < 0 || i >= len(shared) {
				return fmt.Errorf("the cell %s!%s names a shared string the workbook does not have", clip(sh.Name), c.Ref)
			}
			c.Kind, c.Text = String, shared[i]
		case "inlineStr", "str":
			c.Kind, c.Text = String, raw
		case "b":
			c.Kind, c.Text = Bool, map[bool]string{true: "TRUE", false: "FALSE"}[strings.TrimSpace(raw) == "1"]
		case "e":
			c.Kind, c.Text = Error, raw
		case "d":
			c.Kind, c.Text = String, raw
		default:
			raw = strings.TrimSpace(raw)
			if raw == "" {
				break
			}
			n, err := strconv.ParseFloat(raw, 64)
			if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
				return fmt.Errorf("the cell %s!%s holds %q, which is not a number", clip(sh.Name), c.Ref, clip(raw))
			}
			c.Kind, c.Text, c.Number = Number, raw, n
			if dates[style] {
				if t, ok := serialDate(n, wb.Date1904); ok {
					c.Kind, c.Date = Date, t
					if t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 {
						c.Text = t.Format("2006-01-02")
					} else {
						c.Text = t.Format(time.RFC3339)
					}
				}
			}
		}
		if text, ok := comments[c.Ref]; ok {
			c.Comment = text
		}
		row.Cells = append(row.Cells, *c)
		cell = nil
		return nil
	}

	err = p.walkAll(b, part, func(tok xml.Token) error {
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "col":
				if attr(t, "hidden") == "1" || attr(t, "hidden") == "true" {
					lo, _ := strconv.Atoi(attr(t, "min"))
					hi, _ := strconv.Atoi(attr(t, "max"))
					if lo < 1 || hi < lo || hi > p.lim.Columns {
						return fmt.Errorf("the sheet %q hides columns that are not there", clip(sh.Name))
					}
					for c := lo; c <= hi; c++ {
						hiddenCols[c] = true
					}
				}
			case "row":
				n := lastRow + 1
				if s := attr(t, "r"); s != "" {
					var err error
					if n, err = strconv.Atoi(s); err != nil {
						return fmt.Errorf("the sheet %q has a row numbered %q", clip(sh.Name), clip(s))
					}
				}
				if n < 1 || n > p.lim.Rows || n <= lastRow {
					return fmt.Errorf("the sheet %q has a row numbered %d, out of order or beyond %d", clip(sh.Name), n, p.lim.Rows)
				}
				lastRow = n
				sh.Rows = append(sh.Rows, Row{N: n, Hidden: attr(t, "hidden") == "1" || attr(t, "hidden") == "true"})
				row = &sh.Rows[len(sh.Rows)-1]
			case "c":
				if row == nil {
					return fmt.Errorf("the sheet %q has a cell outside a row", clip(sh.Name))
				}
				ref := attr(t, "r")
				col, r := 0, row.N
				if ref == "" {
					col = len(row.Cells) + 1
					if len(row.Cells) > 0 {
						col = row.Cells[len(row.Cells)-1].Col + 1
					}
				} else {
					at, ok := parseRef(ref)
					if !ok || at.row != row.N {
						return fmt.Errorf("the sheet %q has a cell %q that is not in its row", clip(sh.Name), clip(ref))
					}
					col = at.col
				}
				if col < 1 || col > p.lim.Columns {
					return fmt.Errorf("the sheet %q has a cell beyond column %d", clip(sh.Name), p.lim.Columns)
				}
				if len(row.Cells) > 0 && row.Cells[len(row.Cells)-1].Col >= col {
					return fmt.Errorf("the sheet %q has cells out of order in row %d", clip(sh.Name), row.N)
				}
				cell = &Cell{Ref: cellRef(col, r), Col: col, Row: r}
				cellType = attr(t, "t")
				style, _ = strconv.Atoi(attr(t, "s"))
				v.Reset()
				f.Reset()
			case "v":
				inV = cell != nil
			case "f":
				inF = cell != nil
			case "is":
				inIs = cell != nil
			case "t":
				// An inline string's text; a rich one has runs.
			case "mergeCell":
				sh.Merged = append(sh.Merged, attr(t, "ref"))
			case "dataValidation":
				validation = &Validation{Type: attr(t, "type"), Ranges: strings.Fields(attr(t, "sqref"))}
			case "formula1":
				inFormula1 = validation != nil
				formula1.Reset()
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "v":
				inV = false
			case "f":
				inF = false
			case "is":
				inIs = false
			case "c":
				if cell != nil {
					if err := finishCell(); err != nil {
						return err
					}
				}
			case "row":
				row = nil
			case "formula1":
				inFormula1 = false
			case "dataValidation":
				if validation != nil {
					src := strings.TrimSpace(formula1.String())
					if validation.Type == "list" && strings.HasPrefix(src, `"`) && strings.HasSuffix(src, `"`) && len(src) >= 2 {
						for _, o := range strings.Split(src[1:len(src)-1], ",") {
							validation.Options = append(validation.Options, strings.TrimSpace(o))
						}
					} else {
						validation.Source = src
					}
					sh.Validations = append(sh.Validations, *validation)
					validation = nil
				}
			}
		case xml.CharData:
			switch {
			case inV, inIs:
				v.Write(t)
			case inF:
				f.Write(t)
			case inFormula1:
				formula1.Write(t)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := fillMerged(sh, p.lim); err != nil {
		return err
	}
	options := sheetOptions(sh)
	cols := make([]int, 0, len(hiddenCols))
	for c := range hiddenCols {
		cols = append(cols, c)
	}
	sort.Ints(cols)
	for _, c := range cols {
		wb.Flags = append(wb.Flags, Flag{Taint: HiddenColumn, Where: sh.Name + "!" + colName(c)})
	}
	for i := range sh.Rows {
		r := &sh.Rows[i]
		if r.Hidden {
			wb.Flags = append(wb.Flags, Flag{Taint: HiddenRow, Where: sh.Name + "!" + strconv.Itoa(r.N)})
		}
		for j := range r.Cells {
			c := &r.Cells[j]
			c.Options = options[c.Ref]
			has := map[Taint]bool{
				HiddenSheet:  sh.State != "visible",
				HiddenRow:    r.Hidden,
				HiddenColumn: hiddenCols[c.Col],
				Comment:      c.Comment != "",
				Formula:      c.Formula != "",
				DefinedName:  named[c.Ref],
				ExternalLink: externalRef(c.Formula),
			}
			for _, t := range taintOrder {
				if has[t] {
					c.Taints = append(c.Taints, t)
				}
			}
			if c.Comment != "" {
				wb.Flags = append(wb.Flags, Flag{Taint: Comment, Where: sh.Name + "!" + c.Ref})
			}
			if c.Formula != "" {
				wb.Flags = append(wb.Flags, Flag{Taint: Formula, Where: sh.Name + "!" + c.Ref})
			}
		}
	}
	return nil
}

// externalRef reports whether a formula reads another workbook: Excel
// writes such a reference with the link's number in brackets, [1]Sheet!A1.
func externalRef(formula string) bool {
	i := strings.IndexByte(formula, '[')
	if i < 0 {
		return false
	}
	j := strings.IndexByte(formula[i:], ']')
	if j < 2 {
		return false
	}
	_, err := strconv.Atoi(formula[i+1 : i+j])
	return err == nil
}

func (p *pkg) comments(part string, out map[string]string) error {
	b, err := p.part(part)
	if err != nil || b == nil {
		return err
	}
	return p.walk(b, part, func(d *xml.Decoder, se xml.StartElement) error {
		if se.Name.Local != "comment" {
			return nil
		}
		ref := attr(se, "ref")
		text, err := stringItem(d, p.lim.Depth)
		if err != nil {
			return err
		}
		out[ref] = strings.TrimSpace(text)
		return nil
	})
}

// fillMerged gives every cell of a merged range its top-left cell's value,
// marked as merged.
func fillMerged(sh *Sheet, lim Limits) error {
	if len(sh.Merged) == 0 {
		return nil
	}
	rows := map[int]*Row{}
	for i := range sh.Rows {
		rows[sh.Rows[i].N] = &sh.Rows[i]
	}
	var added []Row
	for _, m := range sh.Merged {
		lo, hi, ok := rangeOf(m)
		if !ok {
			return fmt.Errorf("the sheet %q merges %q, which is not a range", clip(sh.Name), clip(m))
		}
		if (hi.col-lo.col+1)*(hi.row-lo.row+1) > 100_000 || hi.row > lim.Rows || hi.col > lim.Columns {
			return fmt.Errorf("the sheet %q merges more cells than a sheet is read with", clip(sh.Name))
		}
		top := rows[lo.row]
		var src *Cell
		if top != nil {
			for i := range top.Cells {
				if top.Cells[i].Col == lo.col {
					src = &top.Cells[i]
				}
			}
		}
		if src == nil {
			continue
		}
		val := *src
		for r := lo.row; r <= hi.row; r++ {
			row := rows[r]
			if row == nil {
				added = append(added, Row{N: r})
				row = &added[len(added)-1]
				rows[r] = row
			}
			for c := lo.col; c <= hi.col; c++ {
				if r == lo.row && c == lo.col {
					continue
				}
				fill := val
				fill.Ref, fill.Col, fill.Row, fill.Merged, fill.Comment = cellRef(c, r), c, r, true, ""
				replaced := false
				for i := range row.Cells {
					if row.Cells[i].Col == c {
						row.Cells[i], replaced = fill, true
					}
				}
				if !replaced {
					row.Cells = append(row.Cells, fill)
				}
			}
			sort.Slice(row.Cells, func(i, j int) bool { return row.Cells[i].Col < row.Cells[j].Col })
		}
	}
	if len(added) > 0 {
		// Rows that held nothing and are covered by a merge; rows map
		// pointed into added, so they are copied in now.
		for _, r := range rows {
			found := false
			for i := range sh.Rows {
				if sh.Rows[i].N == r.N {
					found = true
				}
			}
			if !found {
				sh.Rows = append(sh.Rows, *r)
			}
		}
		sort.Slice(sh.Rows, func(i, j int) bool { return sh.Rows[i].N < sh.Rows[j].N })
	}
	return nil
}

// sheetOptions is the answer options of each cell a list validation with
// its own answers covers.
func sheetOptions(sh *Sheet) map[string][]string {
	out := map[string][]string{}
	for _, v := range sh.Validations {
		if len(v.Options) == 0 {
			continue
		}
		for _, rg := range v.Ranges {
			lo, hi, ok := rangeOf(rg)
			if !ok || (hi.col-lo.col+1)*(hi.row-lo.row+1) > 1_000_000 {
				continue
			}
			for _, r := range sh.Rows {
				if r.N < lo.row || r.N > hi.row {
					continue
				}
				for _, c := range r.Cells {
					if c.Col >= lo.col && c.Col <= hi.col {
						out[c.Ref] = v.Options
					}
				}
			}
		}
	}
	return out
}

// serialDate is a date serial as a moment, in the workbook's date system.
// The 1900 system counts the 29th of February 1900, which never was, as
// day 60; a serial of 60 is not a day, and is kept as a number.
func serialDate(n float64, from1904 bool) (time.Time, bool) {
	if n < 0 || n > 2_958_465 { // the 31st of December 9999
		return time.Time{}, false
	}
	days := math.Floor(n)
	secs := math.Round((n - days) * 86400)
	var epoch time.Time
	switch {
	case from1904:
		epoch = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC)
	case days == 60:
		return time.Time{}, false
	case days < 60:
		epoch = time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC)
	default:
		epoch = time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)
	}
	return epoch.AddDate(0, 0, int(days)).Add(time.Duration(secs) * time.Second), true
}

// at is a cell's place.
type at struct{ col, row int }

// parseRef reads a reference such as B12.
func parseRef(ref string) (at, bool) {
	i := 0
	col := 0
	for i < len(ref) && ref[i] >= 'A' && ref[i] <= 'Z' {
		col = col*26 + int(ref[i]-'A'+1)
		i++
		if col > 1<<20 {
			return at{}, false
		}
	}
	if i == 0 || i == len(ref) {
		return at{}, false
	}
	row, err := strconv.Atoi(ref[i:])
	if err != nil || row < 1 || ref[i] == '0' || ref[i] == '+' || ref[i] == '-' {
		return at{}, false
	}
	return at{col: col, row: row}, true
}

// rangeOf reads A1:C3, or a single cell as a range of one.
func rangeOf(s string) (lo, hi at, ok bool) {
	a, b, two := strings.Cut(s, ":")
	if lo, ok = parseRef(a); !ok {
		return
	}
	hi = lo
	if two {
		if hi, ok = parseRef(b); !ok {
			return
		}
	}
	if hi.col < lo.col || hi.row < lo.row {
		return lo, hi, false
	}
	return lo, hi, true
}

// colName is a column's letters: 1 is A, 27 is AA.
func colName(c int) string {
	var b []byte
	for c > 0 {
		c--
		b = append([]byte{byte('A' + c%26)}, b...)
		c /= 26
	}
	return string(b)
}

func cellRef(col, row int) string { return colName(col) + strconv.Itoa(row) }

var errTooDeep = errors.New("a part nests deeper than any workbook does")

// decoder is an XML decoder over one part that refuses a document type and
// counts how deep it is.
func (p *pkg) decoder(b []byte) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	return d
}

// walkAll hands every token of a part to fn, refusing a document type and
// nesting beyond the limit.
func (p *pkg) walkAll(b []byte, part string, fn func(xml.Token) error) error {
	d := p.decoder(b)
	depth := 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			if depth != 0 {
				return fmt.Errorf("the part %s ends before its elements do", clip(part))
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("the part %s is not well-formed XML: %w", clip(part), err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			if bytes.HasPrefix(bytes.TrimSpace(t), []byte("DOCTYPE")) {
				return fmt.Errorf("the part %s declares a document type, which is how an XML bomb is made and which no workbook needs", clip(part))
			}
		case xml.StartElement:
			depth++
			if depth > p.lim.Depth {
				return fmt.Errorf("the part %s: %w", clip(part), errTooDeep)
			}
		case xml.EndElement:
			depth--
		}
		if err := fn(tok); err != nil {
			return err
		}
	}
}

// walk hands each start element of a part to fn with the decoder, so fn
// may read the element's content itself; what it reads is not walked
// again.
func (p *pkg) walk(b []byte, part string, fn func(*xml.Decoder, xml.StartElement) error) error {
	d := p.decoder(b)
	depth := 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the part %s is not well-formed XML: %w", clip(part), err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			if bytes.HasPrefix(bytes.TrimSpace(t), []byte("DOCTYPE")) {
				return fmt.Errorf("the part %s declares a document type, which is how an XML bomb is made and which no workbook needs", clip(part))
			}
		case xml.StartElement:
			depth++
			if depth > p.lim.Depth {
				return fmt.Errorf("the part %s: %w", clip(part), errTooDeep)
			}
			before := d.InputOffset()
			if err := fn(d, t); err != nil {
				if errors.Is(err, errTooDeep) {
					return fmt.Errorf("the part %s: %w", clip(part), err)
				}
				return err
			}
			if d.InputOffset() != before {
				// fn read the element through to its end.
				depth--
			}
		case xml.EndElement:
			depth--
		}
	}
}

// innerText is the text inside the element just started, to its end.
func innerText(d *xml.Decoder, depth int) (string, error) {
	var b strings.Builder
	level := 1
	for level > 0 {
		tok, err := d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			level++
			if level > depth {
				return "", errTooDeep
			}
		case xml.EndElement:
			level--
		case xml.CharData:
			b.Write(t)
		}
	}
	return b.String(), nil
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name && (a.Name.Space == "" || name == "id") {
			return a.Value
		}
	}
	return ""
}

// rid is the relationship an element names: its r:id.
func rid(se xml.StartElement) string {
	for _, a := range se.Attr {
		if a.Name.Local == "id" && a.Name.Space != "" {
			return a.Value
		}
	}
	return ""
}

// clip is a name from the file, short enough to quote in an error, with
// no character in it that would move a terminal's cursor.
func clip(s string) string {
	r := []rune(s)
	for i, c := range r {
		if c < 0x20 || c == 0x7f {
			r[i] = '?'
		}
	}
	return plaintext.Clip(string(r), 60, "…")
}
