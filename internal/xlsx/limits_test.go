// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package xlsx

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// readWithin reads a workbook and fails the test if the read does not end
// in time: a workbook a few kilobytes long that keeps a reader busy is a
// bomb, whatever it is made of.
func readWithin(t *testing.T, b []byte, d time.Duration) (*Workbook, error) {
	t.Helper()
	type result struct {
		wb  *Workbook
		err error
	}
	done := make(chan result, 1)
	go func() {
		wb, err := Read(b, Limits{})
		done <- result{wb, err}
	}()
	select {
	case r := <-done:
		return r.wb, r.err
	case <-time.After(d):
		t.Fatalf("reading a workbook of %d bytes took longer than %s", len(b), d)
		return nil, nil
	}
}

// A reference beyond the last row or column a sheet can have is not a
// reference. One that names row 4,611,686,018,427,387,904 made the size of
// its range wrap round to nothing, and the reader then counted to it.
func TestReferenceBeyondTheSheetIsNone(t *testing.T) {
	for _, ref := range []string{"A1048577", "XFE1", "A4611686018427387904", "ZZZZ1"} {
		if _, ok := parseRef(ref); ok {
			t.Errorf("%s is read as a reference", ref)
		}
	}
	for _, ref := range []string{"A1048576", "XFD1", "XFD1048576"} {
		if _, ok := parseRef(ref); !ok {
			t.Errorf("%s, a cell a sheet has, is not read as a reference", ref)
		}
	}
	parts := simple(t, `<row r="1"><c r="A1"><v>1</v></c></row>`)
	parts["xl/workbook.xml"] = `<?xml version="1.0"?><workbook ` + nsMain + ` ` + nsRel + `><sheets>` +
		`<sheet name="Answers" sheetId="1" r:id="rId1"/></sheets><definedNames>` +
		`<definedName name="Wraps">Answers!$A$1:$D$4611686018427387904</definedName></definedNames></workbook>`
	if _, err := readWithin(t, book(t, parts), 10*time.Second); err != nil {
		t.Logf("refused: %v", err)
	}
}

// Merged ranges, defined names and answer lists each name a range of
// cells, and a few kilobytes of them can name billions: each is held to
// what a sheet is read with, and so are all of them together.
func TestRangeBombsRefused(t *testing.T) {
	// Forty merges of a hundred thousand cells each.
	var merges, cells strings.Builder
	for k := 0; k < 40; k++ {
		top := k*1000 + 1
		fmt.Fprintf(&cells, `<row r="%d"><c r="A%d"><v>1</v></c></row>`, top, top)
		fmt.Fprintf(&merges, `<mergeCell ref="A%d:CV%d"/>`, top, top+999)
	}
	parts := simple(t, cells.String())
	parts["xl/worksheets/sheet1.xml"] = `<?xml version="1.0"?><worksheet ` + nsMain + `><sheetData>` + cells.String() +
		`</sheetData><mergeCells>` + merges.String() + `</mergeCells></worksheet>`
	if _, err := readWithin(t, book(t, parts), 20*time.Second); err == nil || !strings.Contains(err.Error(), "merge") {
		t.Errorf("a workbook merging four million cells is read: %v", err)
	}

	// One range merged a thousand times over.
	merges.Reset()
	for k := 0; k < 1000; k++ {
		merges.WriteString(`<mergeCell ref="A1:CV1000"/>`)
	}
	parts["xl/worksheets/sheet1.xml"] = `<?xml version="1.0"?><worksheet ` + nsMain + `><sheetData><row r="1"><c r="A1"><v>1</v></c></row>` +
		`</sheetData><mergeCells>` + merges.String() + `</mergeCells></worksheet>`
	if _, err := readWithin(t, book(t, parts), 20*time.Second); err == nil || !strings.Contains(err.Error(), "merge") {
		t.Errorf("a workbook merging one range a thousand times is read: %v", err)
	}

	// Two thousand defined names of a hundred thousand cells each.
	var names strings.Builder
	for k := 0; k < 2000; k++ {
		fmt.Fprintf(&names, `<definedName name="n%d">Answers!$A$1:$CV$1000</definedName>`, k)
	}
	parts = simple(t, `<row r="1"><c r="A1"><v>1</v></c></row>`)
	parts["xl/workbook.xml"] = `<?xml version="1.0"?><workbook ` + nsMain + ` ` + nsRel + `><sheets>` +
		`<sheet name="Answers" sheetId="1" r:id="rId1"/></sheets><definedNames>` + names.String() + `</definedNames></workbook>`
	if _, err := readWithin(t, book(t, parts), 20*time.Second); err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("a workbook naming two hundred million cells is read: %v", err)
	}

	// Ten thousand answer lists over every cell of a sheet of ten thousand.
	cells.Reset()
	for r := 1; r <= 100; r++ {
		fmt.Fprintf(&cells, `<row r="%d">`, r)
		for c := 1; c <= 100; c++ {
			fmt.Fprintf(&cells, `<c r="%s"><v>1</v></c>`, cellRef(c, r))
		}
		cells.WriteString(`</row>`)
	}
	var lists strings.Builder
	for k := 0; k < 10000; k++ {
		lists.WriteString(`<dataValidation type="list" sqref="A1:CV100"><formula1>"Yes,No"</formula1></dataValidation>`)
	}
	parts = simple(t, "")
	parts["xl/worksheets/sheet1.xml"] = `<?xml version="1.0"?><worksheet ` + nsMain + `><sheetData>` + cells.String() +
		`</sheetData><dataValidations>` + lists.String() + `</dataValidations></worksheet>`
	if _, err := readWithin(t, book(t, parts), 20*time.Second); err == nil || !strings.Contains(err.Error(), "answer") {
		t.Errorf("a workbook of ten thousand answer lists over every cell is read: %v", err)
	}
}

// A defined name over more cells than are worth listing one by one still
// marks the cells it covers: a name over a whole column is as hidden from
// a person as one over a single cell.
func TestWideDefinedNameStillTaints(t *testing.T) {
	parts := simple(t, `<row r="1"><c r="A1"><v>1</v></c><c r="B1"><v>2</v></c></row>`+
		`<row r="500000"><c r="A500000"><v>3</v></c></row>`)
	parts["xl/workbook.xml"] = `<?xml version="1.0"?><workbook ` + nsMain + ` ` + nsRel + `><sheets>` +
		`<sheet name="Answers" sheetId="1" r:id="rId1"/></sheets><definedNames>` +
		`<definedName name="Column">Answers!$A$1:$A$1048576</definedName></definedNames></workbook>`
	wb, err := Read(book(t, parts), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	rows := wb.Sheets[0].Rows
	if !slices.Contains(rows[0].Cells[0].Taints, DefinedName) || !slices.Contains(rows[1].Cells[0].Taints, DefinedName) {
		t.Errorf("cells a name over a whole column covers are tainted %v and %v", rows[0].Cells[0].Taints, rows[1].Cells[0].Taints)
	}
	if slices.Contains(rows[0].Cells[1].Taints, DefinedName) {
		t.Errorf("a cell outside the name is tainted %v", rows[0].Cells[1].Taints)
	}
}

// A row given no height and a column given no width are hidden as surely
// as one marked hidden: a person opening the workbook sees neither.
func TestZeroSizedRowsAndColumnsAreHidden(t *testing.T) {
	parts := simple(t, "")
	parts["xl/worksheets/sheet1.xml"] = `<?xml version="1.0"?><worksheet ` + nsMain + `>` +
		`<cols><col min="2" max="2" width="0" customWidth="1"/><col min="3" max="3" width="12"/></cols><sheetData>` +
		`<row r="1"><c r="A1"><v>1</v></c><c r="B1"><v>2</v></c><c r="C1"><v>3</v></c></row>` +
		`<row r="2" ht="0" customHeight="1"><c r="A2"><v>4</v></c></row>` +
		`<row r="3" ht="15"><c r="A3"><v>5</v></c></row>` +
		`</sheetData></worksheet>`
	wb, err := Read(book(t, parts), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	rows := wb.Sheets[0].Rows
	if len(rows[0].Cells[0].Taints) != 0 || len(rows[0].Cells[2].Taints) != 0 || len(rows[2].Cells[0].Taints) != 0 {
		t.Errorf("cells a person sees are tainted: %v %v %v", rows[0].Cells[0].Taints, rows[0].Cells[2].Taints, rows[2].Cells[0].Taints)
	}
	if !slices.Contains(rows[0].Cells[1].Taints, HiddenColumn) {
		t.Errorf("a cell in a column of no width is tainted %v", rows[0].Cells[1].Taints)
	}
	if !slices.Contains(rows[1].Cells[0].Taints, HiddenRow) {
		t.Errorf("a cell in a row of no height is tainted %v", rows[1].Cells[0].Taints)
	}
	if !slices.ContainsFunc(wb.Flags, func(f Flag) bool { return f.Taint == HiddenRow && f.Where == "Answers!2" }) ||
		!slices.ContainsFunc(wb.Flags, func(f Flag) bool { return f.Taint == HiddenColumn && f.Where == "Answers!B" }) {
		t.Errorf("the flags are %+v", wb.Flags)
	}
}

// A name from the workbook quoted in an error moves no terminal's cursor:
// the eight-bit controls are replaced as the seven-bit ones are.
func TestClipDropsEightBitControls(t *testing.T) {
	if got := clip("part\u009b31mred\u001b"); strings.ContainsAny(got, "\u009b\u001b") {
		t.Errorf("clip left a control in %q", got)
	}
}
