// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/feature"
)

func countRecords(t *testing.T, root, name string) int {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := collection.Build(s, tree, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	return idx.Len()
}

func tempFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A spreadsheet becomes a package and its rows; a plain one installs with
// its records on one administrator's say-so.
func TestASpreadsheetInstallsWithItsRecords(t *testing.T) {
	root := featureSite(t)
	csv := tempFile(t, "minerals.csv", "Code,Material,Mass\nM1,Basalt,12\nM2,Granite,8\nM3,Basalt,3\n")
	out := filepath.Join(t.TempDir(), "minerals.json")
	if err := featureFromCmd(root, []string{csv, "-o", out}); err != nil {
		t.Fatal(err)
	}
	rows := strings.TrimSuffix(out, ".json") + ".rows.json"
	if fi, err := os.Stat(rows); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the rows file %v %v", fi, err)
	}
	if err := installFeatureFile(root, out, "", rows, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n := countRecords(t, root, "minerals"); n != 3 {
		t.Errorf("%d records imported", n)
	}
}

// One with addresses in it waits for a second person, and its records come
// in only when they approve.
func TestASpreadsheetAboutPeopleImportsOnlyOnceApproved(t *testing.T) {
	root := featureSite(t)
	csv := tempFile(t, "volunteers.csv", "Name,Email,Shift\nAda,ada@example.org,early\nBo,bo@example.org,late\nCy,cy@example.org,early\n")
	out := filepath.Join(t.TempDir(), "volunteers.json")
	if err := featureFromCmd(root, []string{csv, "-o", out}); err != nil {
		t.Fatal(err)
	}
	rows := strings.TrimSuffix(out, ".json") + ".rows.json"
	if err := installFeatureFile(root, out, "", rows, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	pend, _ := pendingFeatures(root)
	if len(pend) != 1 || pend[0].Rows != 3 || pend[0].RowsCollection != "volunteers" {
		t.Fatalf("pending %+v", pend)
	}
	types, _ := loadInstalledFeatures(root)
	if len(types) != 0 {
		t.Fatal("installed before approval")
	}
	if err := decideFeature(root, pend[0].ID, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	if n := countRecords(t, root, "volunteers"); n != 3 {
		t.Errorf("%d records after approval", n)
	}
	if _, err := os.Stat(featurePendingPath(root, pend[0].ID) + ".rows"); !os.IsNotExist(err) {
		t.Error("the rows waiting with the request were kept after it was decided")
	}
}

// Rows that do not fit the package's type stop the install before anything
// is written.
func TestRowsThatDoNotFitStopTheInstall(t *testing.T) {
	root := featureSite(t)
	csv := tempFile(t, "minerals.csv", "Code,Mass\nM1,12\nM2,8\nM3,3\n")
	out := filepath.Join(t.TempDir(), "minerals.json")
	if err := featureFromCmd(root, []string{csv, "-o", out}); err != nil {
		t.Fatal(err)
	}
	bad := tempFile(t, "bad.rows.json", `{"collection":"minerals","records":[{"code":"M9","mass":"heavy"}]}`)
	err := installFeatureFile(root, out, "", bad, asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "do not fit") {
		t.Fatalf("a row with words for a number was accepted: %v", err)
	}
	if in, _ := loadInstalledFeatures(root); len(in) != 0 {
		t.Error("the feature was installed although its rows were refused")
	}
	other := tempFile(t, "other.rows.json", `{"collection":"elsewhere","records":[{"code":"M9"}]}`)
	if err := installFeatureFile(root, out, "", other, asAdmin("dana")); err == nil {
		t.Error("rows for a collection the package does not declare were accepted")
	}
}

// Importing many records checks each against the collection's type, as
// adding one does; one bad record imports nothing.
func TestARecordsImportChecksEveryRecordAgainstItsType(t *testing.T) {
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	rows := []map[string]any{
		{"code": "S-1", "status": "available"},
		{"code": "S-2", "status": "lost"},
	}
	_, err := putCheckedRecords(root, "samples", rows, asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "record 2") {
		t.Fatalf("a record with a status the type does not allow was imported: %v", err)
	}
	if n := countRecords(t, root, "samples"); n != 0 {
		t.Errorf("%d records imported from a refused file", n)
	}
	b, _ := json.Marshal(rows[:1])
	if err := recordsImport(root, []string{"samples", tempFile(t, "ok.json", string(b))}); err != nil {
		t.Fatal(err)
	}
	if n := countRecords(t, root, "samples"); n != 1 {
		t.Errorf("%d records after a good import", n)
	}
}

// answersModel answers each prompt with the next of its answers.
type answersModel struct {
	answers []string
	asked   []string
}

func (m *answersModel) Complete(_ context.Context, system, user string) (string, error) {
	m.asked = append(m.asked, user)
	a := m.answers[0]
	if len(m.answers) > 1 {
		m.answers = m.answers[1:]
	}
	return a, nil
}

func (m *answersModel) Name() string { return "drafting-model" }

// A model drafts a package; what reaches beyond content is left out, a
// draft that fails the checks is shown its failures once, and nothing is
// installed.
func TestAFeatureIsDraftedFromASentenceAndOnlyDrafted(t *testing.T) {
	root := featureSite(t)
	bad := `{"name": "visits", "title": "Clinic visits", "purpose": "Book and list visits.",
	  "types": [{"name": "visit", "fields": [{"name": "when", "kind": "datetime"}]}],
	  "collections": [{"name": "visits", "type": "visit"}],
	  "agents": [{"name": "booker", "autonomy": "publish"}]}`
	good := `{"name": "visits", "title": "Clinic visits", "purpose": "Book and list visits.",
	  "types": [{"name": "visit", "fields": [{"name": "when", "kind": "date", "required": true}]}],
	  "collections": [{"name": "visits", "type": "visit"}],
	  "pages": [{"name": "visits", "body": {"title": "Visits", "members_only": true,
	     "sections": [{"prose": {"title": "Visits", "paragraphs": ["Ask at the desk."]}}]}}]}`
	m := &answersModel{answers: []string{bad, good}}
	draftModelSeam = func(string) (assist.Model, string) { return m, "" }
	t.Cleanup(func() { draftModelSeam = nil })

	d, err := draftFeature(context.Background(), root, "a page listing clinic visits", asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.asked) != 2 || !strings.Contains(m.asked[1], "failed these checks") {
		t.Fatalf("the failing draft was not shown its failures: %v", m.asked)
	}
	if d.Invalid != "" {
		t.Fatalf("the corrected draft is invalid: %s", d.Invalid)
	}
	if len(d.Package.Agents) != 0 {
		t.Error("the draft kept an agent")
	}
	if d.Package.Made == nil || d.Package.Made.Model != "drafting-model" || d.Package.Made.From == "" {
		t.Errorf("provenance %+v", d.Package.Made)
	}
	if in, _ := loadInstalledFeatures(root); len(in) != 0 {
		t.Error("drafting installed something")
	}
	p, err := feature.Decode(strings.NewReader(string(d.Body)))
	if err != nil || p.Validate(featureChecks(root)) != nil {
		t.Errorf("the written draft does not read back as a valid package: %v", err)
	}
}
