package export_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/export"
	"github.com/quilzo/quilzo/internal/importer"
)

var when = time.Unix(1786000000, 0)

// "there is no lock-in here, and this is how it is proved" is a claim this
// tool makes in its own help text, and until this test it was not proved.
//
// The JSON exporter writes {"index": {"title": "Home"}}. The importer preferred
// a title field over the map key, so it came back as "home" — a round trip
// renamed every page whose title was not its name. For the front page that is
// worse than cosmetic: / serves whatever is called "index", so exporting and
// re-importing a site made its home page unreachable.
//
// Both halves of this had passing tests. The exporter was tested against what
// it writes and the importer against what it reads, and neither was tested
// against the other.
func TestAJSONExportReImportsToTheSameSite(t *testing.T) {
	original := map[string]any{
		"index":   map[string]any{"title": "Home", "body": "Front page."},
		"about":   map[string]any{"title": "About us", "body": "Founded 2019."},
		"pricing": map[string]any{"title": "What it costs", "body": "Ten pounds."},
		"terms":   map[string]any{"title": "Terms & Conditions", "body": "Legal."},
	}
	files, err := export.Export(export.JSON,
		export.Site{Pages: original, Name: "Acme"}, when)
	if err != nil {
		t.Fatal(err)
	}
	pagesJSON := fileNamed(t, files, "content/pages.json")

	rep, err := importer.Import(importer.JSON, bytes.NewReader(pagesJSON),
		when)
	if err != nil {
		t.Fatalf("this tool could not read its own export: %v", err)
	}

	got := map[string]any{}
	for _, p := range rep.Pages {
		got[p.Name] = p.Fields
	}
	if len(got) != len(original) {
		t.Fatalf("exported %d pages and imported %d back", len(original), len(got))
	}
	for name, want := range original {
		back, ok := got[name]
		if !ok {
			names := make([]string, 0, len(got))
			for n := range got {
				names = append(names, n)
			}
			t.Errorf("page %q did not survive the round trip; came back as one "+
				"of %v", name, names)
			continue
		}
		if !reflect.DeepEqual(want, back) {
			t.Errorf("page %q changed: %v became %v", name, want, back)
		}
	}
}

// A page whose title differs from its name is the case that broke, so it is
// worth naming on its own rather than leaving it inside the sweep above.
func TestAPageKeepsItsNameEvenWhenTheTitleSuggestsAnother(t *testing.T) {
	files, err := export.Export(export.JSON, export.Site{
		Pages: map[string]any{"index": map[string]any{"title": "Home"}},
	}, when)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := importer.Import(importer.JSON,
		bytes.NewReader(fileNamed(t, files, "content/pages.json")),
		when)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Pages) != 1 || rep.Pages[0].Name != "index" {
		t.Fatalf("the page came back as %q, so / would 404 after a round trip",
			rep.Pages[0].Name)
	}
}

// An array has no keys, so a title is still a better name than a position.
// The fix must not have taken that away.
func TestAnArrayOfPagesStillTakesItsNamesFromTheContent(t *testing.T) {
	rep, err := importer.Import(importer.JSON, strings.NewReader(
		`[{"title":"About us","body":"x"},{"slug":"pricing","title":"Costs"}]`),
		when)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"about-us": true, "pricing": true}
	for _, p := range rep.Pages {
		if !want[p.Name] {
			t.Errorf("an array element was named %q; a positional placeholder "+
				"leaked through instead of the title or slug", p.Name)
		}
	}
}

// And the export's own sidecar must not be in the directory somebody will
// glob. `quilzo import content/*.json` hit last-changed.json and failed on a
// file this tool wrote itself, which reads as the importer being broken.
func TestTheContentDirectoryHoldsOnlyContent(t *testing.T) {
	files, err := export.Export(export.JSON, export.Site{
		Pages: map[string]any{"index": map[string]any{"title": "Home"}},
	}, when)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "content/") {
			continue
		}
		rep, err := importer.Import(importer.JSON, bytes.NewReader(f.Body),
			when)
		if err != nil || len(rep.Pages) == 0 {
			t.Errorf("%s is inside content/ but is not importable content: %v",
				f.Path, err)
		}
	}
}

func fileNamed(t *testing.T, files []export.File, path string) []byte {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return f.Body
		}
	}
	var have []string
	for _, f := range files {
		have = append(have, f.Path)
	}
	t.Fatalf("no %s in the export; it wrote %v", path, have)
	return nil
}

// Collections were exported by no format at all, and nothing said so.
//
// The demo shop holds twelve products. `export` wrote a catalogue page and
// none of them, then printed "11 page(s)" — a true statement that reads as a
// complete one. The round-trip test above only ever built pages, so the whole
// class was invisible to it: every format passed a test that never asked the
// question.
//
// This is the same shape as the publish gate that checked ten pages and none
// of fifteen products while reporting success. Both were caught by counting
// what was examined rather than what was found.
func TestACollectionSurvivesTheRoundTrip(t *testing.T) {
	records := []export.Record{
		{ID: "aa11", Fields: map[string]any{
			"title": "Copper pen", "price": float64(4200), "body": "Slim."},
			Created: 1786000000, Updated: 1786000900},
		{ID: "bb22", Fields: map[string]any{
			"title": "Brass rule", "price": float64(1800), "body": "300mm."},
			Created: 1786000100, Updated: 1786000800},
	}
	files, err := export.Export(export.JSON, export.Site{
		Pages:       map[string]any{"index": map[string]any{"title": "Home"}},
		Collections: map[string][]export.Record{"products": records},
	}, when)
	if err != nil {
		t.Fatal(err)
	}

	body := fileNamed(t, files, "content/products.json")
	rep, err := importer.Import(importer.JSON, bytes.NewReader(body), when)
	if err != nil {
		t.Fatalf("this tool could not read its own collection export: %v", err)
	}
	if rep.Collection != "products" {
		t.Fatalf("came back as collection %q, not products", rep.Collection)
	}
	// Count what was examined. A loop over an empty slice finds no mismatches
	// and looks exactly like a pass, which is how the original bug survived.
	if len(rep.Records) != len(records) {
		t.Fatalf("exported %d records and imported %d back",
			len(records), len(rep.Records))
	}

	got := map[string]importer.Record{}
	for _, r := range rep.Records {
		got[r.ID] = r
	}
	for _, want := range records {
		back, ok := got[want.ID]
		if !ok {
			t.Errorf("record %q did not survive under its own id", want.ID)
			continue
		}
		if !reflect.DeepEqual(want.Fields, back.Fields) {
			t.Errorf("record %q changed: %v became %v",
				want.ID, want.Fields, back.Fields)
		}
		// The timestamps matter on their own: a catalogue that arrives with
		// every item created at import time sorts wrongly from its first day,
		// and no destination can reconstruct them.
		if back.Created != want.Created || back.Updated != want.Updated {
			t.Errorf("record %q timestamps changed: %d/%d became %d/%d",
				want.ID, want.Created, want.Updated, back.Created, back.Updated)
		}
	}
}

// An id is the record's identity. Inventing one on import produces a record
// that nothing linking to the original still finds, and the broken relation is
// discovered by a reader rather than by the import.
func TestARecordWithNoIDIsRefusedRatherThanRenamed(t *testing.T) {
	doc := `{"collection":"products","records":[
		{"id":"ok1","fields":{"title":"Kept"}},
		{"fields":{"title":"No id"}}]}`
	rep, err := importer.Import(importer.JSON, strings.NewReader(doc), when)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Records) != 1 {
		t.Fatalf("imported %d records, want only the one with an id",
			len(rep.Records))
	}
	if len(rep.Skipped) != 1 {
		t.Fatalf("dropped a record without saying so: skipped %v", rep.Skipped)
	}
}

// The collections file has to be recognised before the page shapes, or a
// catalogue imports as two pages called "collection" and "records".
func TestACollectionsFileIsNotImportedAsPages(t *testing.T) {
	doc := `{"collection":"products","records":[{"id":"a","fields":{"title":"T"}}]}`
	rep, err := importer.Import(importer.JSON, strings.NewReader(doc), when)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Pages) != 0 {
		names := []string{}
		for _, p := range rep.Pages {
			names = append(names, p.Name)
		}
		t.Fatalf("a collections file imported as pages %v", names)
	}
}

// Every format has to carry them, not just the one with a round-trip test.
// WordPress calls this a custom post type and markdown destinations call it a
// section; either way an export that arrives as a shop with no products is not
// a migration.
func TestEveryFormatCarriesTheRecords(t *testing.T) {
	site := export.Site{
		Pages: map[string]any{"index": map[string]any{"title": "Home"}},
		Collections: map[string][]export.Record{"products": {
			{ID: "aa11", Fields: map[string]any{"title": "Copper pen"}},
			{ID: "bb22", Fields: map[string]any{"title": "Brass rule"}},
		}},
		Licence: "https://spdx.org/licenses/CC-BY-4.0", Name: "Shop",
	}
	for _, f := range export.Formats() {
		files, err := export.Export(f, site, when)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		joined := ""
		for _, file := range files {
			joined += file.Path + "\n" + string(file.Body) + "\n"
		}
		for _, want := range []string{"aa11", "bb22", "Copper pen", "Brass rule"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: exported nothing containing %q", f, want)
			}
		}
	}
}
