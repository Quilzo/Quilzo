// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package export_test

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/quilzo/quilzo/internal/export"
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

	rep, err := export.Read(export.JSON, pagesJSON)
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
	rep, err := export.Read(export.JSON, fileNamed(t, files, "content/pages.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Pages) != 1 || rep.Pages[0].Name != "index" {
		t.Fatalf("the page came back as %q, so / would 404 after a round trip",
			rep.Pages[0].Name)
	}
}

// A file that names one page twice brings both.
//
// Two pages of an array that shared a name were already numbered rather
// than one replacing the other, and so were two keys that came to one name.
// The same name written twice as a key was not: the file was read into a
// map, which keeps the last of a repeated key, so {"same": ..., "same": ...}
// imported one page, reported one page, and said nothing about the other. A
// file written by hand, or put together from two, does that.
func TestAPageNamedTwiceInAJSONFileIsNotLost(t *testing.T) {
	rep, err := export.Read(export.JSON, []byte(`{"same":{"title":"Same","body":"first"},
		"other":{"body":"between"},"same":{"title":"Same","body":"second"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range rep.Pages {
		body, _ := p.Fields["body"].(string)
		got = append(got, p.Name+"="+body)
	}
	if g := strings.Join(got, ","); g != "other=between,same=first,same-2=second" {
		t.Fatalf("the pages arrived as %s, not other, same and same-2: the page "+
			"whose name came second was lost", g)
	}

	// What the map read refused is still refused, and in the same words.
	for _, bad := range []string{`{"a":{"title":"A"}} trailing`, `{"a":`, `"a page"`} {
		if _, err := export.Read(export.JSON, []byte(bad)); err == nil ||
			!strings.Contains(err.Error(), "this is not JSON") {
			t.Errorf("%s was read, or refused as something else: %v", bad, err)
		}
	}
	if _, err := export.Read(export.JSON, []byte(`null`)); err == nil ||
		!strings.Contains(err.Error(), "no importable pages") {
		t.Errorf("null was read as pages, or refused as something else: %v", err)
	}
}

// An array has no keys, so a title is still a better name than a position.
// The fix must not have taken that away.
func TestAnArrayOfPagesStillTakesItsNamesFromTheContent(t *testing.T) {
	rep, err := export.Read(export.JSON, []byte(`[{"title":"About us","body":"x"},{"slug":"pricing","title":"Costs"}]`))
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
		rep, err := export.Read(export.JSON, f.Body)
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
	rep, err := export.Read(export.JSON, body)
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

	got := map[string]export.Record{}
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
	rep, err := export.Read(export.JSON, []byte(doc))
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
	rep, err := export.Read(export.JSON, []byte(doc))
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

// A site whose pages carry every kind of value the front matter is written
// with: words, a number, a yes or no, and a list.
func typedSite() export.Site {
	return export.Site{
		Pages: map[string]any{
			"index": map[string]any{"title": "Home", "body": "Front page.\n\nTwo paragraphs."},
			"about": map[string]any{"title": `Tom "&" Jerry`, "body": "Since 1952.",
				"price": float64(4200), "open": true, "tags": []any{"bread", "cake"}},
			"pricing": map[string]any{"title": "What it costs", "summary": "a: b # not a comment"},
		},
		Collections: map[string][]export.Record{"products": {
			{ID: "aa11", Fields: map[string]any{"title": "Copper pen", "price": float64(4200),
				"body": "Slim."}, Created: 1786000000, Updated: 1786000900},
			{ID: "bb22", Fields: map[string]any{"title": "Brass rule", "in_stock": false}},
		}},
		Redirects: []export.Redirect{{From: "/old-about", To: "/about", Permanent: true}},
	}
}

// sameFields says what changed between a page as it went out and as it came
// back. The Markdown export writes the page's name as its slug when it has
// none, which adds nothing the name did not carry, so that one is allowed.
func sameFields(t *testing.T, name string, want, back map[string]any) {
	t.Helper()
	for k, v := range want {
		if !reflect.DeepEqual(v, back[k]) {
			t.Errorf("page %q field %q: %#v became %#v", name, k, v, back[k])
		}
	}
	for k, v := range back {
		if _, ok := want[k]; !ok && !(k == "slug" && v == name) {
			t.Errorf("page %q gained a field %q = %#v", name, k, v)
		}
	}
}

// The Markdown export comes back as it went out, value for value.
//
// Only the JSON export was held to its round trip. The Markdown one was read
// back by the flat front matter reader written for Jekyll and Hugo, so a price
// of 4200 came back as the text "4200", a yes as "true" and a list of tags as
// the text ["bread", "cake"]: a page that went out as a shop's came back as
// one no listing could sort or filter. The crate's round trip passed only
// because its pages held nothing but words.
func TestAMarkdownExportReImportsToTheSameSite(t *testing.T) {
	site := typedSite()
	files, err := export.Export(export.Markdown, site, when)
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	for name, want := range site.Pages {
		c, err := export.Read(export.Markdown, fileNamed(t, files, "content/"+name+".md"))
		if err != nil {
			t.Fatalf("this tool could not read its own export of %s: %v", name, err)
		}
		if len(c.Pages) != 1 || c.Pages[0].Name != name {
			t.Fatalf("content/%s.md came back as %v", name, c.Pages)
		}
		sameFields(t, name, want.(map[string]any), c.Pages[0].Fields)
		read++
	}
	if read != 3 {
		t.Fatalf("read %d pages back", read)
	}
}

// A marked export comes back too. The banner is the file's first line, so the
// reader that looked for front matter at the top found none, and read the
// whole file, front matter and all, as the body of a page called "imported".
func TestAMarkedMarkdownExportReImportsToTheSameSite(t *testing.T) {
	site := typedSite()
	site.Banner = "OFFICIAL-SENSITIVE"
	files, err := export.Export(export.Markdown, site, when)
	if err != nil {
		t.Fatal(err)
	}
	body := fileNamed(t, files, "content/about.md")
	if !strings.HasPrefix(string(body), site.Banner+"\n") {
		t.Fatalf("the export is not marked, so this proves nothing:\n%s", body)
	}
	c, err := export.Read(export.Markdown, body)
	if err != nil {
		t.Fatalf("this tool could not read its own marked export: %v", err)
	}
	if len(c.Pages) != 1 || c.Pages[0].Name != "about" {
		t.Fatalf("a marked page came back as %v", c.Pages)
	}
	sameFields(t, "about", site.Pages["about"].(map[string]any), c.Pages[0].Fields)
}

// A record's file says which record it is and where it belongs, and comes back
// as that record. Read as a page, a product came back as a page named after
// its title, with its id and collection as two fields nobody declared.
func TestAMarkdownRecordFileComesBackAsARecordNotAPage(t *testing.T) {
	site := typedSite()
	files, err := export.Export(export.Markdown, site, when)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range site.Collections["products"] {
		c, err := export.Read(export.Markdown, fileNamed(t, files, "content/products/"+want.ID+".md"))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Pages) != 0 || c.Collection != "products" || len(c.Records) != 1 {
			t.Fatalf("record %s came back as %d pages and %d records of %q",
				want.ID, len(c.Pages), len(c.Records), c.Collection)
		}
		if back := c.Records[0]; !reflect.DeepEqual(back, want) {
			t.Errorf("record %s: %#v became %#v", want.ID, want, back)
		}
	}
}

// A page with a date of its own reads back from the Markdown export. The
// export also wrote the day the page last changed as `date`, so the file gave
// the key twice: a YAML reader refuses that, and the rest kept whichever came
// last, so an event lost its day to the day it was edited.
func TestAPageWithADateOfItsOwnReadsBackFromAMarkdownExport(t *testing.T) {
	site := export.Site{
		Pages:   map[string]any{"fair": map[string]any{"title": "Summer fair", "date": "2027-07-03"}},
		Changed: map[string]time.Time{"fair": when},
	}
	files, err := export.Export(export.Markdown, site, when)
	if err != nil {
		t.Fatal(err)
	}
	c, err := export.Read(export.Markdown, fileNamed(t, files, "content/fair.md"))
	if err != nil {
		t.Fatalf("the page could not be read back: %v", err)
	}
	if got := c.Pages[0].Fields["date"]; got != "2027-07-03" {
		t.Errorf("the fair's own day came back as %v", got)
	}
}

// A page whose name reads as a number, a yes or no or nothing comes back from
// the Markdown export under its own name, with its name as words.
//
// The export wrote the name as `slug: 404`, unquoted, the one value it did not
// quote. Read as YAML, that is the number 404, so the page that shows when
// nothing is found came back with a number for a link, and a file read on its
// own came back under its title's name, not-found; `true` came back a yes and
// `null` as nothing. Hugo and Jekyll read the line the same way.
func TestAPageNamedLikeANumberKeepsItsNameThroughAMarkdownExport(t *testing.T) {
	site := export.Site{Pages: map[string]any{}}
	for _, name := range []string{"404", "2024", "true", "null", "1e3"} {
		site.Pages[name] = map[string]any{"title": "Page " + name, "body": "Words."}
	}
	files, err := export.Export(export.Markdown, site, when)
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{}
	for _, f := range files {
		fsys[f.Path] = &fstest.MapFile{Data: f.Body}
	}
	for name := range site.Pages {
		c, err := export.Read(export.Markdown, fileNamed(t, files, "content/"+name+".md"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(c.Pages) != 1 || c.Pages[0].Name != name {
			t.Errorf("content/%s.md came back as %v", name, c.Pages)
		}
	}
	back, _, err := export.ReadDir(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range site.Pages {
		got, _ := back.Pages[name].(map[string]any)
		sameFields(t, name, want.(map[string]any), got)
	}
}

// A whole export directory comes back as the site it was made from: its pages,
// its records, when each page changed, its redirects and its marking.
func TestAWholeExportDirectoryReImportsToTheSameSite(t *testing.T) {
	for _, f := range []export.Format{export.JSON, export.Markdown, export.ROCrate} {
		t.Run(string(f), func(t *testing.T) {
			site := typedSite()
			site.Banner = "OFFICIAL"
			site.Licence = "https://spdx.org/licenses/CC-BY-4.0"
			if f == export.JSON {
				// The Markdown formats carry the day a page changed as its
				// date, which is what Hugo and Jekyll read it as: a field,
				// not a sidecar.
				site.Changed = map[string]time.Time{"index": when.UTC(), "about": when.Add(-time.Hour).UTC()}
			}
			files, err := export.Export(f, site, when)
			if err != nil {
				t.Fatal(err)
			}
			fsys := fstest.MapFS{}
			for _, file := range files {
				fsys[file.Path] = &fstest.MapFile{Data: file.Body}
			}
			back, skipped, err := export.ReadDir(fsys)
			if err != nil {
				t.Fatalf("this tool could not read its own export: %v", err)
			}
			if len(skipped) > 0 {
				t.Errorf("skipped %v", skipped)
			}
			if len(back.Pages) != len(site.Pages) {
				t.Errorf("exported %d pages and read %d back", len(site.Pages), len(back.Pages))
			}
			for name, want := range site.Pages {
				got, _ := back.Pages[name].(map[string]any)
				sameFields(t, name, want.(map[string]any), got)
			}
			if !reflect.DeepEqual(back.Collections, site.Collections) {
				t.Errorf("the records %v came back as %v", site.Collections, back.Collections)
			}
			if !reflect.DeepEqual(back.Changed, site.Changed) {
				t.Errorf("when the pages changed, %v, came back as %v", site.Changed, back.Changed)
			}
			if !reflect.DeepEqual(back.Redirects, site.Redirects) {
				t.Errorf("the redirects %v came back as %v", site.Redirects, back.Redirects)
			}
			if back.Banner != site.Banner {
				t.Errorf("the marking %q came back as %q", site.Banner, back.Banner)
			}
		})
	}
}

// What is not an export is refused in words, not read as an empty site.
func TestADirectoryThatIsNotAnExportIsRefused(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"nothing under content/": {"README.md": {Data: []byte("# Notes\n")}},
		"a WordPress export":     {"content/wordpress-export.xml": {Data: []byte("<rss/>")}},
	} {
		if _, _, err := export.ReadDir(fsys); err == nil || !strings.Contains(err.Error(), "not an export") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An empty front matter is read, and the page in it has no name to come
	// back under, so it is refused as one, not as a file with no end.
	if c, err := export.Read(export.Markdown, []byte("---\n---\n\nJust words.\n")); err == nil ||
		!strings.Contains(err.Error(), "no usable name") {
		t.Errorf("a page with no name was read back as %v, %v", c, err)
	}
}

// A record keeps its own fields named like what the export says about it.
//
// The record's file wrote its id, collection, created and updated beside its
// fields, so a product with its own collection ("Spring 2027") or id
// ("SKU-1") gave the key twice, which the reader refuses, and one with its
// own created ("5 January") was refused as not a time. Either way the whole
// export no longer read back.
func TestARecordKeepsItsOwnFieldsNamedLikeTheExportsBookkeeping(t *testing.T) {
	site := export.Site{
		Pages: map[string]any{"index": map[string]any{"title": "Home"}},
		Collections: map[string][]export.Record{"products": {
			{ID: "aa11", Fields: map[string]any{"title": "Linen shirt", "collection": "Spring 2027"},
				Created: 1786000000, Updated: 1786000900},
			{ID: "bb22", Fields: map[string]any{"title": "Wool coat", "id": "SKU-1"}},
			{ID: "cc33", Fields: map[string]any{"created": "5 January", "updated": "weekly"},
				Created: 1786000100},
			{ID: "dd44", Fields: map[string]any{"id": "SKU-2", "collection": "Autumn",
				"created": "5 January", "updated": float64(3), "fields": "cotton, linen",
				"body": "Soft."}, Created: 1786000200, Updated: 1786000300},
			// A field of the name the others are kept under, holding what
			// looks like them.
			{ID: "ee55", Fields: map[string]any{"title": "Silk scarf",
				"fields": map[string]any{"id": "inner"}}},
		}},
		Licence: "https://spdx.org/licenses/CC-BY-4.0",
	}
	for _, f := range []export.Format{export.JSON, export.Markdown, export.ROCrate} {
		t.Run(string(f), func(t *testing.T) {
			files, err := export.Export(f, site, when)
			if err != nil {
				t.Fatal(err)
			}
			fsys := fstest.MapFS{}
			for _, file := range files {
				fsys[file.Path] = &fstest.MapFile{Data: file.Body}
			}
			back, skipped, err := export.ReadDir(fsys)
			if err != nil {
				t.Fatalf("this tool could not read its own export: %v", err)
			}
			if len(skipped) > 0 {
				t.Errorf("skipped %v", skipped)
			}
			if !reflect.DeepEqual(back.Collections, site.Collections) {
				t.Errorf("the records %#v came back as %#v", site.Collections, back.Collections)
			}
		})
	}
}

// A page with its own id and collection comes back as that page. A record's
// file is told apart by those two, so a lookbook page naming its season's
// collection and its own id came back as a record of that collection, and
// the page was gone.
func TestAPageWithAnIDAndACollectionOfItsOwnIsNotReadAsARecord(t *testing.T) {
	site := export.Site{Pages: map[string]any{"lookbook": map[string]any{
		"title": "Lookbook", "id": "SKU-1", "collection": "Spring 2027"}},
		Licence: "https://spdx.org/licenses/CC-BY-4.0"}
	for _, f := range []export.Format{export.JSON, export.Markdown, export.ROCrate} {
		t.Run(string(f), func(t *testing.T) {
			files, err := export.Export(f, site, when)
			if err != nil {
				t.Fatal(err)
			}
			fsys := fstest.MapFS{}
			for _, file := range files {
				fsys[file.Path] = &fstest.MapFile{Data: file.Body}
			}
			back, _, err := export.ReadDir(fsys)
			if err != nil {
				t.Fatalf("this tool could not read its own export: %v", err)
			}
			if len(back.Collections) != 0 {
				t.Errorf("the page came back as records: %#v", back.Collections)
			}
			got, _ := back.Pages["lookbook"].(map[string]any)
			sameFields(t, "lookbook", site.Pages["lookbook"].(map[string]any), got)
		})
	}
}

// A record file an earlier export wrote reads as it did: the export's own
// keys beside the record's fields, and a field called fields that is only a
// field.
func TestAnEarlierRecordFileStillReads(t *testing.T) {
	c, err := export.Read(export.Markdown, []byte("---\n"+
		"collection: \"products\"\n"+
		"created: \"2026-08-06T07:06:40Z\"\n"+
		"fields: \"cotton, linen\"\n"+
		"id: \"aa11\"\n"+
		"price: 4200\n"+
		"title: \"Copper pen\"\n"+
		"---\n\nSlim.\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := export.Record{ID: "aa11", Created: 1786000000, Fields: map[string]any{
		"title": "Copper pen", "price": float64(4200), "fields": "cotton, linen", "body": "Slim."}}
	if c.Collection != "products" || len(c.Records) != 1 || !reflect.DeepEqual(c.Records[0], want) {
		t.Fatalf("an earlier record file came back as %q %#v", c.Collection, c.Records)
	}
}
