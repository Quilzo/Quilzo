package export_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/export"
	"github.com/rsh1k/scrivet/internal/importer"
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
// glob. `scrivet import content/*.json` hit last-changed.json and failed on a
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
