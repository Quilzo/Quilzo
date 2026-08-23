package export

import (
	"strings"
	"testing"
	"time"
)

// A page with a hero and sections can leave.
//
// The Markdown export refused any nested field, and a page written the way this
// product's own layouts want has two of them: a hero map and a list of section
// maps. So `export markdown` failed outright — no files at all — on the shape
// the shipped starters produce, while the help calls this section "leaving
// (there is no lock-in here, and this is how it is proved)".
//
// Nested values go out as JSON, which is valid YAML flow style and is read back
// as a map by Hugo, Astro, Eleventy and Jekyll.
func TestAPageWithNestedFieldsCanBeExportedToMarkdown(t *testing.T) {
	page := map[string]any{
		"title": "Aster & Alum",
		"hero": map[string]any{
			"title": "Colour that comes out of a bucket",
			"lead":  "Ten metres at a time.",
		},
		"sections": []any{
			map[string]any{"features": map[string]any{
				"title": "Three things",
				"items": []any{map[string]any{"title": "No synthetic dye"}},
			}},
		},
	}
	files, err := Export(Markdown, Site{
		Name: "Aster & Alum", Pages: map[string]any{"index": page},
	}, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatalf("a page with a hero could not be exported: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no files")
	}
	var body string
	for _, f := range files {
		if strings.HasSuffix(f.Path, "index.md") {
			body = string(f.Body)
		}
	}
	if body == "" {
		t.Fatal("no index.md in the export")
	}
	// The nested values are there, and they are readable as structure rather
	// than as a Go map printed with %v.
	for _, want := range []string{`"title":"Colour that comes out of a bucket"`,
		`"features"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the front matter does not carry %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "map[") {
		t.Error("a Go map was printed into the front matter, which no parser " +
			"reads back")
	}
}
