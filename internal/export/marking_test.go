package export_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/export"
)

func site(banner string) export.Site {
	return export.Site{
		Banner: banner,
		Pages: map[string]any{
			"index": map[string]any{"title": "Home", "body": "Welcome."},
		},
	}
}

// An export leaves the machine, and a file with no marking on it does not look
// like a file whose marking was lost — it looks like one that never had a
// marking.
func TestExportedMarkdownCarriesTheBanner(t *testing.T) {
	files, err := export.Export(export.Markdown, site("SECRET//NOFORN"),
		time.Unix(1787000000, 0))
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, f := range files {
		if !strings.HasSuffix(f.Path, ".md") {
			continue
		}
		found++
		body := string(f.Body)
		if !strings.HasPrefix(body, "SECRET//NOFORN") {
			t.Errorf("%s does not open with the banner:\n%s", f.Path, body)
		}
		if !strings.HasSuffix(strings.TrimSpace(body), "SECRET//NOFORN") {
			t.Errorf("%s does not close with the banner", f.Path)
		}
	}
	if found == 0 {
		t.Fatal("no markdown was exported, so this proves nothing")
	}
}

// Every marked export carries one file for the whole directory.
//
// It covers the formats that cannot hold a comment, and it is where somebody
// looks who has been handed a directory and does not know what it is.
func TestAMarkedExportSaysSoAtItsRoot(t *testing.T) {
	for _, format := range []export.Format{export.Markdown, export.JSON} {
		files, err := export.Export(format, site("SECRET//NOFORN"),
			time.Unix(1787000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		var root string
		for _, f := range files {
			if f.Path == "CLASSIFICATION" {
				root = string(f.Body)
			}
		}
		if root == "" {
			t.Errorf("%s export has no CLASSIFICATION file", format)
			continue
		}
		if !strings.Contains(root, "SECRET//NOFORN") {
			t.Errorf("%s: the file does not carry the banner", format)
		}
	}
}

// JSON is the lossless format this program re-imports. A banner inside it
// would change what comes back, so it must not be there.
func TestTheJSONExportIsStillValidJSON(t *testing.T) {
	files, err := export.Export(export.JSON, site("SECRET//NOFORN"),
		time.Unix(1787000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if !strings.HasSuffix(f.Path, ".json") {
			continue
		}
		checked++
		var any any
		if err := json.Unmarshal(f.Body, &any); err != nil {
			t.Errorf("%s is no longer valid JSON after marking: %v", f.Path, err)
		}
	}
	if checked == 0 {
		t.Fatal("no JSON was exported")
	}
}

// A deployment that does not mark exports exactly what it did before, with no
// extra file.
func TestAnUnmarkedExportIsUnchanged(t *testing.T) {
	files, err := export.Export(export.Markdown, site(""),
		time.Unix(1787000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "CLASSIFICATION" {
			t.Error("an unmarked export carries a classification file")
		}
		if strings.HasSuffix(f.Path, ".md") &&
			strings.HasPrefix(string(f.Body), "SECRET") {
			t.Errorf("%s was marked on an unmarked deployment", f.Path)
		}
	}
}
