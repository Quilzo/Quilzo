package export_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/export"
	"github.com/quilzo/quilzo/internal/importer"
)

func crateSite() export.Site {
	return export.Site{
		Pages: map[string]any{
			"index":   map[string]any{"title": "Home", "body": "Front page."},
			"about":   map[string]any{"title": "About us", "body": "Founded 2019."},
			"pricing": map[string]any{"title": "What it costs", "body": "Ten pounds."},
		},
		Name:      "Marginalia",
		BaseURL:   "https://example.test",
		Licence:   "https://spdx.org/licenses/CC-BY-4.0",
		Publisher: "Marginalia Ltd",
		Commit:    strings.Repeat("c", 64),
	}
}

func crateFiles(t *testing.T) []export.File {
	t.Helper()
	files, err := export.Export(export.ROCrate, crateSite(), when)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func graph(t *testing.T, files []export.File) map[string]map[string]any {
	t.Helper()
	var doc struct {
		Context string           `json:"@context"`
		Graph   []map[string]any `json:"@graph"`
	}
	raw := fileNamed(t, files, "ro-crate-metadata.json")
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the crate metadata is not valid JSON: %v", err)
	}
	by := map[string]map[string]any{}
	for _, e := range doc.Graph {
		by[e["@id"].(string)] = e
	}
	return by
}

// The whole value of a crate is that a reader can check the file is the one
// described. A checksum computed over anything other than the bytes actually
// written would pass every test that builds metadata and fail the first time
// somebody verified a deposit — which is the moment it matters most.
func TestEveryChecksumIsOfTheBytesActuallyWritten(t *testing.T) {
	files := crateFiles(t)
	described := graph(t, files)

	checked := 0
	for _, f := range files {
		if f.Path == "ro-crate-metadata.json" {
			continue
		}
		e, ok := described[f.Path]
		if !ok {
			t.Errorf("%s was written but the crate does not describe it", f.Path)
			continue
		}
		sum := sha256.Sum256(f.Body)
		if want := hex.EncodeToString(sum[:]); e["sha256"] != want {
			t.Errorf("%s: the crate says %v, the bytes hash to %s",
				f.Path, e["sha256"], want)
		}
		if got, want := e["contentSize"], float64(len(f.Body)); got != want {
			t.Errorf("%s: contentSize %v, actual %v", f.Path, got, want)
		}
		checked++
	}
	// Assert how much was examined. A loop that describes no files also
	// reports no mismatches, and would have looked exactly like a pass.
	if checked != len(files)-1 {
		t.Fatalf("checked %d files out of %d written", checked, len(files)-1)
	}
	if checked == 0 {
		t.Fatal("the crate contains no files at all")
	}
}

// A crate is a directory with a metadata file in it, not an archive. If the
// content stopped being ordinary markdown the deposit would be readable only
// by whoever has this program, which is the thing exports exist to prevent.
func TestACrateReImportsToTheSameSite(t *testing.T) {
	files := crateFiles(t)
	original := crateSite().Pages

	got := map[string]any{}
	for _, f := range files {
		// Only the content. The markdown export also writes a README
		// explaining how to load the files elsewhere; it is part of the
		// deposit and carries a checksum, but it is not a page.
		if !strings.HasPrefix(f.Path, "content/") {
			continue
		}
		rep, err := importer.Import(importer.Markdown, bytes.NewReader(f.Body), when)
		if err != nil {
			t.Fatalf("%s: this tool could not read its own crate: %v", f.Path, err)
		}
		for _, p := range rep.Pages {
			got[p.Name] = p.Fields
		}
	}
	if len(got) != len(original) {
		t.Fatalf("deposited %d pages and read %d back", len(original), len(got))
	}
	for name, want := range original {
		back, ok := got[name].(map[string]any)
		if !ok {
			names := []string{}
			for n := range got {
				names = append(names, n)
			}
			t.Errorf("page %q did not survive under its own name; came back "+
				"as one of %v", name, names)
			continue
		}
		for k, v := range want.(map[string]any) {
			if !reflect.DeepEqual(v, back[k]) {
				t.Errorf("page %q field %q: %v became %v", name, k, v, back[k])
			}
		}
		// The importer records the name in a slug field whether or not the
		// export carried one. That adds no information the name did not
		// already carry, so it is not a loss — but it has to equal the name,
		// because a slug that disagreed with the page's name would point the
		// destination's URLs somewhere else.
		for k := range back {
			if _, expected := want.(map[string]any)[k]; expected {
				continue
			}
			if k == "slug" && back[k] == name {
				continue
			}
			t.Errorf("page %q gained an unexpected field %q = %v", name, k, back[k])
		}
	}
}

// The specification fixes this filename. A crate that named it anything else
// would not be found by a consumer, and would be a folder.
func TestTheMetadataFileIsAtTheRootUnderItsFixedName(t *testing.T) {
	files := crateFiles(t)
	found := false
	for _, f := range files {
		if f.Path == "ro-crate-metadata.json" {
			found = true
		}
	}
	if !found {
		names := []string{}
		for _, f := range files {
			names = append(names, f.Path)
		}
		t.Fatalf("no ro-crate-metadata.json at the root; got %v", names)
	}
}

// Guessing a licence is a legal claim about somebody else's content. The
// refusal has to survive at the export boundary, not only inside the builder.
func TestAnExportWithNoLicenceIsRefused(t *testing.T) {
	s := crateSite()
	s.Licence = ""
	if _, err := export.Export(export.ROCrate, s, when); err == nil {
		t.Fatal("exported a crate with no licence")
	}
}

// The commit is what makes the deposit recoverable: it names bytes in a store
// that addresses content by hash, so the same identifier always means the same
// site. Dropping it turns a verifiable deposit into a snapshot.
func TestTheRootRecordsThePublishedCommit(t *testing.T) {
	files := crateFiles(t)
	root := graph(t, files)["./"]
	if root == nil {
		t.Fatal("no root data entity")
	}
	if want := "sha256:" + strings.Repeat("c", 64); root["identifier"] != want {
		t.Errorf("identifier is %v, want %s", root["identifier"], want)
	}
}

// A page's title is what a catalogue shows. Falling back to the filename would
// list a deposit as "index" and "about", which is not what anybody searches.
func TestAPageIsNamedByItsTitleNotItsFilename(t *testing.T) {
	files := crateFiles(t)
	g := graph(t, files)
	e := g["content/index.md"]
	if e == nil {
		t.Fatalf("no entity for content/index.md; graph has %d entries", len(g))
	}
	if e["name"] != "Home" {
		t.Errorf("content/index.md is named %v, want its title", e["name"])
	}
}
