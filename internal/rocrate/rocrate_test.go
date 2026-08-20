package rocrate_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/rocrate"
)

var when = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)

func good() []rocrate.File {
	return []rocrate.File{
		{Path: "content/about.md", SHA256: strings.Repeat("a", 64), Size: 12,
			MediaType: "text/markdown", Name: "About us", Author: "Ada Lovelace"},
		{Path: "content/index.md", SHA256: strings.Repeat("b", 64), Size: 30,
			MediaType: "text/markdown", Name: "Home"},
	}
}

func opts() rocrate.Options {
	return rocrate.Options{
		Name:        "Marginalia",
		Description: "A shop.",
		License:     "https://spdx.org/licenses/CC-BY-4.0",
		Publisher:   "Marginalia Ltd",
		Commit:      strings.Repeat("c", 64),
	}
}

func build(t *testing.T) rocrate.Crate {
	t.Helper()
	c, err := rocrate.Build(good(), when, opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("a crate this package built does not pass its own check: %v", err)
	}
	return c
}

func entity(t *testing.T, c rocrate.Crate, id string) rocrate.Entity {
	t.Helper()
	for _, e := range c.Graph {
		if e["@id"] == id {
			return e
		}
	}
	ids := []string{}
	for _, e := range c.Graph {
		ids = append(ids, e["@id"].(string))
	}
	t.Fatalf("no entity %q in the graph; it has %v", id, ids)
	return nil
}

// The specification fixes three things a consumer looks for. If any of them is
// wrong the file is not a crate, and no amount of correct content elsewhere
// makes it one.
func TestTheShapeAConsumerLooksForIsThere(t *testing.T) {
	c := build(t)
	if c.Context != "https://w3id.org/ro/crate/1.1/context" {
		t.Errorf("@context is %q", c.Context)
	}
	d := entity(t, c, "ro-crate-metadata.json")
	if d["@type"] != "CreativeWork" {
		t.Errorf("the descriptor is a %v, not a CreativeWork", d["@type"])
	}
	if about, _ := d["about"].(map[string]any); about["@id"] != "./" {
		t.Errorf("the descriptor points at %v, not the root", d["about"])
	}
	conf, _ := d["conformsTo"].(map[string]any)
	if conf["@id"] != "https://w3id.org/ro/crate/1.1" {
		t.Errorf("conformsTo is %v", d["conformsTo"])
	}

	root := entity(t, c, "./")
	for _, required := range []string{"name", "description", "datePublished", "license"} {
		if root[required] == nil {
			t.Errorf("the root has no %s, which the specification requires", required)
		}
	}
	if root["datePublished"] != "2026-08-20T09:00:00Z" {
		t.Errorf("datePublished is %v, want RFC3339 UTC", root["datePublished"])
	}
}

// The checksum is the difference between a crate and a folder. A crate that
// describes a file without saying what its bytes hash to cannot be verified,
// which is the only reason to produce one.
func TestEveryFileCarriesItsChecksum(t *testing.T) {
	c := build(t)
	for _, f := range good() {
		e := entity(t, c, f.Path)
		if e["sha256"] != f.SHA256 {
			t.Errorf("%s: sha256 is %v, want %s", f.Path, e["sha256"], f.SHA256)
		}
		if e["@type"] != "File" {
			t.Errorf("%s is a %v, not a File", f.Path, e["@type"])
		}
		if e["contentSize"] != f.Size {
			t.Errorf("%s: contentSize is %v, want %d", f.Path, e["contentSize"], f.Size)
		}
	}
}

// hasPart is how a reader enumerates the crate. One that lists fewer files than
// the crate contains hands over a deposit that silently drops content, and one
// that lists more points at nothing.
func TestTheRootListsEveryFileAndNothingElse(t *testing.T) {
	c := build(t)
	root := entity(t, c, "./")
	parts, _ := root["hasPart"].([]any)
	if len(parts) != len(good()) {
		t.Fatalf("the root lists %d parts for %d files", len(parts), len(good()))
	}
	listed := map[string]bool{}
	for _, p := range parts {
		m, _ := p.(map[string]any)
		listed[m["@id"].(string)] = true
	}
	for _, f := range good() {
		if !listed[f.Path] {
			t.Errorf("%s is in the crate but not listed in hasPart", f.Path)
		}
	}
}

// A licence is required by the specification, and guessing one on a
// depositor's behalf is a legal claim this program is in no position to make.
func TestACrateWithNoLicenceIsRefusedRatherThanDefaulted(t *testing.T) {
	o := opts()
	o.License = ""
	_, err := rocrate.Build(good(), when, o)
	if err == nil {
		t.Fatal("built a crate with no licence")
	}
	if !strings.Contains(err.Error(), "licence") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

func TestACrateWithNoNameIsRefused(t *testing.T) {
	o := opts()
	o.Name = ""
	if _, err := rocrate.Build(good(), when, o); err == nil {
		t.Fatal("built a nameless crate")
	}
}

// An author named on two files is one Person entity referenced twice, not two
// entities with the same name. A reader deduplicating by @id would otherwise
// see one contributor as several.
func TestAnAuthorOnSeveralFilesIsOnePerson(t *testing.T) {
	files := good()
	files[1].Author = "Ada Lovelace"
	c, err := rocrate.Build(files, when, opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	people := 0
	for _, e := range c.Graph {
		if e["@type"] == "Person" {
			people++
		}
	}
	if people != 1 {
		t.Fatalf("two files by one author produced %d Person entities", people)
	}
	for _, f := range files {
		e := entity(t, c, f.Path)
		ref, _ := e["author"].(map[string]any)
		if ref["@id"] != "#author-ada-lovelace" {
			t.Errorf("%s: author is %v", f.Path, e["author"])
		}
	}
}

// The graph is a set of entities addressed by @id. Two sharing one means a
// reference resolves to neither, and JSON-LD processors differ on which wins.
//
// Duplicating a File rather than the root, deliberately. A second "./" is also
// rejected — but for the wrong reason: it becomes the root, and fails the
// required-properties check instead. That version of this test passed with the
// duplicate guard removed entirely, so it proved nothing about the guard it
// was named after. A duplicated File passes every other check there is.
func TestADuplicateIDIsRefused(t *testing.T) {
	c := build(t)
	c.Graph = append(c.Graph, rocrate.Entity{
		"@id": "content/about.md", "@type": "File", "name": "Something else"})
	err := c.Validate()
	if err == nil {
		t.Fatal("validated a graph with two entities sharing an @id")
	}
	if !strings.Contains(err.Error(), "content/about.md") {
		t.Errorf("the error does not name the duplicate: %v", err)
	}
}

// A hasPart pointing at nothing is a crate that claims to contain a file it
// does not describe — exactly the failure a checksum manifest prevents.
func TestAPartWithNoEntityIsRefused(t *testing.T) {
	c := build(t)
	root := entity(t, c, "./")
	root["hasPart"] = append(root["hasPart"].([]any),
		map[string]any{"@id": "content/ghost.md"})
	if err := c.Validate(); err == nil {
		t.Fatal("validated a crate listing a part nothing describes")
	}
}

func TestAMissingDescriptorIsRefused(t *testing.T) {
	c := build(t)
	kept := c.Graph[:0]
	for _, e := range c.Graph {
		if e["@id"] != "ro-crate-metadata.json" {
			kept = append(kept, e)
		}
	}
	c.Graph = kept
	if err := c.Validate(); err == nil {
		t.Fatal("validated a crate with no metadata descriptor")
	}
}

// Ordering has to be stable or two exports of unchanged content produce
// different bytes, and anybody diffing deposits sees noise.
func TestTwoBuildsOfTheSameContentAreIdentical(t *testing.T) {
	shuffled := []rocrate.File{good()[1], good()[0]}
	a, err := rocrate.Build(good(), when, opts())
	if err != nil {
		t.Fatal(err)
	}
	b, err := rocrate.Build(shuffled, when, opts())
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("the same files in a different order produced different crates:\n%s\n%s", ja, jb)
	}
}
