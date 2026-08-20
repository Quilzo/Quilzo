// Package rocrate packages a publication as a research object.
//
// # What this is for
//
// RO-Crate is how research data is handed over: content, checksums, provenance
// and licence in one self-describing bundle that both a person and a machine
// can read. It is used across bioinformatics, digital humanities and regulatory
// science, and its Workflow Run profile exists specifically to make an analysis
// reproducible by recording what went in, what came out, and the sha256 of
// each.
//
// That is a description of the store this program already keeps. Content
// addressed by the hash of its own bytes, arranged in trees, published by
// moving a pointer, with an append-only record of who changed what. Exporting
// a crate is a serialisation of facts that already exist — no new state, no
// second source of truth, and nothing that has to be kept in step.
//
// # Why a CMS should do this at all
//
// Because a publication is evidence. A regulator asking what a site said on a
// date, a journal asking for the dataset behind a figure, an archivist taking a
// deposit — each of them wants the bytes plus enough context to know what they
// are, and each currently gets a zip file and an email. A crate is the format
// that community already reads.
//
// # What it does not claim
//
// A crate says what was published and what its checksums are. It does not
// certify that the content is correct, that the provenance is complete for
// anything that happened outside this store, or that the licence is one the
// depositor had the right to grant. Those are claims about the world; this is
// a claim about bytes.
package rocrate

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Context is the RO-Crate 1.1 JSON-LD context.
const Context = "https://w3id.org/ro/crate/1.1/context"

// ConformsTo is the profile URI the descriptor points at.
const ConformsTo = "https://w3id.org/ro/crate/1.1"

// MetadataFile is the name the specification fixes for the descriptor.
//
// Not configurable. A crate is recognised by a consumer looking for exactly
// this filename at the root, and a crate that named it anything else would be
// a directory of files.
const MetadataFile = "ro-crate-metadata.json"

// Crate is the metadata document.
//
// A flat @graph rather than nested objects, which is how JSON-LD expresses a
// set of entities that refer to one another by @id. Nesting would render the
// same facts and would not round-trip through any RO-Crate reader.
type Crate struct {
	Context string   `json:"@context"`
	Graph   []Entity `json:"@graph"`
}

// Entity is one node in the graph.
//
// A map rather than a struct per type. RO-Crate entities are schema.org terms
// and the useful ones differ by type — a Dataset has hasPart, a File has
// contentSize, a Person has affiliation — so a struct would either be a union
// of every field with most of them empty, or a type hierarchy that has to grow
// whenever a new term is worth emitting.
type Entity map[string]any

// Options are the facts the store does not carry.
type Options struct {
	// Name disambiguates this crate from another.
	Name string
	// Description says what it is.
	Description string
	// License is a URI. Required by the specification, and refused when empty
	// rather than defaulted: a deposit whose licence somebody guessed is worse
	// than one that would not build.
	License string
	// Publisher is the organisation depositing it.
	Publisher string
	// Version is the build that produced the crate.
	Version string
	// Commit is the published commit this crate is of.
	Commit string
}

// File is one published thing, with the hash that names it.
type File struct {
	// Path inside the crate, relative and without a leading slash.
	Path string
	// SHA256 of the bytes, hex. This is the whole point of the format: a
	// consumer can verify the file is the one the metadata describes.
	SHA256 string
	// Size in bytes.
	Size int64
	// MediaType, when known.
	MediaType string
	// Name is what to call it in a listing.
	Name string
	// Description, when the store holds one — an image's alt text is a
	// description somebody wrote, and it is more useful here than a filename.
	Description string
	// Author is who wrote it, when the history says.
	Author string
	// DateModified is when it last changed.
	DateModified string
}

// Build assembles a crate for a set of published files.
func Build(files []File, at time.Time, o Options) (Crate, error) {
	if strings.TrimSpace(o.License) == "" {
		return Crate{}, fmt.Errorf(
			"a crate needs a licence: the specification requires one on the " +
				"root, and a deposit whose licence somebody guessed is worse " +
				"than one that would not build")
	}
	if strings.TrimSpace(o.Name) == "" {
		return Crate{}, fmt.Errorf("a crate needs a name to be told apart from another")
	}

	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	parts := make([]any, 0, len(sorted))
	for _, f := range sorted {
		parts = append(parts, map[string]any{"@id": f.Path})
	}

	root := Entity{
		"@id":           "./",
		"@type":         "Dataset",
		"name":          o.Name,
		"description":   nonEmpty(o.Description, o.Name),
		"datePublished": at.UTC().Format(time.RFC3339),
		"license":       map[string]any{"@id": o.License},
		"hasPart":       parts,
	}
	if o.Publisher != "" {
		root["publisher"] = map[string]any{"@id": "#publisher"}
	}
	if o.Commit != "" {
		// The commit this crate is of, as an identifier a reader can check
		// against the store. Content addressing is what makes this meaningful:
		// the same identifier always names the same bytes.
		root["identifier"] = "sha256:" + o.Commit
	}

	graph := []Entity{
		{
			"@id":        MetadataFile,
			"@type":      "CreativeWork",
			"conformsTo": map[string]any{"@id": ConformsTo},
			"about":      map[string]any{"@id": "./"},
		},
		root,
	}

	if o.Publisher != "" {
		graph = append(graph, Entity{
			"@id":   "#publisher",
			"@type": "Organization",
			"name":  o.Publisher,
		})
	}

	authors := map[string]bool{}
	for _, f := range sorted {
		e := Entity{
			"@id":   f.Path,
			"@type": "File",
		}
		if f.Name != "" {
			e["name"] = f.Name
		}
		if f.Description != "" {
			e["description"] = f.Description
		}
		if f.MediaType != "" {
			e["encodingFormat"] = f.MediaType
		}
		if f.Size > 0 {
			e["contentSize"] = f.Size
		}
		if f.SHA256 != "" {
			// The checksum, under the property RO-Crate consumers read. This
			// is the difference between a crate and a folder: a reader can
			// tell whether the file is the one the metadata describes.
			e["sha256"] = f.SHA256
		}
		if f.DateModified != "" {
			e["dateModified"] = f.DateModified
		}
		if f.Author != "" {
			e["author"] = map[string]any{"@id": "#author-" + slug(f.Author)}
			authors[f.Author] = true
		}
		graph = append(graph, e)
	}

	names := make([]string, 0, len(authors))
	for a := range authors {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		graph = append(graph, Entity{
			"@id":   "#author-" + slug(a),
			"@type": "Person",
			"name":  a,
		})
	}

	return Crate{Context: Context, Graph: graph}, nil
}

// Validate refuses a crate a consumer would reject.
//
// The specification's required set is small and specific, and a crate missing
// any of it is a directory with a JSON file in it. Checked before writing,
// because the alternative is finding out from whoever the deposit was for.
func (c Crate) Validate() error {
	if c.Context != Context {
		return fmt.Errorf("@context is %q, want %q", c.Context, Context)
	}
	var descriptor, root Entity
	ids := map[string]bool{}
	for _, e := range c.Graph {
		id, _ := e["@id"].(string)
		if id == "" {
			return fmt.Errorf("an entity in the graph has no @id")
		}
		if ids[id] {
			return fmt.Errorf(
				"two entities share the @id %q, so a reference to it names "+
					"neither of them", id)
		}
		ids[id] = true
		switch id {
		case MetadataFile:
			descriptor = e
		case "./":
			root = e
		}
	}
	if descriptor == nil {
		return fmt.Errorf(
			"no %s descriptor entity; a consumer identifies a crate by "+
				"finding exactly that", MetadataFile)
	}
	if root == nil {
		return fmt.Errorf("no root data entity with @id \"./\"")
	}
	if about, _ := descriptor["about"].(map[string]any); about == nil ||
		about["@id"] != "./" {
		return fmt.Errorf("the descriptor does not point at the root data entity")
	}
	for _, required := range []string{"name", "description", "datePublished", "license"} {
		if v, there := root[required]; !there || v == nil || v == "" {
			return fmt.Errorf(
				"the root data entity has no %s, which the specification "+
					"requires", required)
		}
	}
	if t, _ := root["@type"].(string); t != "Dataset" {
		return fmt.Errorf("the root data entity is a %q, not a Dataset", t)
	}

	// Every referenced part exists in the graph. A hasPart pointing at nothing
	// is a crate that says it contains a file it does not describe, which is
	// the failure a checksum manifest is supposed to prevent.
	parts, _ := root["hasPart"].([]any)
	for _, p := range parts {
		m, _ := p.(map[string]any)
		id, _ := m["@id"].(string)
		if !ids[id] {
			return fmt.Errorf(
				"the root claims a part %q that no entity in the graph "+
					"describes", id)
		}
	}
	return nil
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
