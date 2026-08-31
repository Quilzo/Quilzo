package main

import (
	"strings"
	"testing"
)

// The scanner reads a page at every depth, or it reads almost nothing.
//
// collectInputs read the top level of each page and stopped. A page built the
// way the shipped layouts want keeps its text in a hero object and a list of
// section objects, so a <script> tag or a credential written inside a prose
// section was never scanned — while the same string at the top level was a
// critical finding. `quilzo scan --fail-on high` is what a pipeline runs, and on
// the recommended content shape it was reporting a clean scan of two fields.
//
// Demonstrated by putting the same key at two depths on one page and watching
// one of them go unreported.
func TestContentIsScannedAtEveryDepth(t *testing.T) {
	page := map[string]any{
		"title": "Leak test",
		"body":  "A top-level secret: AKIAIOSFODNN7EXAMPLE",
		"hero": map[string]any{
			"lead": "In the hero: <script>alert(1)</script>",
		},
		"sections": []any{
			map[string]any{"prose": map[string]any{
				"paragraphs": []any{"Nested: AKIAIOSFODNN7EXAMPLE"},
			}},
		},
	}

	fields := contentStrings(page)
	paths := map[string]string{}
	for _, f := range fields {
		paths[f.path] = f.text
	}
	for _, want := range []string{"body", "hero.lead",
		"sections.0.prose.paragraphs.0"} {
		if _, ok := paths[want]; !ok {
			t.Errorf("%s was not collected, so nothing scans it:\n\t%v",
				want, paths)
		}
	}
	// The field's own name travels with it, because the credential rules match
	// a name and a value together.
	for _, f := range fields {
		if f.path == "sections.0.prose.paragraphs.0" && f.key != "paragraphs" {
			t.Errorf("the nested field's key is %q; the rules look for a name "+
				"beside the value", f.key)
		}
	}
	// A path a reader can act on: it says which section to open.
	for _, f := range fields {
		if strings.Contains(f.path, "..") {
			t.Errorf("the path %q is malformed", f.path)
		}
	}
}
