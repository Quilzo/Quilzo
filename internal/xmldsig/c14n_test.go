// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package xmldsig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Every element of every document in testdata/c14n, canonicalised here and
// by libxml2 (testdata/gen_c14n.py), with four PrefixLists. Agreement with
// an implementation that shares no code with this one is the evidence that
// a signature made by somebody else's software verifies here.
func TestCanonicalAgreesWithLibxml2(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "c14n", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		File      string   `json:"file"`
		Path      []int    `json:"path"`
		Inclusive []string `json:"inclusive"`
		C14N      string   `json:"c14n"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 200 {
		t.Fatalf("only %d cases; the corpus shrank", len(cases))
	}
	docs := map[string]*Document{}
	for _, c := range cases {
		d := docs[c.File]
		if d == nil {
			b, err := os.ReadFile(filepath.Join("testdata", "c14n", c.File))
			if err != nil {
				t.Fatal(err)
			}
			if d, err = Read(b); err != nil {
				t.Fatalf("%s: %v", c.File, err)
			}
			docs[c.File] = d
		}
		if len(c.Inclusive) == 1 && c.Inclusive[0] == "#default" {
			// Where libxml2 and the standard's wording part company; a
			// signature naming it is refused (TestDefaultInPrefixListIsRefused).
			continue
		}
		e := d.Root
		for _, i := range c.Path {
			kids, _ := e.Elements()
			e = kids[i]
		}
		got, err := Canonical(e, c.Inclusive, nil)
		if err != nil {
			t.Errorf("%s %v %v: %v", c.File, c.Path, c.Inclusive, err)
			continue
		}
		if string(got) != c.C14N {
			t.Errorf("%s %v %v:\n  got  %s\n  want %s", c.File, c.Path, c.Inclusive, got, c.C14N)
		}
	}
}

// What is canonicalised reads back to itself: the property VerifyEnveloped
// relies on to hand back only what was signed.
func TestCanonicalIsAFixedPoint(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "c14n", "*.xml"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		d, err := Read(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, incl := range [][]string{nil, {"xs"}, {"#default"}} {
			once, err := Canonical(d.Root, incl, nil)
			if err != nil {
				t.Fatal(err)
			}
			d2, err := Read(once)
			if err != nil {
				t.Fatalf("%s: the canonical form does not read: %v", f, err)
			}
			twice, err := Canonical(d2.Root, incl, nil)
			if err != nil {
				t.Fatal(err)
			}
			if string(once) != string(twice) {
				t.Errorf("%s %v is not a fixed point:\n  %s\n  %s", f, incl, once, twice)
			}
		}
	}
}
