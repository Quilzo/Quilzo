// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"strings"
	"testing"
)

const anID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const another = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// Every spelling this program writes is recognised.
//
// It writes more than one: the picker and the chat editor store "/media/<id>"
// because that is what a template needs, and an importer and a record store
// the bare id. A reader that accepted only one was blind to half the pictures
// on the site.
func TestEverySpellingOfAReferenceIsRead(t *testing.T) {
	for _, spelling := range []string{
		anID, "/media/" + anID, "media/" + anID, "  /media/" + anID + "  ",
	} {
		got, ok := IDIn(spelling)
		if !ok || got != anID {
			t.Errorf("%q read as %q/%v", spelling, got, ok)
		}
	}
}

// And nothing else is.
//
// An external URL that happens to end in something hexadecimal is not a file
// in this library, and treating it as one would have the rights gate reporting
// on a picture nobody here stores.
func TestSomethingElseIsNotAReference(t *testing.T) {
	for _, v := range []string{
		"", "hello", anID[:63], anID + "0", strings.ToUpper(anID),
		"https://example.com/media/" + anID,
		"/media/" + anID + "/thumb",
		"/other/" + anID,
	} {
		if got, ok := IDIn(v); ok {
			t.Errorf("%q was read as the reference %q", v, got)
		}
	}
}

// A picture inside a section is found.
//
// This is the bug. The walk read the top level of the map and the direct
// members of a list, so a record — a flat map — was checked and a page was
// not. Every shipped layout puts its pictures at page.sections[3].split.image,
// three levels down, so the gate that refuses to publish an expired licence
// had never examined a single image on a page.
func TestAPictureInsideASectionIsFound(t *testing.T) {
	page := map[string]any{
		"title": "A page",
		"sections": []any{
			map[string]any{"prose": map[string]any{"title": "Words"}},
			map[string]any{"split": map[string]any{
				"title": "Beside", "image": "/media/" + anID,
			}},
			map[string]any{"gallery": map[string]any{
				"items": []any{
					map[string]any{"image": another, "alt": "a picture"},
				},
			}},
		},
	}
	got := IDsIn(page)
	if len(got) != 2 {
		t.Fatalf("found %d picture(s): %v", len(got), got)
	}
	if got[0] != anID || got[1] != another {
		t.Errorf("found %v", got)
	}
}

// A flat record still works, because that is what used to work and a site full
// of product photographs depends on it.
func TestAFlatRecordStillWorks(t *testing.T) {
	rec := map[string]any{"slug": "brass-pen", "image": anID, "price": 4600.0}
	if got := IDsIn(rec); len(got) != 1 || got[0] != anID {
		t.Errorf("found %v", got)
	}
}

// One file used twice is one file.
//
// A caller counting uses to decide whether a licence covers them would
// otherwise count the same licence twice, and a gate would name the same
// picture in two findings.
func TestOneFileUsedTwiceIsCountedOnce(t *testing.T) {
	page := map[string]any{
		"hero":  map[string]any{"image": anID},
		"share": "/media/" + anID,
	}
	if got := IDsIn(page); len(got) != 1 {
		t.Errorf("found %d, want 1: %v", len(got), got)
	}
}

// The walk is bounded, because content is nested by authors and by importers
// and a walk without a limit is a way to spend the stack on a page somebody
// wrote.
func TestTheWalkIsBounded(t *testing.T) {
	deep := any(anID)
	for i := 0; i < 400; i++ {
		deep = map[string]any{"in": deep}
	}
	// The property is that it returns rather than that it finds anything: past
	// the limit the reference is deliberately out of reach.
	got := IDsIn(deep)
	if len(got) != 0 {
		t.Errorf("a reference %d levels down was read: %v", 400, got)
	}

	shallow := any(anID)
	for i := 0; i < 5; i++ {
		shallow = map[string]any{"in": shallow}
	}
	if got := IDsIn(shallow); len(got) != 1 {
		t.Errorf("a reference five levels down was missed: %v", got)
	}
}

// Nothing in it, nothing out of it.
func TestOddContentIsNoReference(t *testing.T) {
	for name, v := range map[string]any{
		"nil":     nil,
		"number":  42.0,
		"boolean": true,
		"empty":   map[string]any{},
		"list":    []any{nil, 1.0, "x"},
	} {
		if got := IDsIn(v); len(got) != 0 {
			t.Errorf("%s produced %v", name, got)
		}
	}
}
