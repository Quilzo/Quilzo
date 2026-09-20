// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	oldID = "6ad5f75c7795a595655fd5902b6c65c75a4f6d3fbcd548dc5c0d439d05d7d9e2"
	newID = "78ef1d17633ea76cf3acea1196f2db6f4491687dd19c47b88021a2851d82d2cc"
)

func TestEverySpellingIsRewrittenAndKeepsItsSpelling(t *testing.T) {
	// The reader accepts three spellings because this program writes three.
	// A writer that normalised them would replace the picture and break the
	// page: a template reads "/media/<id>" as a path, so handing it a bare id
	// renders <img src="6ad5..."> against nothing.
	for _, in := range []string{
		oldID,
		"/media/" + oldID,
		"media/" + oldID,
	} {
		out, n := ReplaceID(in, oldID, newID)
		if n != 1 {
			t.Fatalf("%q: %d reference(s) changed", in, n)
		}
		got, _ := out.(string)
		want := strings.Replace(in, oldID, newID, 1)
		if got != want {
			t.Errorf("%q became %q, wanted %q", in, got, want)
		}
		// And the reader agrees about what came out.
		if id, ok := IDIn(got); !ok || id != newID {
			t.Errorf("the reader does not recognise %q as %s", got, newID[:8])
		}
	}
}

func TestAPictureInsideASectionIsRewritten(t *testing.T) {
	// Every shipped layout puts its pictures inside sections, three levels
	// down. A walk that read the top level would rewrite records and leave
	// every page — which is the exact miss the rights gate had before IDsIn
	// recursed.
	page := map[string]any{
		"title": "Seasonal",
		"sections": []any{
			map[string]any{"kind": "hero"},
			map[string]any{
				"kind":  "split",
				"split": map[string]any{"image": "/media/" + oldID},
			},
		},
	}
	out, n := ReplaceID(page, oldID, newID)
	if n != 1 {
		t.Fatalf("%d reference(s) changed three levels down", n)
	}
	if ids := IDsIn(out); len(ids) != 1 || ids[0] != newID {
		t.Fatalf("after the rewrite the page refers to %v", ids)
	}
}

func TestOneFileUsedTwiceIsRewrittenTwice(t *testing.T) {
	// IDsIn deduplicates, because one file used twice is one licence. This
	// must not: a count of references is what the command reports, and
	// leaving the second one behind would be a page half replaced.
	page := map[string]any{
		"hero":  "/media/" + oldID,
		"thumb": oldID,
	}
	out, n := ReplaceID(page, oldID, newID)
	if n != 2 {
		t.Fatalf("%d reference(s) changed; both should have", n)
	}
	m := out.(map[string]any)
	if m["hero"] != "/media/"+newID || m["thumb"] != newID {
		t.Fatalf("the page still holds %v", m)
	}
}

func TestNothingElseIsTouched(t *testing.T) {
	other := "a5b1f3c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f"
	page := map[string]any{
		"image":   oldID,
		"another": other,
		"hash":    "not a media reference",
		"count":   float64(3),
		"live":    true,
		"nested":  []any{map[string]any{"x": other}},
	}
	out, n := ReplaceID(page, oldID, newID)
	if n != 1 {
		t.Fatalf("%d reference(s) changed", n)
	}
	m := out.(map[string]any)
	if m["another"] != other {
		t.Error("a different picture was rewritten")
	}
	if m["hash"] != "not a media reference" || m["count"] != float64(3) ||
		m["live"] != true {
		t.Errorf("a value that is not a reference changed: %v", m)
	}
}

func TestTheContentGoingInIsNotModified(t *testing.T) {
	// Content here comes out of a content-addressed object. A walk that
	// edited in place would be editing bytes something else may still be
	// holding under their own hash — and the store's whole promise is that
	// the old object is still what it was.
	page := map[string]any{
		"sections": []any{map[string]any{"image": oldID}},
	}
	before, _ := json.Marshal(page)
	ReplaceID(page, oldID, newID)
	after, _ := json.Marshal(page)
	if string(before) != string(after) {
		t.Fatalf("the input changed:\n  before %s\n  after  %s", before, after)
	}
}

func TestTheRewriteIsBoundedTheSameWayTheWalkIs(t *testing.T) {
	// The same bound IDsIn has, for the same reason: content is nested by
	// authors and importers, and a walk with no limit is a way to spend the
	// process's stack on a page somebody wrote.
	deep := any("/media/" + oldID)
	for range maxReferenceDepth + 5 {
		deep = map[string]any{"in": deep}
	}
	_, n := ReplaceID(deep, oldID, newID)
	if n != 0 {
		t.Fatalf("%d reference(s) changed past the depth bound", n)
	}
	// And the reader agrees it cannot see that far either, so the two do not
	// disagree about what is in the content.
	if ids := IDsIn(deep); len(ids) != 0 {
		t.Fatalf("the reader sees %v past the bound and the writer does not; "+
			"a reference one can see and the other cannot is a picture "+
			"replaced everywhere the gate looks and still on the page", ids)
	}
}

func TestReplacingWithItselfChangesNothingVisible(t *testing.T) {
	page := map[string]any{"image": "/media/" + oldID}
	out, n := ReplaceID(page, oldID, oldID)
	if n != 1 {
		t.Fatalf("%d", n)
	}
	if !reflect.DeepEqual(out, page) {
		t.Fatalf("replacing a file with itself changed the content to %v", out)
	}
}
