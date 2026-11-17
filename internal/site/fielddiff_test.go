// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// A modified page says which of its fields changed and how: a reviewer
// told to read the change before approving it was shown the page's name
// and the word "modified", and nothing it said.
func TestAModifiedPageSaysWhichFieldsChangedAndHow(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	from, err := SaveDraft(s, map[string]any{
		"returns": map[string]any{"title": "Returns", "days": 30.0,
			"body": "Thirty days.\n\nWe pay the postage.\n\nInk is the exception."},
	}, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	to, err := SaveDraft(s, map[string]any{
		"returns": map[string]any{"title": "Returns", "days": 14.0, "note": "New",
			"body": "Fourteen days.\n\nWe pay the postage.\n\nInk is the exception."},
	}, "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	changes, err := Diff(s, from, to)
	if err != nil || len(changes) != 1 {
		t.Fatalf("%v %v", changes, err)
	}
	fields, err := FieldChanges(s, changes[0])
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]FieldChange{}
	for _, f := range fields {
		got[f.Field] = f
	}
	if _, ok := got["title"]; ok || len(got) != 3 {
		t.Fatalf("changed fields are %v", fields)
	}
	if d := got["days"]; d.Before != "30" || d.After != "14" {
		t.Errorf("days is %+v", d)
	}
	if n := got["note"]; n.Before != "" || n.After != "New" {
		t.Errorf("note is %+v", n)
	}
	want := []LineChange{{"-", "Thirty days."}, {"+", "Fourteen days."}, {" ", ""},
		{" ", "We pay the postage."}, {" ", ""}, {" ", "Ink is the exception."}}
	lines := got["body"].Lines
	if len(lines) != len(want) {
		t.Fatalf("body lines are %v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d is %v, want %v", i, lines[i], want[i])
		}
	}
}
