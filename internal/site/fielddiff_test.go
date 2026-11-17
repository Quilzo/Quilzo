// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"fmt"
	"strings"
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

// fieldChangesBetween saves two versions of one page and says what differs.
func fieldChangesBetween(t *testing.T, before, after map[string]any) map[string]FieldChange {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	from, err := SaveDraft(s, map[string]any{"page": before}, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	to, err := SaveDraft(s, map[string]any{"page": after}, "second", "test")
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
	return got
}

// A value that changed kind and not characters is still a change somebody
// approving the page has to be able to read: the number 10 turned into the
// text "10", or false into the text "false", which a layout reads as true.
// Shown as written, both sides said 10, and the change read as none.
func TestAChangeOfKindIsNotShownAsTheSameValueTwice(t *testing.T) {
	got := fieldChangesBetween(t,
		map[string]any{"title": "T", "rows": 10.0, "featured": false},
		map[string]any{"title": "T", "rows": "10", "featured": "false"})
	if r := got["rows"]; r.Before != `10` || r.After != `"10"` {
		t.Errorf("rows is shown as %q then %q", r.Before, r.After)
	}
	if f := got["featured"]; f.Before != `false` || f.After != `"false"` {
		t.Errorf("featured is shown as %q then %q", f.Before, f.After)
	}
}

// A long text with one line changed is compared line by line, however
// long it is: the lines both versions begin and end with are not part of
// the work. Past the bound it was shown whole, twice, and the one changed
// line among thousands was for the reader to find.
func TestOneChangedLineIsFoundInALongText(t *testing.T) {
	var before, after strings.Builder
	for i := 0; i < 3*maxLineDiff; i++ {
		line := fmt.Sprintf("Line %d of the terms.\n", i)
		before.WriteString(line)
		if i == maxLineDiff+7 {
			line = "The line somebody changed.\n"
		}
		after.WriteString(line)
	}
	got := fieldChangesBetween(t,
		map[string]any{"body": before.String()}, map[string]any{"body": after.String()})
	var changed []LineChange
	for _, l := range got["body"].Lines {
		if l.Op != " " {
			changed = append(changed, l)
		}
	}
	want := []LineChange{
		{"-", fmt.Sprintf("Line %d of the terms.", maxLineDiff+7)},
		{"+", "The line somebody changed."},
	}
	if len(changed) != len(want) || changed[0] != want[0] || changed[1] != want[1] {
		t.Fatalf("the changed lines are %v, want %v", changed, want)
	}
	if n := len(got["body"].Lines); n != 3*maxLineDiff+2 {
		t.Errorf("the comparison has %d lines, want every line of the text and the one replaced", n)
	}

	// Two long texts with nothing in common are still shown whole: that
	// comparison is the work the bound is there to refuse.
	var other strings.Builder
	for i := 0; i < 3*maxLineDiff; i++ {
		fmt.Fprintf(&other, "Another line, %d.\n", i)
	}
	got = fieldChangesBetween(t,
		map[string]any{"body": before.String()}, map[string]any{"body": other.String()})
	if got["body"].Lines != nil || got["body"].Before == "" || got["body"].After == "" {
		t.Errorf("two long unrelated texts were compared line by line: %d lines", len(got["body"].Lines))
	}
}
