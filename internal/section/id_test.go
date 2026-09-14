// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package section

import (
	"fmt"
	"testing"
)

// fixedIDs makes the generator countable, so a test can say which section it
// means.
func fixedIDs(t *testing.T) {
	t.Helper()
	n := 0
	old := newID
	newID = func() string { n++; return fmt.Sprintf("id%d", n) }
	t.Cleanup(func() { newID = old })
}

func threeSections(t *testing.T) map[string]any {
	t.Helper()
	body := map[string]any{"title": "A page"}
	var err error
	for i, kind := range []string{"prose", "quote", "notice"} {
		body, err = Insert(body, kind, i)
		if err != nil {
			t.Fatal(err)
		}
	}
	return body
}

// A section keeps its name when one above it goes.
//
// It had no name. Placed carried an Index and nothing else, and Insert, Remove
// and Move were index arithmetic — fine while one person is looking at one
// screen and wrong the moment two are.
func TestASectionKeepsItsNameWhenOneAboveItGoes(t *testing.T) {
	fixedIDs(t)
	body := threeSections(t)

	placed := On(body)
	if len(placed) != 3 {
		t.Fatalf("%d sections", len(placed))
	}
	third := placed[2].ID
	if third == "" {
		t.Fatal("a section has no id, so nothing can point at it")
	}

	next, err := Remove(body, 0)
	if err != nil {
		t.Fatal(err)
	}
	at, ok := IndexOf(next, third)
	if !ok {
		t.Fatal("the section that was third cannot be found after the first " +
			"was removed; its name did not survive")
	}
	if at != 1 {
		t.Errorf("it is now at %d, want 1", at)
	}
	// And it is the same section, not the one that took its place.
	if On(next)[at].Kind != "notice" {
		t.Errorf("the id now names a %s", On(next)[at].Kind)
	}
}

// Which is the bug: the same thing by position picks the wrong one.
//
// Somebody with the Sections screen open decides to remove the third section.
// A colleague adds a banner at the top. By position, the wrong section goes —
// nothing fails, and the page is missing something else.
func TestByPositionTheWrongSectionIsRemoved(t *testing.T) {
	fixedIDs(t)
	body := threeSections(t)
	meant := On(body)[2].ID

	// The colleague's insertion.
	moved, err := Insert(body, "cta", 0)
	if err != nil {
		t.Fatal(err)
	}

	// By position, as it was.
	byIndex, err := Remove(moved, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, stillThere := IndexOf(byIndex, meant); !stillThere {
		t.Fatal("the premise is wrong: the section meant was removed")
	}

	// By name, as it is.
	at, ok := IndexOf(moved, meant)
	if !ok {
		t.Fatal("the section meant cannot be found")
	}
	byName, err := Remove(moved, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, stillThere := IndexOf(byName, meant); stillThere {
		t.Error("removing by name did not remove the section that was named")
	}
}

// A page written before ids existed gains them on the edit that needs them.
//
// Lazily rather than by migration: a migration over a content-addressed store
// would rewrite every page's hash to add a field nothing was using yet.
func TestAPageWithoutIDsGainsThemWhenItIsArranged(t *testing.T) {
	fixedIDs(t)
	old := map[string]any{
		"title": "Written before this existed",
		"sections": []any{
			map[string]any{"prose": map[string]any{"paragraphs": []any{"One."}}},
			map[string]any{"quote": map[string]any{"text": "Two."}},
		},
	}
	for _, p := range On(old) {
		if p.ID != "" {
			t.Fatal("the premise is wrong: it already has ids")
		}
	}

	next, err := Move(old, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range On(next) {
		if p.ID == "" {
			t.Error("a section still has no id after the page was arranged")
		}
	}

	// And the ids are distinct, or naming one names two.
	seen := map[string]bool{}
	for _, p := range On(next) {
		if seen[p.ID] {
			t.Errorf("two sections share the id %q", p.ID)
		}
		seen[p.ID] = true
	}
}

// The id is not a second kind.
//
// It sits beside the kind rather than among its fields, so the rule that
// refuses two sections written as one had to learn the difference — otherwise
// every named section is a blocking validation failure and the arrangement
// gate refuses the publish.
func TestAnIDIsNotASecondKind(t *testing.T) {
	fixedIDs(t)
	body := threeSections(t)

	blocking, _ := Validate(body)
	for _, p := range blocking {
		t.Errorf("a named section is reported as a problem: %s", p.Detail)
	}

	// Two actual kinds on one entry is still refused.
	two := map[string]any{"sections": []any{map[string]any{
		IDField: "abc",
		"prose": map[string]any{"paragraphs": []any{"One."}},
		"quote": map[string]any{"text": "Two."},
	}}}
	if blocking, _ := Validate(two); len(blocking) == 0 {
		t.Error("two kinds on one entry are no longer refused, so one of " +
			"them renders and the other is silently dropped")
	}
}
