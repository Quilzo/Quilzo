// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package section

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The blanks on a page are found wherever they are, filled in everywhere
// they appear, and left out cleanly; the page passed in is not changed.
func TestBlanksAreFoundFilledAndLeftOut(t *testing.T) {
	var page map[string]any
	if err := json.Unmarshal([]byte(`{
		"title": "Visit",
		"hero": {"lead": "Find us at [[your address]]."},
		"sections": [
			{"prose": {"title": "Getting here", "paragraphs": ["[[how to get there]]", "Open [[your hours]] , every week."]}},
			{"faq": {"items": [{"q": "Where?", "a": "At [[your address]]."}]}}
		],
		"note": "[not a blank] and [[]] is not one either"
	}`), &page); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(page)

	got := Unfilled(page)
	want := []Blank{
		{"hero.lead", "your address"},
		{"sections.0.prose.paragraphs.0", "how to get there"},
		{"sections.0.prose.paragraphs.1", "your hours"},
		{"sections.1.faq.items.0.a", "your address"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("found %+v", got)
	}

	filled, n := Fill(page, map[string]string{"your address": "4 Mill Lane, Leeds", "how to get there": "", "your hours": ""})
	if n != 4 {
		t.Fatalf("filled %d places", n)
	}
	if left := Unfilled(filled); len(left) != 0 {
		t.Fatalf("still to fill: %+v", left)
	}
	f := filled.(map[string]any)
	if f["hero"].(map[string]any)["lead"] != "Find us at 4 Mill Lane, Leeds." {
		t.Errorf("the lead is %q", f["hero"].(map[string]any)["lead"])
	}
	paras := f["sections"].([]any)[0].(map[string]any)["prose"].(map[string]any)["paragraphs"].([]any)
	if len(paras) != 1 || paras[0] != "Open, every week." {
		t.Errorf("left out, the paragraphs are %q", paras)
	}
	if after, _ := json.Marshal(page); string(after) != string(before) {
		t.Error("filling changed the page it was given")
	}
	if _, n := Fill(page, map[string]string{"something else": "x"}); n != 0 {
		t.Errorf("a value for no blank filled %d places", n)
	}
}
