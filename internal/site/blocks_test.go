// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func blockPages() map[string]any {
	return map[string]any{
		"index": map[string]any{"title": "Home", "sections": []any{
			map[string]any{"id": "a1", "hero": map[string]any{"title": "Welcome"}},
			map[string]any{"id": "a2", "block": map[string]any{"page": "cta"}},
			map[string]any{"id": "a3", "block": map[string]any{"page": "about"}},
			map[string]any{"id": "a4", "block": map[string]any{"page": "secret"}},
		}},
		"about": map[string]any{"title": "About", "sections": []any{
			map[string]any{"block": map[string]any{"page": "cta"}},
		}},
		"cta": map[string]any{"title": "Call", "block": true, "sections": []any{
			map[string]any{"cta": map[string]any{"title": "Order a sample"}},
			map[string]any{"block": map[string]any{"page": "cta"}},
		}},
		"secret": map[string]any{"title": "Members", "block": true, "members_only": true, "sections": []any{
			map[string]any{"text": map[string]any{"title": "Members' prices"}},
		}},
	}
}

// A page shows a block's sections where it reuses it, and nothing where it
// names a page that is not a block, a block for members, or a block from
// inside a block; nothing it was given is changed.
func TestABlockIsShownWhereAPageReusesIt(t *testing.T) {
	pages := blockPages()
	before, _ := json.Marshal(pages)
	got, used := ExpandBlocks(pages["index"], pages)
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), "Order a sample") || strings.Contains(string(b), "Members' prices") ||
		strings.Contains(string(b), `"block"`) {
		t.Fatalf("%s", b)
	}
	if secs := got.(map[string]any)["sections"].([]any); len(secs) != 2 {
		t.Fatalf("%d sections: %s", len(secs), b)
	}
	if !reflect.DeepEqual(used, []string{"cta"}) {
		t.Fatalf("used %v", used)
	}
	after, _ := json.Marshal(pages)
	if string(before) != string(after) {
		t.Fatal("expanding changed the pages it read")
	}
	if same, used := ExpandBlocks(pages["cta"], pages); len(used) != 0 || !reflect.DeepEqual(same, pages["cta"]) {
		t.Fatal("a block was expanded as a page")
	}
	read := WithBlocks(pages)
	if _, ok := read["cta"]; ok {
		t.Fatal("a block is read as a page of its own")
	}
	if _, ok := Visible(pages, time.Now())["cta"]; ok {
		t.Fatal("a block is visible as a page of its own")
	}
}

// Where each block is used, and the changes that would leave a page
// showing nothing it meant to are refused.
func TestWhereABlockIsUsed(t *testing.T) {
	pages := blockPages()
	uses := BlockUses(pages)
	if !reflect.DeepEqual(uses["cta"], []string{"about", "index"}) || len(uses["secret"]) != 1 || uses["about"][0] != "index" {
		t.Fatalf("%v", uses)
	}
	if !reflect.DeepEqual(Blocks(pages), []string{"cta", "secret"}) {
		t.Fatalf("%v", Blocks(pages))
	}
	if err := BlockChange("cta", pages, false); err == nil || !strings.Contains(err.Error(), "about, index") {
		t.Errorf("a block pages reuse made a page: %v", err)
	}
	if err := BlockChange("index", pages, true); err == nil {
		t.Error("the home page made a block")
	}
	if err := BlockChange("about", pages, true); err == nil {
		t.Error("a page reusing a block made a block")
	}
	pages["plain"] = map[string]any{"title": "Plain"}
	if err := BlockChange("plain", pages, true); err != nil {
		t.Error(err)
	}
	if err := CanReuse("index", "plain", pages); err == nil {
		t.Error("a page reused that is not a block")
	}
	if err := CanReuse("cta", "secret", pages); err == nil {
		t.Error("a block reused inside a block")
	}
}
