// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package section

import (
	"strings"
	"testing"
)

var loop = "/media/" + strings.Repeat("f", 64)

func heroPage() map[string]any {
	return map[string]any{"title": "Home", "hero": map[string]any{"title": "Hi"},
		"sections": []any{
			map[string]any{"features": map[string]any{"title": "Games", "tone": "tone-raised"}},
			map[string]any{"notice": map[string]any{"title": "Closed Monday"}},
		}}
}

// A section gets its backdrop as an operation, because an edit writes only
// fields that are there: the surface becomes media, the address is the
// library's, and nothing else moves.
func TestABackdropGoesBehindASectionAndComesAway(t *testing.T) {
	next, err := SetBackdrop(heroPage(), 0, loop)
	if err != nil {
		t.Fatal(err)
	}
	inner := next[Field].([]any)[0].(map[string]any)["features"].(map[string]any)
	if inner["surface"] != MediaSurface || inner[BackdropField] != loop || inner["tone"] != "tone-raised" {
		t.Errorf("the section is %v", inner)
	}
	if !On(next)[0].Backdrop {
		t.Error("the section's listing does not say it has a backdrop")
	}
	// The field may be left for a picker.
	if _, err := SetBackdrop(heroPage(), 0, ""); err != nil {
		t.Errorf("an empty backdrop for the picker to fill was refused: %v", err)
	}
	back, err := ClearBackdrop(next, 0)
	if err != nil {
		t.Fatal(err)
	}
	inner = back[Field].([]any)[0].(map[string]any)["features"].(map[string]any)
	if _, has := inner[BackdropField]; has || inner["surface"] != nil {
		t.Errorf("taking it away left %v", inner)
	}
	// And the original was not touched: the page body is shared.
	if _, has := heroPage()[Field].([]any)[0].(map[string]any)["features"].(map[string]any)["surface"]; has {
		t.Error("the page passed in was changed")
	}
}

// The hero takes a backdrop without a surface; a notice takes none; and an
// address from anywhere but the library is refused.
func TestABackdropIsOnlyWhereItCanBe(t *testing.T) {
	next, err := SetBackdrop(heroPage(), HeroAt, loop)
	if err != nil {
		t.Fatal(err)
	}
	hero := next["hero"].(map[string]any)
	if hero[BackdropField] != loop || hero["surface"] != nil {
		t.Errorf("the hero is %v", hero)
	}
	if _, err := SetBackdrop(heroPage(), 1, loop); err == nil {
		t.Error("a notice took a backdrop")
	}
	for _, bad := range []string{"https://example.com/loop.mp4", "/media/loop.mp4", "/media/../x"} {
		if _, err := SetBackdrop(heroPage(), 0, bad); err == nil {
			t.Errorf("%q became a backdrop", bad)
		}
	}
	if _, err := SetBackdrop(map[string]any{"title": "x"}, HeroAt, loop); err == nil {
		t.Error("a page with no hero took a hero backdrop")
	}
}

// A backdrop field and a surface are known on every kind, and what is worth
// saying about a card picture or an empty media surface is said, not refused.
func TestBackdropAndCardPictureFieldsAreKnown(t *testing.T) {
	body := map[string]any{"sections": []any{
		map[string]any{"split": map[string]any{"title": "x", "surface": "media"}},
		map[string]any{"features": map[string]any{"title": "x", "items": []any{
			map[string]any{"title": "a", "image": loop},
			map[string]any{"title": "b", "image": loop, "alt": "A neon halo"},
		}}},
	}}
	blocking, advisory := Validate(body)
	if len(blocking) > 0 {
		t.Fatalf("refused: %v", blocking)
	}
	var said []string
	for _, a := range advisory {
		said = append(said, a.String())
	}
	all := strings.Join(said, "\n")
	if strings.Contains(all, `no "surface"`) || strings.Contains(all, `no "image"`) {
		t.Errorf("a backdrop or card picture field was called a typo:\n%s", all)
	}
	if !strings.Contains(all, "names no backdrop_url") || !strings.Contains(all, "card 1 has a picture and no alt") ||
		strings.Contains(all, "card 2") {
		t.Errorf("the advice is wrong:\n%s", all)
	}
	if kind, ok := FileKind("sections.0.features.backdrop_url"); !ok || kind != Backdrop {
		t.Errorf("a backdrop field is %q", kind)
	}
}

// What a hero is drawn over is read without knowing a page's shape, for a
// screen that offers a backdrop only where there is a hero to put one behind.
func TestWhatAHeroIsDrawnOverIsRead(t *testing.T) {
	if addr, has := HeroBackdrop(heroPage()); !has || addr != "" {
		t.Errorf("a hero with no backdrop: %q %v", addr, has)
	}
	next, err := SetBackdrop(heroPage(), HeroAt, loop)
	if err != nil {
		t.Fatal(err)
	}
	if addr, has := HeroBackdrop(next); !has || addr != loop {
		t.Errorf("a hero with a backdrop: %q %v", addr, has)
	}
	if _, has := HeroBackdrop(map[string]any{"title": "No hero"}); has {
		t.Error("a page with no hero has one")
	}
	if _, has := HeroBackdrop("not a page"); has {
		t.Error("something that is not a page has a hero")
	}
}
