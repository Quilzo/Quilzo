// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/store"
)

// A page with a hero and sections can leave.
//
// The Markdown export refused any nested field, and a page written the way this
// product's own layouts want has two of them: a hero map and a list of section
// maps. So `export markdown` failed outright — no files at all — on the shape
// the shipped starters produce, while the help calls this section "leaving
// (there is no lock-in here, and this is how it is proved)".
//
// Nested values go out as JSON, which is valid YAML flow style and is read back
// as a map by Hugo, Astro, Eleventy and Jekyll.
func TestAPageWithNestedFieldsCanBeExportedToMarkdown(t *testing.T) {
	page := map[string]any{
		"title": "Aster & Alum",
		"hero": map[string]any{
			"title": "Colour that comes out of a bucket",
			"lead":  "Ten metres at a time.",
		},
		"sections": []any{
			map[string]any{"features": map[string]any{
				"title": "Three things",
				"items": []any{map[string]any{"title": "No synthetic dye"}},
			}},
		},
	}
	files, err := Export(Markdown, Site{
		Name: "Aster & Alum", Pages: map[string]any{"index": page},
	}, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatalf("a page with a hero could not be exported: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no files")
	}
	var body string
	for _, f := range files {
		if strings.HasSuffix(f.Path, "index.md") {
			body = string(f.Body)
		}
	}
	if body == "" {
		t.Fatal("no index.md in the export")
	}
	// The nested values are there, and they are readable as structure rather
	// than as a Go map printed with %v.
	for _, want := range []string{`"title":"Colour that comes out of a bucket"`,
		`"features"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the front matter does not carry %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "map[") {
		t.Error("a Go map was printed into the front matter, which no parser " +
			"reads back")
	}
}

// The name an import makes from words in another language is the words,
// spelled in the letters a page name may hold, as a sheet's links are.
//
// Every letter outside ASCII was left out: ürünlerimiz came in as rnlerimiz
// and a Greek title had nothing left.
func TestASlugSpellsLettersFromOtherAlphabets(t *testing.T) {
	for in, want := range map[string]string{
		"ürünlerimiz": "urunlerimiz",
		"Naïve café":  "naive-cafe",
		"İstanbul":    "istanbul",
		"σχετικά":     "schetika",
		"Объявление":  "obiavlenie",
		"مرحبا":       "",
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

// The name an import makes is one the store holds, however long the words
// it was made from, and so is the name a page is numbered to.
//
// A name was cut at 80 characters and the store holds a part of 64: a
// WordPress post whose slug ran past that came in under a name the store
// refused, and the one refusal failed the whole import, after the report had
// listed every page as brought. Spelling letters in ASCII made it likelier:
// a Russian title of fifty letters is a name of seventy. Two long titles that
// differ only at their ends are one name when cut, and the second was
// numbered past what the store holds, with the same end.
func TestANameMadeFromWordsIsOneTheStoreHolds(t *testing.T) {
	for _, words := range []string{
		"Ten things you should know before you visit Istanbul in the winter of 2024 or later",
		"Как правильно выбрать зимние шины для вашего автомобиля в этом году",
		strings.Repeat("x", 300),
	} {
		if got := Slug(words); !store.ValidPath(got) {
			t.Errorf("Slug(%q) = %q (%d characters), which the store does not hold", words, got, len(got))
		}
	}
	// What the store already held is as it was.
	if at := strings.Repeat("a", 64); Slug(at) != at {
		t.Errorf("a name of 64 characters, which the store holds, was cut to %d", len(Slug(at)))
	}

	named := NewNames()
	seen := map[string]bool{}
	for _, base := range []string{strings.Repeat("a", 64), strings.Repeat("a", 64), strings.Repeat("a", 64),
		"tr/" + strings.Repeat("b", 64), "tr/" + strings.Repeat("b", 64), "short", "short"} {
		name := named.Claim(base)
		if !store.ValidPath(name) {
			t.Errorf("%q was named %q, which the store does not hold", base, name)
		}
		if seen[name] {
			t.Errorf("two pages were named %q", name)
		}
		seen[name] = true
	}
	if !seen["short-2"] || !seen["tr/"+strings.Repeat("b", 62)+"-2"] {
		t.Errorf("a name taken is numbered from the name the pages share: %v", seen)
	}
}
