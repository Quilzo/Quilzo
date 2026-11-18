// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package export_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/export"
	"github.com/quilzo/quilzo/internal/webimport"
)

// A WordPress export is one WordPress takes as a site: pages as pages, at
// slugs WordPress can hold, blog posts as posts, a record at its own page
// link, and a redirect from every page address that moves.
//
// Every page went out as a blog post, with its Quilzo name as its slug:
// tr/about kept a slash WordPress strips, so it came in at another address
// with no redirect; a product went out as a post named by its record's id,
// and the blog's posts as a post type WordPress does not have.
func TestAWordPressExportIsASiteWordPressTakes(t *testing.T) {
	site := export.Site{Name: "Bakery", BaseURL: "https://bakery.example",
		Pages: map[string]any{
			"index":    map[string]any{"title": "Home"},
			"about":    map[string]any{"title": "About"},
			"tr":       map[string]any{"title": "Türkçe"},
			"tr/about": map[string]any{"title": "Hakkımızda"},
			"docs/v1":  map[string]any{"title": "Version one"},
		},
		Collections: map[string][]export.Record{
			"posts": {{ID: strings.Repeat("a", 32), Fields: map[string]any{"title": "Rye at last",
				"slug": "rye-at-last", "body": "It rose."}}},
			"products": {{ID: strings.Repeat("b", 32), Fields: map[string]any{"title": "Walnut ink",
				"slug": "walnut-ink", "body": "Dark."}}},
		}}
	files, err := export.Export(export.WXR, site, when)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := webimport.ReadWordPress(fileNamed(t, files, "content/wordpress-export.xml"))
	if err != nil {
		t.Fatal(err)
	}
	type item struct{ name, kind, parent string }
	byTitle := map[string]item{}
	ids := map[string]string{}
	for _, it := range doc.Channel.Items {
		byTitle[it.Title] = item{it.Name, it.Type, it.Parent}
		ids[it.ID] = it.Title
	}
	for title, want := range map[string]item{
		"About":       {"about", "page", ""},
		"Türkçe":      {"tr", "page", ""},
		"Hakkımızda":  {"about", "page", "Türkçe"},
		"Version one": {"docs-v1", "page", ""},
		"Rye at last": {"rye-at-last", "post", ""},
		"Walnut ink":  {"walnut-ink", "products", ""},
	} {
		got := byTitle[title]
		got.parent = ids[got.parent]
		if got != want {
			t.Errorf("%s went out as %+v, want %+v", title, got, want)
		}
	}

	// The page that moves is redirected; the home page and the pages
	// WordPress keeps at their address are not.
	var red struct{ Redirects []export.Redirect }
	if err := json.Unmarshal(fileNamed(t, files, "redirects.json"), &red); err != nil {
		t.Fatal(err)
	}
	if len(red.Redirects) != 1 || red.Redirects[0].From != "/docs/v1" || red.Redirects[0].To != "/docs-v1/" {
		t.Errorf("the redirects are %+v", red.Redirects)
	}
}
