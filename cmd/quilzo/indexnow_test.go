// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/personalise"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

func setConfigs(t *testing.T, root string, kv map[string]string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		if err := cfg.Set(k, v, "a test", "test"); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
}

// Off, nothing is sent. On, the first publish is a starting point and makes
// the key the site serves; after that each publish sends the addresses of
// the pages that changed, a page reusing a changed block among them, and
// never one left out of results or a block's own.
func TestSearchEnginesAreToldWhatChanged(t *testing.T) {
	root := demoStore(t)
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	was := indexNowEndpoint
	indexNowEndpoint = srv.URL
	defer func() { indexNowEndpoint = was }()

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(change func(map[string]any)) {
		t.Helper()
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		change(pages)
		if _, err := site.SaveDraft(s, pages, "change", "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := site.Publish(s, ""); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	publish(func(p map[string]any) {
		p["hours"] = map[string]any{"title": "Hours", "block": true, "sections": []any{
			map[string]any{"text": map[string]any{"title": "Nine to five"}}}}
		p["visit"] = map[string]any{"title": "Visit", "sections": []any{map[string]any{"block": map[string]any{"page": "hours"}}}}
		p["thanks"] = map[string]any{"title": "Thanks", "noindex": true}
	})
	if said := indexNowAfterPublish(ctx, root); said != "" || len(got) != 0 {
		t.Fatalf("told while off: %q %v", said, got)
	}
	setConfigs(t, root, map[string]string{"site.indexnow": "true", "site.base_url": "https://shop.example"})
	if said := indexNowAfterPublish(ctx, root); said != "" || len(got) != 0 {
		t.Fatalf("the first publish told: %q", said)
	}
	key := servedIndexNowKey(root)()
	if !reIndexNowKey.MatchString(key) {
		t.Fatalf("no key served: %q", key)
	}
	publish(func(p map[string]any) {
		p["hours"] = map[string]any{"title": "Hours", "block": true, "sections": []any{
			map[string]any{"text": map[string]any{"title": "Ten to six"}}}}
		p["thanks"] = map[string]any{"title": "Thank you!", "noindex": true}
	})
	said := indexNowAfterPublish(ctx, root)
	if len(got) != 1 || !strings.Contains(said, "1 changed page") && !strings.Contains(said, "a changed page") {
		t.Fatalf("%q %v", said, got)
	}
	urls := []string{}
	for _, u := range got[0]["urlList"].([]any) {
		urls = append(urls, u.(string))
	}
	if !slices.Equal(urls, []string{"https://shop.example/visit"}) || got[0]["host"] != "shop.example" ||
		got[0]["key"] != key || got[0]["keyLocation"] != "https://shop.example/"+key+".txt" {
		t.Fatalf("%v", got[0])
	}
	// Nothing new published: nothing sent.
	if said := indexNowAfterPublish(ctx, root); said != "" || len(got) != 1 {
		t.Fatalf("told twice: %q", said)
	}
	if info, err := os.Stat(indexNowKeyPath(root)); err != nil || info.Size() == 0 {
		t.Fatal(err)
	}
}

// A page a running test serves at another page's address is a version of
// that page, which the site's sitemap leaves out and whose canonical link
// names the page tested. IndexNow sent it by its own address all the same,
// so a search engine was asked to index /returns-b as a page of its own.
func TestSearchEnginesAreNotToldOfAVariant(t *testing.T) {
	root := demoStore(t)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			URLs []string `json:"urlList"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m.URLs...)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	was := indexNowEndpoint
	indexNowEndpoint = srv.URL
	defer func() { indexNowEndpoint = was }()

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(words string) {
		t.Helper()
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		pages["returns"] = map[string]any{"title": "Returns " + words}
		pages["returns-b"] = map[string]any{"title": "Returns, put simply " + words}
		if _, err := site.SaveDraft(s, pages, "change", "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := site.Publish(s, ""); err != nil {
			t.Fatal(err)
		}
	}
	publish("one")
	setConfigs(t, root, map[string]string{"site.indexnow": "true", "site.base_url": "https://shop.example"})
	ctx := context.Background()
	if said := indexNowAfterPublish(ctx, root); said != "" {
		t.Fatalf("the first publish told: %q", said)
	}
	set := &experiment.Set{}
	if err := set.Put(experiment.Experiment{Name: "retx", Page: "returns", Goal: "page:/delivery",
		Running: true, Variants: []experiment.Variant{
			{Name: "a", Page: "returns", Weight: 1}, {Name: "b", Page: "returns-b", Weight: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := experiment.Save(experimentsPath(root), set); err != nil {
		t.Fatal(err)
	}
	publish("two")
	indexNowAfterPublish(ctx, root)
	if !slices.Equal(got, []string{"https://shop.example/returns"}) {
		t.Fatalf("told %v while returns-b is a variant of /returns", got)
	}
	// Stopped, it is a page again, and sent when it changes.
	set.Experiments[0].Running = false
	if err := experiment.Save(experimentsPath(root), set); err != nil {
		t.Fatal(err)
	}
	got = nil
	publish("three")
	indexNowAfterPublish(ctx, root)
	if !slices.Equal(got, []string{"https://shop.example/returns", "https://shop.example/returns-b"}) {
		t.Fatalf("told %v once the test stopped", got)
	}
}

// A page in another of the site's languages is a page of its own, though a
// rule serves it at the default language's address to a browser asking for
// that language. By the rule for variants a changed translation was left
// out of the notice, as the site left it out of its sitemap: the French
// page a search engine had was never refreshed.
func TestSearchEnginesAreToldOfATranslationARuleServes(t *testing.T) {
	root := demoStore(t)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			URLs []string `json:"urlList"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m.URLs...)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	was := indexNowEndpoint
	indexNowEndpoint = srv.URL
	defer func() { indexNowEndpoint = was }()

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(words string) {
		t.Helper()
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		pages["returns"] = map[string]any{"title": "Returns " + words}
		pages["fr/returns"] = map[string]any{"title": "Retours " + words}
		pages["returns-phone"] = map[string]any{"title": "Returns, briefly " + words}
		if _, err := site.SaveDraft(s, pages, "change", "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := site.Publish(s, ""); err != nil {
			t.Fatal(err)
		}
	}
	publish("one")
	setConfigs(t, root, map[string]string{"site.indexnow": "true", "site.base_url": "https://shop.example"})
	ctx := context.Background()
	if said := indexNowAfterPublish(ctx, root); said != "" {
		t.Fatalf("the first publish told: %q", said)
	}
	if err := saveJSON(localesPath(root), &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "fr"}}); err != nil {
		t.Fatal(err)
	}
	rules := &personalise.Set{}
	for _, r := range []personalise.Rule{
		{Name: "returns-fr", Page: "returns", Variant: "fr/returns", Enabled: true,
			When: []personalise.Condition{{Field: personalise.Language, Values: []string{"fr"}}}},
		{Name: "returns-phone", Page: "returns", Variant: "returns-phone", Enabled: true,
			When: []personalise.Condition{{Field: personalise.Device, Values: []string{"phone"}}}},
	} {
		if err := rules.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := personalise.Save(personalisePath(root), rules); err != nil {
		t.Fatal(err)
	}
	publish("two")
	indexNowAfterPublish(ctx, root)
	if !slices.Equal(got, []string{"https://shop.example/fr/returns", "https://shop.example/returns"}) {
		t.Fatalf("told %v; the translation is a page of its own, and returns-phone is a variant of /returns", got)
	}
}

// Records live in the store beside the pages, under data, which is not a
// page. A record change was sent as https://SITE/data, which the site
// answers 404, and the pages that did change were not sent at all: the
// product's own page and every page listing its collection kept the old
// price in the engines. A changed record is sent as its detail page, if a
// listing keeps it, and as each page showing a listing over its collection;
// a part of the store that is not a page is never an address.
func TestSearchEnginesAreToldOfTheProductPageARecordChanged(t *testing.T) {
	root := demoStore(t)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			URLs []string `json:"urlList"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m.URLs...)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	was := indexNowEndpoint
	indexNowEndpoint = srv.URL
	defer func() { indexNowEndpoint = was }()

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	setConfigs(t, root, map[string]string{"site.indexnow": "true", "site.base_url": "https://shop.example"})
	ctx := context.Background()
	if said := indexNowAfterPublish(ctx, root); said != "" {
		t.Fatalf("the first publish told: %q", said)
	}

	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := collection.List(s, tree, "products", collection.Query{Limit: collection.MaxLimit})
	if err != nil {
		t.Fatal(err)
	}
	var walnut *collection.Record
	for i := range recs {
		if recs[i].Fields["slug"] == "walnut-ink" {
			walnut = &recs[i]
		}
	}
	if walnut == nil {
		t.Fatal("the demonstration has no walnut ink")
	}
	walnut.Fields["price"] = 1350.0
	walnut.Fields["price_display"] = "£13.50"
	if err := commitTree(s, "test", func(base string) (string, string, error) {
		next, _, err := collection.Put(s, base, "products", *walnut, time.Now(), nil)
		return next, "a new price", err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	indexNowAfterPublish(ctx, root)

	for _, want := range []string{
		"https://shop.example/product/walnut-ink",
		"https://shop.example/shop",
		"https://shop.example/available",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("not told of %s: %v", want, got)
		}
	}
	for _, u := range got {
		if u == "https://shop.example/data" || u == "https://shop.example/stockists" ||
			strings.HasPrefix(u, "https://shop.example/product/") && u != "https://shop.example/product/walnut-ink" {
			t.Errorf("told of %s, which did not change or is not a page: %v", u, got)
		}
	}
}
