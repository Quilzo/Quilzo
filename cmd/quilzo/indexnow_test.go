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
