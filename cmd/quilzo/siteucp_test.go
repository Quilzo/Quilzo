// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/render"
)

// The demonstration shop over UCP, as an agent meets it: the profile, a
// search, a lookup, all from the records the site publishes.
func TestTheDemoShopAnswersOverUCP(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"--templates", filepath.Join(root, "templates")}); err != nil {
		t.Fatal(err)
	}
	// As installed, the demonstration serves UCP at the address it tells
	// its reader to run at, and starts with nothing else configured.
	if _, err := siteFor(root, &Design{Layouts: render.OneLayout(`<!doctype html><title>x</title>`)}, siteOpts{}); err != nil {
		t.Fatalf("the demonstration as installed does not start: %v", err)
	}
	if cfg, err := loadConfig(root); err != nil || !cfg.Bool("ucp.catalogue") || cfg.Raw("site.base_url") != demoSiteURL {
		t.Fatalf("the demonstration did not turn UCP on at its own address: %v", err)
	}
	// An operator's own address, once set, is the one every URL is built on.
	if err := cmdConfig(root, []string{"set", "site.base_url", "https://marginalia.example"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"--publish=false", "--templates", filepath.Join(root, "templates")}); err == nil {
		if cfg, _ := loadConfig(root); cfg.Raw("site.base_url") != "https://marginalia.example" {
			t.Errorf("installing the demonstration again replaced the operator's address")
		}
	}
	st, err := siteFor(root, &Design{Layouts: render.OneLayout(
		`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body>{{ page.body }}</body></html>`)}, siteOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(method, path, body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Request-Id", "t-1")
		r.Header.Set("UCP-Agent", `profile="https://platform.example/.well-known/ucp"`)
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s answered %d: %s", method, path, w.Code, w.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	profile, _ := json.Marshal(ask("GET", "/.well-known/ucp", ""))
	if !strings.Contains(string(profile), `"endpoint":"https://marginalia.example/ucp"`) {
		t.Errorf("the profile does not name this site's endpoint: %s", profile)
	}
	found := ask("POST", "/ucp/catalog/search", `{"query":"brass"}`)
	products, _ := found["products"].([]any)
	if len(products) == 0 {
		t.Fatalf("a search of the demonstration shop found nothing: %v", found)
	}
	first := products[0].(map[string]any)
	id := first["id"].(string)
	price := first["variants"].([]any)[0].(map[string]any)["price"].(map[string]any)
	if price["currency"] != "GBP" || price["amount"].(float64) <= 0 {
		t.Errorf("a product is not priced from its record: %v", price)
	}
	looked := ask("POST", "/ucp/catalog/lookup", `{"ids":["`+id+`","no-such-thing"]}`)
	if got := looked["products"].([]any); len(got) != 1 {
		t.Errorf("a lookup of %s found %d", id, len(got))
	}
}

// Each configuration that would look switched on and answer nothing useful
// is refused at startup.
func TestAUCPCatalogueThatCannotWorkIsRefusedAtStartup(t *testing.T) {
	for _, base := range []string{"", "http://shop.example", "https://shop.example/shop", "ftp://shop.example"} {
		if _, err := ucpBase(base); err == nil {
			t.Errorf("%q was accepted as the site's address", base)
		}
	}
	for in, want := range map[string]string{"https://shop.example/": "https://shop.example",
		"http://127.0.0.1:8081": "http://127.0.0.1:8081", "http://localhost:8081": "http://localhost:8081"} {
		if got, err := ucpBase(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "ucp.catalogue", "true"}); err != nil {
		t.Fatal(err)
	}
	_, err := siteFor(root, &Design{Layouts: render.OneLayout(`<!doctype html><title>x</title>`)}, siteOpts{})
	if err == nil || !strings.Contains(err.Error(), "no catalogue is served") {
		t.Errorf("a site with no catalogue started with UCP on: %v", err)
	}
}
