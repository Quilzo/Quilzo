// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/webimport"
)

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 40, 30))
	for x := 0; x < 40; x++ {
		for y := 0; y < 30; y++ {
			img.Set(x, y, color.RGBA{R: 194, G: 65, B: 12, A: 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// An old site is read, kept as a package, installed as the site, its
// pictures in the library with the descriptions it gave them, its pages
// marked as carried over by software, and its old addresses redirected.
func TestAnOldSiteIsBroughtInAndInstalled(t *testing.T) {
	root, design := siteStore(t)
	picture := tinyPNG(t)
	pages := map[string]string{
		"/": `<html><head><title>Hart's Bakery</title><meta property="og:site_name" content="Hart's Bakery">
<meta name="theme-color" content="#1d4ed8"></head><body><header><nav><a href="/">Home</a><a href="/About_Us.html">About us</a></nav></header>
<main><h1>Bread baked before dawn</h1><p>Sourdough and rye.</p><img src="/loaf.png" alt="A loaf"><h2>Hours</h2><p>From seven.</p></main></body></html>`,
		"/About_Us.html": `<html><head><title>About us | Hart's Bakery</title></head><body><main><h1>About us</h1><p>Since 2019.</p></main></body></html>`,
	}
	siteImportGetSeam = func(_ context.Context, raw string) (*webimport.Fetched, error) {
		u, _ := url.Parse(raw)
		if u.Path == "/loaf.png" {
			return &webimport.Fetched{FinalURL: raw, Status: 200, ContentType: "image/png", Body: picture}, nil
		}
		if body, ok := pages[u.Path]; ok {
			return &webimport.Fetched{FinalURL: raw, Status: 200, ContentType: "text/html", Body: []byte(body)}, nil
		}
		return nil, errors.New("404")
	}
	t.Cleanup(func() { siteImportGetSeam = nil })

	b, site, err := importSite(context.Background(), root, "https://hartsbakery.example/", "", 10, true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if len(site.Pages) != 2 || b.Package.Site.Name != "Hart's Bakery" || len(b.Redirects) != 1 || b.Redirects[0].From != "/About_Us.html" {
		t.Fatalf("read %d, made %+v, redirects %v", len(site.Pages), b.Package.Site, b.Redirects)
	}
	path := filepath.Join(t.TempDir(), "harts.json")
	body, _ := jsonMarshalIndent(b.Package)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n, _ := siteSettings(t, root); n != "Hart's Bakery" {
		t.Fatalf("the site is called %q", n)
	}
	if !fileExists(filepath.Join(design, "page.html")) {
		t.Fatal("the brought site has no layouts")
	}
	draft, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	index, _ := draft["index"].(map[string]any)
	hero, _ := index["hero"].(map[string]any)
	img, _ := hero["image"].(string)
	if !strings.HasPrefix(img, "/media/") || hero["alt"] != "A loaf" {
		t.Fatalf("the home page's picture is %v", hero)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := lib.Get(strings.TrimPrefix(img, "/media/"))
	if err != nil || f.Alt != "A loaf" || f.Source != "https://hartsbakery.example/loaf.png" {
		t.Fatalf("the picture in the library is %+v: %v", f, err)
	}
	if draft["about-us"] == nil {
		t.Fatalf("no about-us page: %v", sortedNames(draft))
	}
	for _, p := range []string{"index", "about-us"} {
		if r := provenanceOf(t, root, p); r.SourceType != provenance.AlgorithmicMedia {
			t.Fatalf("page %s is marked %+v", p, r)
		}
	}

	// A site that answers with nothing is said to, not installed as empty.
	pages = map[string]string{}
	if _, _, err := importSite(context.Background(), root, "https://hartsbakery.example/", "", 10, true, asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "no page") {
		t.Fatalf("an empty site: %v", err)
	}
}

func jsonMarshalIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
