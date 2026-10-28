// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/theme"
)

// siteStore is a new store with two administrators, and a templates
// directory of its own for site packages to write into.
func siteStore(t *testing.T) (root, design string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root = t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"})
	design = filepath.Join(t.TempDir(), "templates")
	old := featureDesignDir
	featureDesignDir = design
	t.Cleanup(func() { featureDesignDir = old })
	return root, design
}

// sitePackage is a small whole site: a home page, a menu and the site.
func sitePackage(t *testing.T, name, version, colour string) string {
	t.Helper()
	p := feature.Package{Format: feature.Format, Name: name, Version: version,
		Title: "Hart's Bakery", Purpose: "The bakery's website.",
		Site: &feature.Site{Name: "Hart's Bakery", Description: "Bread baked before dawn in Leeds.",
			Style: "soft", Colour: colour},
		Pages: []feature.Page{{Name: "index", Body: map[string]any{"title": "Hart's Bakery",
			"sections": []any{map[string]any{"prose": map[string]any{"title": "Fresh every morning",
				"paragraphs": []any{"Sourdough, rye and pastries from four o'clock."}}}}}}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name+"-"+version+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func siteSettings(t *testing.T, root string) (name, description string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Raw("site.name"), cfg.Raw("site.description")
}

func siteLook(t *testing.T, dir string) map[string]string {
	t.Helper()
	tok, err := loadThemeFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A package that is a whole site names it, gives it layouts and a look,
// and owns all of it: a new version changes it, another package cannot
// take it, and removing the package takes the site back to nothing while
// keeping the layouts its pages render through.
func TestAPackageCanBeAWholeSite(t *testing.T) {
	root, design := siteStore(t)
	if err := installFeatureFile(root, sitePackage(t, "bakery", "1.0", "#c2410c"), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n, d := siteSettings(t, root); n != "Hart's Bakery" || d != "Bread baked before dawn in Leeds." {
		t.Fatalf("the site is %q, %q", n, d)
	}
	want, err := theme.Generate("#c2410c")
	if err != nil {
		t.Fatal(err)
	}
	tok := siteLook(t, design)
	if tok["style"] != "soft" || tok["primary"] != want["primary"] {
		t.Fatalf("the look is %v", tok)
	}
	if !fileExists(filepath.Join(design, "page.html")) {
		t.Fatal("a site with no layouts was given none")
	}
	if !owns(t, root, "bakery")["site site"] {
		t.Fatal("the package does not own the site")
	}

	// A new version changes the look.
	if err := installFeatureFile(root, sitePackage(t, "bakery", "1.1", "#1d4ed8"), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	blue, _ := theme.Generate("#1d4ed8")
	if siteLook(t, design)["primary"] != blue["primary"] {
		t.Fatal("a new version did not change the look")
	}

	// Another site package is refused: a site is one package's.
	err = installFeatureFile(root, sitePackage(t, "other", "1.0", "#15803d"), "", "", asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "the site belongs to the feature bakery") {
		t.Fatalf("a second site package: %v", err)
	}

	if err := removeFeature(root, "bakery", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n, d := siteSettings(t, root); n != "" || d != "" {
		t.Fatalf("after removal the site is still %q, %q", n, d)
	}
	if fileExists(filepath.Join(design, themeFile)) {
		t.Fatal("the package's look outlived it")
	}
	if !fileExists(filepath.Join(design, "page.html")) {
		t.Fatal("removing the package took the layouts, and with them every page")
	}
}

// A site somebody set up by hand is theirs: a site package is refused
// until told to take it over, and removing the package puts it back.
func TestASiteMadeByHandIsTakenOverOnlyWhenAsked(t *testing.T) {
	root, design := siteStore(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("site.name", "Dana's Notes", "", "dana"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(design, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeThemeFile(design, map[string]string{"style": "editorial"}); err != nil {
		t.Fatal(err)
	}
	pkg := sitePackage(t, "bakery", "1.0", "#c2410c")
	err = installFeatureFile(root, pkg, "", "", asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "--take-site") {
		t.Fatalf("a site set up by hand was taken without asking: %v", err)
	}
	if n, _ := siteSettings(t, root); n != "Dana's Notes" {
		t.Fatalf("a refused install changed the name to %q", n)
	}

	if err := installFeatureFileWith(root, pkg, "", "", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n, _ := siteSettings(t, root); n != "Hart's Bakery" {
		t.Fatalf("taken over, the site is %q", n)
	}
	if err := removeFeature(root, "bakery", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n, _ := siteSettings(t, root); n != "Dana's Notes" {
		t.Fatalf("the name was not put back: %q", n)
	}
	if siteLook(t, design)["style"] != "editorial" {
		t.Fatal("the look was not put back")
	}
}

// A site's old addresses go into the site's redirect map with it, beside a
// redirect somebody set by hand, which stays theirs; a new version replaces
// them, and removing the package takes them out.
func TestASitesRedirectsComeAndGoWithIt(t *testing.T) {
	root, _ := siteStore(t)
	if err := saveJSON(storeRedirectsPath(root), redirectFile{Redirects: []seo.Redirect{
		{From: "/old-news", To: "/news", Permanent: true}, {From: "/visit.html", To: "/contact", Permanent: true}}}); err != nil {
		t.Fatal(err)
	}
	withRedirects := func(version string, rs ...seo.Redirect) string {
		path := sitePackage(t, "bakery", version, "#c2410c")
		var p feature.Package
		b, _ := os.ReadFile(path)
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		p.Site.Redirects = rs
		b, _ = json.Marshal(p)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	redirects := func() map[string]string {
		var f redirectFile
		if err := loadRedirectFile(storeRedirectsPath(root), &f); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range f.Redirects {
			out[r.From] = r.To
		}
		return out
	}
	if err := installFeatureFile(root, withRedirects("1.0",
		seo.Redirect{From: "/Home.html", To: "/", Permanent: true},
		seo.Redirect{From: "/visit.html", To: "/", Permanent: true}), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	got := redirects()
	if got["/Home.html"] != "/" || got["/visit.html"] != "/contact" || got["/old-news"] != "/news" || len(got) != 3 {
		t.Fatalf("installed, the redirects are %v", got)
	}
	if err := installFeatureFile(root, withRedirects("1.1", seo.Redirect{From: "/index.php", To: "/", Permanent: true}), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if got := redirects(); got["/index.php"] != "/" || got["/Home.html"] != "" || len(got) != 3 {
		t.Fatalf("upgraded, the redirects are %v", got)
	}
	if err := removeFeature(root, "bakery", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if got := redirects(); got["/index.php"] != "" || got["/old-news"] != "/news" || len(got) != 2 {
		t.Fatalf("removed, the redirects are %v", got)
	}

	// A package that would send old addresses off the site is refused, and
	// so is one that would hide its own page: redirects are served first.
	bad := withRedirects("2.0", seo.Redirect{From: "/shop", To: "https://elsewhere.example/", Permanent: true})
	if err := installFeatureFile(root, bad, "", "", asAdmin("dana")); err == nil || !strings.Contains(err.Error(), "own pages") {
		t.Fatalf("a redirect off the site: %v", err)
	}
	hides := withRedirects("2.1", seo.Redirect{From: "/", To: "/about", Permanent: true})
	if err := installFeatureFile(root, hides, "", "", asAdmin("dana")); err == nil || !strings.Contains(err.Error(), "would hide") {
		t.Fatalf("a redirect from its own page: %v", err)
	}

	// A page already on the site is not hidden either: that redirect is
	// left out, and the rest go in.
	putDraftPage(t, root, "menu", map[string]any{"title": "Our menu"})
	if err := installFeatureFile(root, withRedirects("3.0",
		seo.Redirect{From: "/menu", To: "/", Permanent: true},
		seo.Redirect{From: "/Home.html", To: "/", Permanent: true}), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if got := redirects(); got["/menu"] != "" || got["/Home.html"] != "/" {
		t.Fatalf("over a page the site has, the redirects are %v", got)
	}
}

// The site serves its own redirect map with the file it is given laid over
// it, and an export carries them, so the addresses that moved keep moving.
func TestTheSitesRedirectsAreServedAndExported(t *testing.T) {
	root, _ := siteStore(t)
	if err := saveJSON(storeRedirectsPath(root), redirectFile{Redirects: []seo.Redirect{
		{From: "/About_Us.html", To: "/about-us", Permanent: true}, {From: "/blog", To: "/news", Permanent: true}}}); err != nil {
		t.Fatal(err)
	}
	given := filepath.Join(t.TempDir(), "wp.json")
	if err := saveJSON(given, redirectFile{Redirects: []seo.Redirect{
		{From: "/blog/", To: "/journal", Permanent: true}, {From: "/2019/our-story", To: "/about-us", Permanent: true}}}); err != nil {
		t.Fatal(err)
	}
	got, err := siteRedirects(root, given)
	if err != nil {
		t.Fatal(err)
	}
	to := map[string]string{}
	for _, r := range got {
		to[r.From] = r.To
	}
	if len(got) != 3 || to["/blog/"] != "/journal" || to["/About_Us.html"] != "/about-us" || to["/blog"] != "" {
		t.Fatalf("laid over the site's own, the redirects are %v", got)
	}
	m, err := servedRedirects(root, given)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := m.Lookup("/About_Us.html"); !ok || r.To != "/about-us" {
		t.Fatalf("the site's own redirect is not served: %+v", r)
	}
	if r, ok := m.Lookup("/blog"); !ok || r.To != "/journal" {
		t.Fatalf("the file given does not win: %+v", r)
	}
	if _, err := servedRedirects(root, filepath.Join(t.TempDir(), "missing.json")); err == nil ||
		!strings.Contains(err.Error(), "no such redirect map") {
		t.Fatalf("a redirect map that is not there: %v", err)
	}

	// An export carries the site's own, wherever it is run from.
	solo := t.TempDir() + "/solo"
	if err := cmdInit(solo); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(storeRedirectsPath(root), storeRedirectsPath(solo)); err != nil {
		t.Fatal(err)
	}
	putDraftPage(t, solo, "about-us", map[string]any{"title": "About us"})
	out := filepath.Join(t.TempDir(), "export")
	if err := cmdExport(solo, []string{"--to", out, "--ref", "draft"}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(out, "redirects.json"))
	if err != nil || !strings.Contains(string(body), "/About_Us.html") {
		t.Fatalf("the export's redirects: %s, %v", body, err)
	}
}

// putDraftPage drafts a page of somebody's own.
func putDraftPage(t *testing.T, root, name string, body map[string]any) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	pages[name] = body
	if err := saveDraft(root, s, pages, "their page", "rae", ""); err != nil {
		t.Fatal(err)
	}
}
