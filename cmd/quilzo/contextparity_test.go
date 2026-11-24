// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// The public site, `quilzo render` (which builds what the command line's
// publish gate judges) and the admin's preview (which builds what the
// browser's gate judges) each built a template's context of their own. On
// the demo's wholesale page the site showed its enquiry form and the site's
// icon; render showed the icon and not the form, and the preview showed
// neither, so an editor's preview left out what visitors get and neither gate
// ever judged the form a visitor is served. There is one context, the public
// site's, and every renderer draws the same page from it.
func TestEveryRendererBuildsTheSameContextForAPage(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root, tpl := t.TempDir()+"/st", t.TempDir()+"/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-templates", tpl, "-examples", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	icon := ""
	for _, f := range files {
		if f.Kind == media.Image {
			icon = f.ID
			break
		}
	}
	if icon == "" {
		t.Fatal("the demo's library holds no picture")
	}
	if err := cmdConfig(root, []string{"set", "site.icon", icon}); err != nil {
		t.Fatal(err)
	}
	// A shipped starter whose page shows a form where the page names one,
	// and the icon beside the site's name.
	if err := cmdTemplate(root, []string{"use", "catalogue", "--dir", tpl, "--force"}); err != nil {
		t.Fatal(err)
	}
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	st, err := siteFor(root, design, siteOpts{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/wholesale", nil))
	served := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("the site: %d", rec.Code)
	}

	live := s.GetRef(site.RefLive)
	pages, err := site.PagesAt(s, live)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := sourcesFor(root, s, live, siteName(root), pages).For("wholesale", pages["wholesale"], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, layout, err := design.Layouts.For(pages["wholesale"])
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := tmpl.Render(layout, ctx)
	if err != nil {
		t.Fatal(err)
	}

	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueSession("passkey:dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	srv, err := admin.New(s, pol, toks, design.Layouts)
	if err != nil {
		t.Fatal(err)
	}
	srv.Sources = renderContext(root, s)
	req := httptest.NewRequest("GET", "/preview/wholesale", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+secret)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the preview: %d %s", rec.Code, rec.Body.String())
	}
	previewed := rec.Body.String()

	iconAt := `src="/media/` + icon + `"`
	for name, html := range map[string]string{"the site": served, "quilzo render": rendered, "the preview": previewed} {
		if !strings.Contains(html, `action="/form/wholesale"`) {
			t.Errorf("%s does not show the page's form", name)
		}
		if !strings.Contains(html, iconAt) {
			t.Errorf("%s does not show the site's icon", name)
		}
	}
}

// A template's context is assembled in one place, the public site's
// (public.(*Site).Sources): each renderer that built one of its own drew a
// different page, and nothing said so until somebody compared them.
func TestOnlyOneFunctionAssemblesATemplateContext(t *testing.T) {
	var found []string
	for _, dir := range []string{".", "../../internal/admin", "../../internal/public", "../../internal/render"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for range strings.Count(string(b), "render.Sources{") {
				found = append(found, filepath.ToSlash(f))
			}
		}
	}
	if len(found) != 1 || found[0] != "../../internal/public/public.go" {
		t.Fatalf("a template's context is assembled in %v; it is the public site's to assemble", found)
	}
}
