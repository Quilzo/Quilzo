// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/theme"
)

// layerRule is a rule a layer may hold: a colour that is a token.
const layerRule = ".card { border-color: var(--outline); }"

// The style layer is part of the design the public site reads again: a layer
// set while the site runs reaches readers with the publish, and not before,
// as every other change to templates/ does.
//
// The layer and the reload were built side by side, and the reload's promise
// is about everything loadDesign reads; a layer that waited for a restart
// while a typeface beside it arrived with the publish would be the one part
// of the design that still needed one.
func TestALayerReachesReadersWithThePublishNotBefore(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	if strings.Contains(served(rl, "/site.css").Body.String(), layerRule) {
		t.Fatal("a layer is served before there is one")
	}
	css := writeTemp(t, "arena.css", []byte(layerRule+"\n"))
	if err := cmdTheme(root, []string{"layer", "set", css, "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(served(rl, "/site.css").Body.String(), layerRule) {
		t.Fatal("a layer reached readers before any publish")
	}
	editDraft(t, root, "index", "Changed words.")
	if err := runPublish(t, root, "-templates", tpl); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(served(rl, "/site.css").Body.String(), layerRule) {
		t.Fatal("the published layer is not served")
	}

	// And taken away the same way: still served until the next publish.
	if err := cmdTheme(root, []string{"layer", "unset", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(served(rl, "/site.css").Body.String(), layerRule) {
		t.Fatal("a layer taken away left readers before any publish")
	}
	editDraft(t, root, "index", "Changed words again.")
	if err := runPublish(t, root, "-templates", tpl); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(served(rl, "/site.css").Body.String(), layerRule) {
		t.Fatal("a layer taken away and published is still served")
	}
}

// A layer saved on the Design screen is in the preview's stylesheet when the
// screen comes back, and one changed on disk is in it with the next look at
// templates/, as a face is.
//
// The layer hooks are the admin's design hooks, built in one place with the
// watch that reads the design again (adminDesignHooks), so a save reads it
// at once rather than waiting for the watch's next look.
func TestALayerSavedOnTheScreenIsInThePreviewAtOnce(t *testing.T) {
	root, tpl := fontSite(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	toks := &auth.TokenStore{}
	session, _, err := toks.IssueSession("t", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, design.Layouts)
	if err != nil {
		t.Fatal(err)
	}
	srv.SiteCSS = design.Stylesheet
	dw := newDesignWatch(tpl, design, func(d *Design) { srv.SetDesign(d.Layouts, d.Stylesheet) })
	// Never looked at again on its own: what reaches the preview here is
	// what the save itself read.
	dw.every = time.Hour
	dw.looked = time.Now()
	dw.say = func(string, ...any) {}
	srv.DesignSet = adminDesignHooks(tpl, dw)
	h := dw.Wrap(srv.Handler())
	do := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var req *http.Request
		if form != nil {
			req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+session)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := do(http.MethodPost, "/design/layer", url.Values{"layer": {layerRule}})
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther && w.Code != http.StatusFound || strings.Contains(loc, "e=") {
		t.Fatalf("saving the layer: %d %s\n%s", w.Code, loc, w.Body.String())
	}
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "next publish") {
		t.Errorf("saving the layer does not say when readers get it: %s", loc)
	}
	if b, _ := os.ReadFile(filepath.Join(tpl, theme.LayerFile)); string(b) != layerRule {
		t.Fatalf("the layer on disk is %q", b)
	}
	if css := do(http.MethodGet, "/site.css", nil).Body.String(); !strings.Contains(css, layerRule) {
		t.Fatal("the preview's stylesheet does not have the layer just saved")
	}

	// Taken away from the screen: gone from the preview as the screen
	// comes back.
	w = do(http.MethodPost, "/design/layer", url.Values{"remove": {"1"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "The style layer is gone") {
		t.Fatalf("taking the layer away: %d\n%s", w.Code, w.Body.String())
	}
	if css := do(http.MethodGet, "/site.css", nil).Body.String(); strings.Contains(css, layerRule) {
		t.Fatal("the preview's stylesheet still has the layer taken away")
	}

	// By hand, as somebody editing templates/style.css would: with the
	// watch's next look.
	if err := os.WriteFile(filepath.Join(tpl, theme.LayerFile), []byte(layerRule), 0o600); err != nil {
		t.Fatal(err)
	}
	dw.every = 0
	if css := do(http.MethodGet, "/site.css", nil).Body.String(); !strings.Contains(css, layerRule) {
		t.Fatal("a layer written by hand did not reach the preview with the next look")
	}
	if page := do(http.MethodGet, "/design", nil).Body.String(); !strings.Contains(page, "The saved layer is served") {
		t.Error("the Design screen does not show the layer written by hand")
	}
}
