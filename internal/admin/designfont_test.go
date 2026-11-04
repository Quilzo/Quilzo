// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/render"
)

// postFont sends a typeface to the Design screen as its form does.
func postFont(t *testing.T, srv *Server, token, filename string, body []byte, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write(body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/design/font", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// A typeface is added from the Design screen, as `quilzo theme font add`
// adds one, and the person who did it is on the record.
//
// The screen said to put a .woff2 in a directory, which is advice for
// somebody with a shell and a WOFF2; a customer whose foundry sent a .ttf had
// neither.
func TestATypefaceIsAddedFromTheDesignScreen(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	type call struct {
		filename, name string
		size           int
		replace        bool
	}
	var got []call
	srv.DesignSet.AddFont = func(filename string, body []byte, name string, replace bool) (FontAdded, error) {
		got = append(got, call{filename, name, len(body), replace})
		if name == "bad" {
			return FontAdded{}, errors.New("the face has no \"cmap\" table")
		}
		return FontAdded{File: "Aster-400-700.woff", Family: "Aster", Weight: "400 700",
			Style: "normal", From: "truetype"}, nil
	}
	var records []map[string]string
	srv.Audit = func(action, resource string, detail map[string]string) {
		if action == "theme.font.add" {
			records = append(records, detail)
		}
	}

	page := get(t, srv, "/design", token).Body.String()
	if !strings.Contains(page, `action="/design/font" enctype="multipart/form-data"`) {
		t.Fatal("the Design screen offers no way to add a typeface")
	}
	whole(t, page)
	for _, f := range a11y.Check("/design", page).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the Design screen with the typeface form: %s (%s) — %s", f.Rule, f.Criterion, f.Detail)
		}
	}

	w := postFont(t, srv, token, "Aster.ttf", []byte("a face"), map[string]string{"name": "Aster-400-700", "replace": "1"})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("adding a face: %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if msg := loc.Query().Get("m"); !strings.Contains(msg, "/fonts/Aster-400-700.woff") || !strings.Contains(msg, "400 700") {
		t.Errorf("the screen said %q", msg)
	}
	if len(got) != 1 || got[0] != (call{"Aster.ttf", "Aster-400-700", 6, true}) {
		t.Fatalf("the host was asked %+v", got)
	}
	if len(records) != 1 || records[0]["file"] != "Aster-400-700.woff" || records[0]["from"] != "truetype" || records[0]["by"] != "editor" {
		t.Errorf("recorded %v", records)
	}

	// A refusal is the host's reason, said on the screen, and not recorded
	// as something that happened.
	w = postFont(t, srv, token, "Aster.ttf", []byte("a face"), map[string]string{"name": "bad"})
	loc, _ = url.Parse(w.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("e"), "cmap") || len(records) != 1 {
		t.Errorf("a refused face: %q, %d record(s)", loc.Query().Get("e"), len(records))
	}
}

// Adding a typeface is a change to the design, so somebody who may only read
// cannot.
func TestAReaderCannotAddATypeface(t *testing.T) {
	srv, _ := setup(t)
	designFake(srv, map[string]string{})
	called := false
	srv.DesignSet.AddFont = func(string, []byte, string, bool) (FontAdded, error) {
		called = true
		return FontAdded{}, nil
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "newcomer", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	reader, _, err := srv.Tokens.IssueSession("r", "newcomer", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := postFont(t, srv, reader, "Aster.ttf", []byte("a face"), nil); w.Code < 400 || called {
		t.Fatalf("a reader added a typeface: %d, called %v", w.Code, called)
	}
}

// A WOFF 1.0 face is served to the preview as one.
func TestThePreviewGetsAWOFFAsAWOFF(t *testing.T) {
	srv, token := setup(t)
	srv.DesignSet = &Design{FontFile: func(name string) ([]byte, bool) {
		return []byte("wOFF a face"), name == "Aster-400-700.woff"
	}}
	w := get(t, srv, "/fonts/Aster-400-700.woff", token)
	if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff" {
		t.Fatalf("a WOFF: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

// The design the host hands over while the server runs is the one the
// preview renders and the stylesheet it serves.
//
// Both were read once at startup, so a layout or a face changed on disk was
// not in the admin until it restarted.
func TestADesignHandedOverIsTheOneThePreviewUses(t *testing.T) {
	srv, token := setup(t)
	srv.SiteCSS = "body { color: red }"
	if css := get(t, srv, "/site.css", token).Body.String(); css != srv.SiteCSS {
		t.Fatalf("before: %q", css)
	}
	srv.SetDesign(render.OneLayout(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head>`+
		`<body><main><h1>Changed: {{ page.title }}</h1></main></body></html>`), "body { color: blue }")
	if css := get(t, srv, "/site.css", token).Body.String(); css != "body { color: blue }" {
		t.Errorf("the stylesheet after it changed: %q", css)
	}
	if srv.layouts().Names()[0] != "page" {
		t.Fatalf("layouts: %v", srv.layouts().Names())
	}
	_, layout, err := srv.layouts().For(map[string]any{"title": "Home"})
	if err != nil || !strings.Contains(layout, "Changed:") {
		t.Errorf("the preview renders through %q (%v)", layout, err)
	}
}
