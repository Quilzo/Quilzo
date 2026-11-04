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
	"github.com/quilzo/quilzo/internal/site"
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

// A face served under a name nobody typed says where the name came from.
//
// Aster-Regular.ttf with "Served as" left empty is served as Aster-400.woff,
// a file nobody named; a screen that said only "served at /fonts/Aster-400.woff"
// would leave somebody looking for where that came from, and one that said
// nothing of it for a name somebody did give would be saying something false.
func TestTheScreenSaysWhenTheNameCameFromTheFace(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	srv.DesignSet.AddFont = func(filename string, body []byte, name string, replace bool) (FontAdded, error) {
		return FontAdded{File: "Aster-400.woff", Family: "Aster", Weight: "400",
			Style: "normal", From: "truetype", NamedFromFace: name == ""}, nil
	}
	for name, wantNote := range map[string]bool{"": true, "Aster-400": false} {
		w := postFont(t, srv, token, "Aster-Regular.ttf", []byte("a face"), map[string]string{"name": name})
		loc, _ := url.Parse(w.Header().Get("Location"))
		msg := loc.Query().Get("m")
		if !strings.Contains(msg, "/fonts/Aster-400.woff") {
			t.Fatalf("name %q: the screen said %q", name, msg)
		}
		if got := strings.Contains(msg, "the ones the face declares") &&
			strings.Contains(msg, "Served as"); got != wantNote {
			t.Errorf("name %q: says the name came from the face: %v, want %v (%q)", name, got, wantNote, msg)
		}
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

// Adding a typeface takes the authority over the whole site, as installing a
// layout does: an author who may edit drafts may not.
//
// A face is the glyphs every page that names it is drawn with, and its
// glyphs are whatever its maker drew: a face whose digits are drawn as other
// digits changes every price and telephone number on the site at once. No
// gate reads a glyph, and a publisher reviewing an author's draft sees its
// words, not the shapes the next publish will draw them in.
func TestAnAuthorCannotAddATypeface(t *testing.T) {
	srv, _ := setup(t)
	designFake(srv, map[string]string{})
	called := false
	srv.DesignSet.AddFont = func(string, []byte, string, bool) (FontAdded, error) {
		called = true
		return FontAdded{File: "Aster.woff", Family: "Aster", Weight: "100 900", Style: "normal"}, nil
	}
	for _, who := range []struct {
		name string
		role auth.Role
	}{{"kit", auth.RoleAuthor}, {"pat", auth.RolePublisher}} {
		if err := srv.Policy.Grant(auth.Binding{Principal: who.name, Role: who.role, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	author, _, err := srv.Tokens.IssueSession("a", "kit", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := postFont(t, srv, author, "Aster.ttf", []byte("a face"), nil); w.Code < 400 || called {
		t.Fatalf("an author added a typeface: %d, called %v", w.Code, called)
	}
	publisher, _, err := srv.Tokens.IssueSession("p", "pat", auth.RolePublisher, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := postFont(t, srv, publisher, "Aster.ttf", []byte("a face"), nil); w.Code != http.StatusSeeOther || !called {
		t.Fatalf("a publisher could not add a typeface: %d, called %v", w.Code, called)
	}
}

// Replacing a face that is served says so in the record, so the moment the
// text on every page changed shape can be found.
func TestAReplacedTypefaceIsRecordedAsReplaced(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	srv.DesignSet.AddFont = func(_ string, _ []byte, _ string, replace bool) (FontAdded, error) {
		return FontAdded{File: "Aster.woff", Family: "Aster", Weight: "100 900", Style: "normal",
			From: "truetype", Replaced: replace}, nil
	}
	var records []map[string]string
	srv.Audit = func(action, resource string, detail map[string]string) {
		if action == "theme.font.add" {
			records = append(records, detail)
		}
	}
	postFont(t, srv, token, "Aster.ttf", []byte("a face"), nil)
	postFont(t, srv, token, "Aster.ttf", []byte("a face"), map[string]string{"replace": "1"})
	if len(records) != 2 || records[0]["replaced"] == "true" || records[1]["replaced"] != "true" {
		t.Errorf("recorded %v", records)
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

// The publish check reads the design once, so a design handed over while it
// runs cannot leave a page both unreported and unchecked.
//
// It read the layouts again for each question it asked of them. The host
// hands over a new design whenever templates/ changes (SetDesign), so the
// first question, "is this page's layout there", could be answered by the
// design that had it and the next, "render the page through it", by the one
// that had not: the page was then neither reported as asking for a layout
// the site lacks nor rendered to be checked, and the check passed a page it
// never looked at.
func TestThePublishCheckReadsOneDesign(t *testing.T) {
	srv, _ := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["shop"] = map[string]any{"title": "Shop", "body": "x", "layout": "shop"}
	if _, err := site.SaveDraft(srv.Store, pages, "a page with its own layout", "test"); err != nil {
		t.Fatal(err)
	}
	// The shop layout fails the check: a picture with nothing to say what it is.
	with, err := render.NewLayouts(map[string]string{"page": siteTemplate,
		"shop": `<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head>` +
			`<body><h1>{{ page.title }}</h1><img src="/a.png"></body></html>`})
	if err != nil {
		t.Fatal(err)
	}
	designFake(srv, map[string]string{})
	tokens := srv.DesignSet.Tokens
	// The host reads templates/ again while the check runs, and the shop
	// layout has gone: at each moment the check asks the host anything, in
	// turn, which is where a request reading the design again can land.
	for at := 1; at <= 3; at++ {
		srv.SetDesign(with, "")
		calls := 0
		srv.DesignSet.Tokens = func() (map[string]string, error) {
			if calls++; calls == at {
				srv.SetDesign(render.OneLayout(siteTemplate), "")
			}
			return tokens()
		}
		reports, err := srv.checkAll(srv.Store.GetRef(site.RefDraft))
		if err != nil {
			t.Fatal(err)
		}
		if !blocksPage(reports, "shop") {
			t.Errorf("with the design changed at the check's question %d, a page whose layout "+
				"went was neither reported as asking for it nor checked: %+v", at, reports)
		}
	}
}

// blocksPage says the reports hold a blocking finding about a page.
func blocksPage(reports []*a11y.Report, page string) bool {
	for _, r := range reports {
		if !r.Blocks() {
			continue
		}
		if r.Page == page {
			return true
		}
		for _, f := range r.Findings {
			if f.Severity == a11y.Blocking && f.Page == page {
				return true
			}
		}
	}
	return false
}

// A file in the fonts directory that is not served says why, on the screen.
//
// The screen said "No typefaces of your own" over a directory holding a
// renamed .ttf and nothing else: the face somebody had put there was missing
// without a word, and the reason was on the server's error output, where the
// person looking at this screen is not.
func TestAFaceThatIsNotServedSaysWhyOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	page := get(t, srv, "/design", token).Body.String()
	if strings.Contains(page, "not served.") {
		t.Fatal("a directory with nothing refused in it said something was")
	}
	why := "Aster.woff2 was refused: this is not a WOFF2 file"
	srv.DesignSet.FontNotes = func() []string { return []string{why} }
	page = get(t, srv, "/design", token).Body.String()
	whole(t, page)
	if !strings.Contains(page, "1 file in") || !strings.Contains(page, why) {
		t.Errorf("the screen does not say which file is not served, or why")
	}
	for _, f := range a11y.Check("/design", page).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the Design screen with a refused face: %s (%s) — %s", f.Rule, f.Criterion, f.Detail)
		}
	}
}
