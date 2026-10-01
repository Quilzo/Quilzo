// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/render"
)

// A site with an icon shows it everywhere a browser looks for one.
//
// Every page's request for /favicon.ico was a 404 and the manifest declared
// no icons, so a tab showed a blank square and an installed site a tile the
// platform made up.
func TestASitesIconIsLinkedDeclaredAndServed(t *testing.T) {
	f, body := fixtureImage(t)
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	st.Media = func(id string) (media.File, []byte, error) {
		if id != f.ID {
			return media.File{}, nil, http.ErrMissingFile
		}
		return f, body, nil
	}

	// Not configured: nothing claimed, and the 404 is honest.
	if w := get(st, "/favicon.ico", nil); w.Code != 404 {
		t.Errorf("with no icon, /favicon.ico gave %d", w.Code)
	}
	if strings.Contains(get(st, "/", nil).Body.String(), `rel="icon"`) {
		t.Error("a page links an icon the site does not have")
	}
	// Configured with an id the library does not hold: the same.
	st.Icon = strings.Repeat("e", 64)
	if strings.Contains(get(st, "/", nil).Body.String(), `rel="icon"`) {
		t.Error("a page links an icon that is not in the library")
	}

	st.Icon = f.ID
	if !strings.Contains(get(st, "/", nil).Body.String(),
		`<link rel="icon" href="/media/`+f.ID+`">`) {
		t.Error("the page does not link the icon")
	}
	w := get(st, "/favicon.ico", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" ||
		w.Body.String() == "" {
		t.Errorf("/favicon.ico: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	var doc struct {
		Icons []map[string]string `json:"icons"`
	}
	if err := json.Unmarshal(get(st, "/manifest.webmanifest", nil).Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Icons) != 1 || doc.Icons[0]["src"] != "/media/"+f.ID ||
		doc.Icons[0]["type"] != "image/png" || doc.Icons[0]["sizes"] != "1x1" {
		t.Errorf("the manifest declares %v", doc.Icons)
	}
	// And a static copy carries it, for the request made before a page is
	// read.
	files, err := st.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	if len(files["favicon.ico"]) == 0 {
		t.Error("the static copy has no favicon.ico")
	}
}

// A layout can show the icon beside the site's name.
func TestALayoutCanShowTheIcon(t *testing.T) {
	f, body := fixtureImage(t)
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	st.Media = func(id string) (media.File, []byte, error) {
		if id != f.ID {
			return media.File{}, nil, http.ErrMissingFile
		}
		return f, body, nil
	}
	st.Layouts = render.OneLayout(`<html><head></head><body>{% if site.icon %}<img src="{{ site.icon }}" alt="">{% end %}{{ site.name }}</body></html>`)
	if strings.Contains(get(st, "/", nil).Body.String(), "<img") {
		t.Error("a site with no icon showed one")
	}
	st.Icon = f.ID
	if !strings.Contains(get(st, "/", nil).Body.String(), `<img src="/media/`+f.ID+`"`) {
		t.Error("the layout did not get the icon")
	}
}
