// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// The editor saves what a page tells search engines, and takes it off
// again; the two fields are not shown twice.
func TestTheEditorSetsWhatSearchEnginesAreTold(t *testing.T) {
	srv, token := setup(t)
	save := func(v url.Values) map[string]any {
		t.Helper()
		v.Set("__name", "about")
		v.Set("__base", srv.Store.GetRef(site.RefDraft))
		v.Set("title", "About")
		w := postForm(t, srv, "/save", token, v.Encode())
		if w.Code >= 400 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		pages, _ := site.PagesAt(srv.Store, site.RefDraft)
		return pages["about"].(map[string]any)
	}
	got := save(url.Values{"__seo": {"1"}, "__noindex": {"1"}, "__canonical": {"https://journal.example/about"}})
	if got["noindex"] != true || got["canonical"] != "https://journal.example/about" {
		t.Fatalf("%v", got)
	}
	body := get(t, srv, "/page/about", token).Body.String()
	if !strings.Contains(body, `id="f-noindex" type="checkbox" name="__noindex" value="1" checked`) ||
		strings.Count(body, "journal.example/about") != 1 {
		t.Fatal("the editor does not show them once, as they are")
	}
	got = save(url.Values{"__seo": {"1"}, "__canonical": {""}})
	if _, on := got["noindex"]; on {
		t.Fatal("unticked and still left out of results")
	}
	if _, on := got["canonical"]; on {
		t.Fatal("emptied and still a copy")
	}
}
