// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// iframeSrc finds the documents a screen frames.
var iframeSrc = regexp.MustCompile(`<iframe[^>]*\ssrc="([^"]*)"`)

// The editor of a page nobody has saved frames nothing that refuses to be
// framed.
//
// It framed /preview/NAME, which answers 404 for a page with no draft, and a
// 404 carries frame-ancestors 'none' like every other response: a blank pane,
// a framing error and a 404 in the console on the first visit to every new
// page's editor, beside a hint saying the pane shows the page.
func TestTheEditorOfANewPageFramesOnlyWhatMayBeFramed(t *testing.T) {
	srv, token := setup(t)
	for _, page := range []string{"brand-new", "about"} {
		body := get(t, srv, "/page/"+page, token).Body.String()
		if !strings.Contains(body, `name="preview-frame"`) {
			t.Fatalf("%s: the editor has no frame for the preview to show in", page)
		}
		for _, m := range iframeSrc.FindAllStringSubmatch(body, -1) {
			src := html.UnescapeString(m[1])
			w := get(t, srv, src, token)
			if w.Code != http.StatusOK ||
				!strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
				t.Errorf("%s: the editor frames %s, which answers %d with %q", page, src, w.Code,
					w.Header().Get("Content-Security-Policy"))
			}
		}
	}
	if !strings.Contains(get(t, srv, "/page/about", token).Body.String(), `src="/preview/about?plain=1"`) {
		t.Error("a saved page's editor no longer shows its preview")
	}
}
