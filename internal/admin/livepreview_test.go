// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
)

// What is typed renders in the preview and is not saved; showing it takes
// what saving takes.
func TestTheLivePreviewRendersWhatIsTypedAndSavesNothing(t *testing.T) {
	srv, token := setup(t)
	before := srv.Store.GetRef(site.RefDraft)
	form := url.Values{"__name": {"index"}, "title": {"Unsaved words, not yet anybody's"}}
	w := postForm(t, srv, "/preview/index?plain=1", token, form.Encode())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Unsaved words, not yet anybody") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("the preview cannot be framed by the editor")
	}
	if srv.Store.GetRef(site.RefDraft) != before {
		t.Fatal("previewing saved the page")
	}
	if got := get(t, srv, "/preview/index?plain=1", token).Body.String(); strings.Contains(got, "Unsaved words") {
		t.Fatal("what was previewed is in the draft")
	}
}

// Somebody who may only read sees the saved draft in a preview, and cannot
// have unsaved words rendered as the page.
func TestAReaderCannotPreviewUnsavedWords(t *testing.T) {
	srv, token := asRole(t, auth.RoleReader)
	form := url.Values{"__name": {"index"}, "title": {"Words a reader made up"}}
	w := postForm(t, srv, "/preview/index?plain=1", token, form.Encode())
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "Words a reader made up") {
		t.Fatalf("a reader previewed unsaved words: %d", w.Code)
	}
}
