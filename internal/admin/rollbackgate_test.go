// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// "Make live" returns to a version the public has seen, and nothing else. It
// put any commit live, and every save to the draft is a commit: a card
// number refused by the publish check went live from the History screen,
// past that check and past the second approval.
func TestMakeLiveOnlyReturnsToWhatWasLive(t *testing.T) {
	srv, token := setup(t)
	pages := func(body string) map[string]any {
		return map[string]any{"index": map[string]any{"title": "Home", "body": body}}
	}
	first, err := site.SaveDraft(srv.Store, pages("first"), "first", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(srv.Store, ""); err != nil {
		t.Fatal(err)
	}
	unpublished, err := site.SaveDraft(srv.Store, pages("quote card 4539 1488 0343 6467"), "never published", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(srv.Store, pages("second"), "second", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(srv.Store, ""); err != nil {
		t.Fatal(err)
	}
	second := srv.Store.GetRef(site.RefLive)

	w := postForm(t, srv, "/rollback", token, "commit="+unpublished)
	if w.Code != http.StatusConflict {
		t.Errorf("making a never-published save live answered %d", w.Code)
	}
	if got := srv.Store.GetRef(site.RefLive); got != second {
		t.Fatalf("live moved to %s", got[:12])
	}

	h := get(t, srv, "/history", token)
	body := h.Body.String()
	if strings.Count(body, `action="/rollback"`) != 1 {
		t.Errorf("History offers Make live on %d versions, want only the earlier publication",
			strings.Count(body, `action="/rollback"`))
	}
	if !strings.Contains(body, "never published") || !strings.Contains(body, `value="`+first+`"`) {
		t.Error("History does not tell the never-published save from the earlier publication")
	}

	if w := postForm(t, srv, "/rollback", token, "commit="+first); w.Code != http.StatusOK {
		t.Fatalf("going back to the earlier publication answered %d", w.Code)
	}
	if got := srv.Store.GetRef(site.RefLive); got != first {
		t.Errorf("live is %s, want the earlier publication", got[:12])
	}
}
