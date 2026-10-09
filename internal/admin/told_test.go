// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
)

// Publishing and rolling back in the browser tell the webhooks, as the
// command line does. They did not: a receiver subscribed to "published"
// heard about every publish made from a script and none made from the
// screen most people use.
func TestTheBrowserTellsTheWebhooks(t *testing.T) {
	srv, token := setup(t)
	told := make(chan string, 8)
	srv.Told = func(event, commit string, pages []string) {
		told <- event + " " + commit[:8] + " " + strings.Join(pages, ",")
	}
	wait := func(want string) string {
		t.Helper()
		select {
		case got := <-told:
			if !strings.HasPrefix(got, want+" ") {
				t.Fatalf("told %q, want %s", got, want)
			}
			return got
		case <-time.After(5 * time.Second):
			t.Fatalf("nothing told for %s", want)
		}
		return ""
	}
	if w := postForm(t, srv, "/publish", token, "reason=a test needs something live"); w.Code != http.StatusOK {
		t.Fatalf("publish answered %d", w.Code)
	}
	if got := wait("published"); !strings.Contains(got, "index") {
		t.Fatalf("the pages that changed are not named: %q", got)
	}
	live := srv.Store.GetRef(site.RefLive)
	if w := postForm(t, srv, "/rollback", token, "commit="+live); w.Code >= 400 {
		t.Fatalf("rollback answered %d", w.Code)
	}
	wait("rolled-back")
}
