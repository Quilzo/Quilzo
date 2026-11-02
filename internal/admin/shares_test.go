// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// fakeShares keep links in memory, as the command does on disk.
type fakeShares struct{ links map[string][]ShareLink }

func (f *fakeShares) hooks() *Shares {
	f.links = map[string][]ShareLink{}
	return &Shares{
		Create: func(page, by string, days int) (ShareLink, error) {
			if days < 1 || days > 30 {
				return ShareLink{}, errors.New("a link lives 1 to 30 days")
			}
			l := ShareLink{ID: strings.Repeat("a", 31) + string(rune('0'+len(f.links[page]))), By: by, Live: true,
				Expires: time.Now().Add(time.Duration(days) * 24 * time.Hour)}
			l.URL = "https://example.org/shared/" + l.ID
			f.links[page] = append(f.links[page], l)
			return l, nil
		},
		For: func(page string) ([]ShareLink, error) { return f.links[page], nil },
		Revoke: func(page, id, by string) error {
			for i, l := range f.links[page] {
				if l.ID == id {
					f.links[page][i].Live = false
					return nil
				}
			}
			return errors.New("no such link")
		},
	}
}

// Whoever may publish a page shares it from its editor and sees the link;
// it can be revoked there.
func TestAPageIsSharedFromItsEditor(t *testing.T) {
	srv, token := setup(t)
	f := &fakeShares{}
	srv.Shares = f.hooks()
	if body := get(t, srv, "/page/index", token).Body.String(); !strings.Contains(body, "Share this draft") {
		t.Fatal("the editor offers no sharing")
	}
	code, loc := postFormLoc(t, srv, token, "/shares", url.Values{"op": {"share"}, "page": {"index"}, "days": {"7"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "/page/index") || len(f.links["index"]) != 1 {
		t.Fatalf("%d %s %+v", code, loc, f.links)
	}
	if body := get(t, srv, "/page/index", token).Body.String(); !strings.Contains(body, f.links["index"][0].URL) {
		t.Fatal("the link is not listed")
	}
	if _, loc := postFormLoc(t, srv, token, "/shares", url.Values{"op": {"share"}, "page": {"index"}, "days": {"90"}}); !strings.Contains(loc, "e=") {
		t.Errorf("a link for ninety days: %s", loc)
	}
	id := f.links["index"][0].ID
	postFormLoc(t, srv, token, "/shares", url.Values{"op": {"revoke"}, "page": {"about"}, "id": {id}})
	if !f.links["index"][0].Live {
		t.Fatal("revoked through another page")
	}
	postFormLoc(t, srv, token, "/shares", url.Values{"op": {"revoke"}, "page": {"index"}, "id": {id}})
	if f.links["index"][0].Live {
		t.Fatal("not revoked")
	}
	if w := get(t, srv, "/shares", token); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
}

// Somebody who may write but not publish cannot show a draft outside, and
// is not offered to.
func TestAnAuthorCannotShareADraft(t *testing.T) {
	srv, token := asRole(t, auth.RoleAuthor)
	f := &fakeShares{}
	srv.Shares = f.hooks()
	if body := get(t, srv, "/page/index", token).Body.String(); strings.Contains(body, "Make a link") {
		t.Fatal("an author is offered a link")
	}
	postFormLoc(t, srv, token, "/shares", url.Values{"op": {"share"}, "page": {"index"}, "days": {"7"}})
	if len(f.links["index"]) != 0 {
		t.Fatal("an author shared a draft")
	}
}
