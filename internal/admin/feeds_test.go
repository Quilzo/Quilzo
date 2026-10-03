// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

type feedsFake struct {
	added, removed []string
	off            map[string]bool
}

func wireFeeds(srv *Server) *feedsFake {
	f := &feedsFake{off: map[string]bool{}}
	srv.Feeds = &FeedsAdmin{
		List: func() ([]FeedView, error) {
			return []FeedView{{Name: "okta", Kind: "okta", KindWords: "Okta event hook", Path: "/feeds/okta",
				Deliveries: 3, Stored: 7, Signals: 1, Last: "3 Oct 09:12",
				Recent: []FeedSignal{{At: "3 Oct 09:12", Type: "account-disabled", Words: "Account disabled",
					Person: "ivo@acme.example", Severity: "medium", Tone: "warning"}}}}, nil
		},
		Mappings: func() []string { return []string{"okta/system"} },
		Add: func(kind, name, mapping, issuer, url, alias, by string) ([]string, error) {
			f.added = append(f.added, kind+":"+name)
			return []string{"Authorization header value: s3cr3t-shown-once"}, nil
		},
		SetOff: func(name string, off bool, by string) error { f.off[name] = off; return nil },
		Remove: func(name, by string) error { f.removed = append(f.removed, name); return nil },
	}
	return f
}

// An analyst sees what is arriving and cannot add, switch off or remove a
// feed: whoever adds one decides whose word reaches the automations.
func TestAnAnalystReadsFeedsAndCannotChangeThem(t *testing.T) {
	srv, token := asJob(t, "analyst")
	f := wireFeeds(srv)
	page := getPage(t, srv, "/security/feeds", token)
	if !strings.Contains(page, "ivo@acme.example") || strings.Contains(page, `value="add"`) {
		t.Errorf("an analyst's page: signals shown %v, add form shown %v",
			strings.Contains(page, "ivo@acme.example"), strings.Contains(page, `value="add"`))
	}
	postForm(t, srv, "/security/feeds/act", token, "do=add&kind=okta&name=mine")
	postForm(t, srv, "/security/feeds/act", token, "do=off&name=okta")
	postForm(t, srv, "/security/feeds/act", token, "do=remove&name=okta")
	if len(f.added) != 0 || len(f.removed) != 0 || len(f.off) != 0 {
		t.Errorf("an analyst changed feeds: %+v", f)
	}
}

// An administrator adds one, and the secret is on that answer only: not in
// a redirect, an address bar or anything cached.
func TestAddingAFeedShowsItsSecretOnce(t *testing.T) {
	srv, token := setup(t)
	f := wireFeeds(srv)
	w := postForm(t, srv, "/security/feeds/act", token, "do=add&kind=okta&name=okta-main")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "s3cr3t-shown-once") {
		t.Fatalf("adding answered %d", w.Code)
	}
	if w.Header().Get("Location") != "" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("the secret's page can be kept: Location %q Cache-Control %q", w.Header().Get("Location"), w.Header().Get("Cache-Control"))
	}
	if len(f.added) != 1 || f.added[0] != "okta:okta-main" {
		t.Errorf("added %v", f.added)
	}
	if strings.Contains(getPage(t, srv, "/security/feeds", token), "s3cr3t-shown-once") {
		t.Error("the secret is on the screen again")
	}
	postForm(t, srv, "/security/feeds/act", token, "do=off&name=okta")
	if !f.off["okta"] {
		t.Error("an administrator could not switch a feed off")
	}
}
