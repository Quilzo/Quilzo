// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
)

func withMissing(t *testing.T, srv *Server, added *[]seo.Redirect) {
	t.Helper()
	if _, err := site.Publish(srv.Store, ""); err != nil {
		t.Fatal(err)
	}
	srv.Analytics = &Analytics{
		Read: func(int) ([]analytics.Day, error) {
			return []analytics.Day{{Date: "2026-11-02", Missing: map[string]int{"/abuot": 4, "/careers": 1},
				NoResults: map[string]int{"gift vouchers": 3}}}, nil
		},
		Redirect: func(r seo.Redirect, by string) error { *added = append(*added, r); return nil },
	}
}

// The Analytics screen lists what people looked for and did not find, with
// the page each most likely meant, and sends one there for whoever may
// publish; and the searches that found nothing.
func TestAMissingAddressIsRedirectedFromAnalytics(t *testing.T) {
	srv, token := setup(t)
	var added []seo.Redirect
	withMissing(t, srv, &added)
	body := get(t, srv, "/analytics", token).Body.String()
	for _, want := range []string{"/abuot", "<code>/about</code>", "Redirect it", "/careers", "no close page", "gift vouchers"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	code, loc := postFormLoc(t, srv, token, "/analytics/redirect", url.Values{"from": {"/abuot"}, "to": {"/about"}})
	if code != 303 || refused(loc) || len(added) != 1 || added[0].From != "/abuot" || added[0].To != "/about" || !added[0].Permanent {
		t.Fatalf("%d %s %+v", code, loc, added)
	}
}

// Somebody who may write but not publish is shown the report and cannot
// change where an address goes.
func TestAnAuthorCannotAddARedirect(t *testing.T) {
	srv, token := asRole(t, auth.RoleAuthor)
	var added []seo.Redirect
	withMissing(t, srv, &added)
	if strings.Contains(get(t, srv, "/analytics", token).Body.String(), "Redirect it") {
		t.Fatal("an author is offered a redirect")
	}
	postFormLoc(t, srv, token, "/analytics/redirect", url.Values{"from": {"/abuot"}, "to": {"/about"}})
	if len(added) != 0 {
		t.Fatal("an author added a redirect")
	}
}
