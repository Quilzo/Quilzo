// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/personalise"
)

func personaliseRig() (*Personalise, *personalise.Set) {
	set := &personalise.Set{}
	return &Personalise{
		Load: func() (*personalise.Set, error) {
			return &personalise.Set{Rules: append([]personalise.Rule(nil), set.Rules...)}, nil
		},
		Save: func(s *personalise.Set, _, _, _ string) error { *set = *s; return nil },
		Simulate: func(campaign, _, _, _, _ string) (*http.Request, time.Time, error) {
			return httptest.NewRequest("GET", "/?utm_source="+campaign, nil), time.Now(), nil
		},
	}, set
}

func TestARuleIsAddedTurnedOnAndSimulated(t *testing.T) {
	srv, token := setup(t)
	x, set := personaliseRig()
	srv.Personalise = x
	decideForm(t, srv, "/personalise/change", token, url.Values{"op": {"add"}, "name": {"news"},
		"page": {"index"}, "variant": {"index-news"}, "field0": {"campaign"}, "values0": {"newsletter"}})
	r, ok := set.Get("news")
	if !ok || r.Enabled || len(r.When) != 1 {
		t.Fatalf("%+v", set)
	}
	decideForm(t, srv, "/personalise/change", token, url.Values{"op": {"enable"}, "name": {"news"}})
	if r, _ = set.Get("news"); !r.Enabled {
		t.Fatal("not turned on")
	}
	body := get(t, srv, "/personalise?page=index&campaign=newsletter", token).Body.String()
	if !strings.Contains(body, "applies") || !strings.Contains(body, "/index-news") {
		t.Fatal("the simulator did not name the rule")
	}
	body = get(t, srv, "/personalise?page=index&campaign=other", token).Body.String()
	if !strings.Contains(body, "No rule applies") {
		t.Fatal("the simulator applied a rule without its condition")
	}
	// A rule with no condition would be an edit to everybody's page.
	w := decideForm(t, srv, "/personalise/change", token, url.Values{"op": {"add"}, "name": {"all"},
		"page": {"index"}, "variant": {"index-b"}})
	if !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatal("a rule with no conditions was accepted")
	}
}
