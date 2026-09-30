// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/personalise"
)

func TestARuleServesItsPageAndTakesPrecedence(t *testing.T) {
	st, c := experimentSite(t)
	set := &personalise.Set{}
	if err := set.Put(personalise.Rule{Name: "news", Page: "pricing", Variant: "thanks",
		Enabled: true, When: []personalise.Condition{{Field: personalise.Campaign, Values: []string{"newsletter"}}}}); err != nil {
		t.Fatal(err)
	}
	st.Personalise = func() (*personalise.Set, error) { return set, nil }

	r := httptest.NewRequest("GET", "/pricing?utm_source=newsletter", nil)
	r.RemoteAddr = "203.0.113.5:1"
	r.Header.Set("User-Agent", browser)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "Thanks") || !strings.HasPrefix(w.Header().Get("Cache-Control"), "private") {
		t.Fatalf("the rule's page was not served privately: %q", w.Header().Get("Cache-Control"))
	}
	d := c.Today()
	if d.Goals[personalise.SeenKey("news")] != 1 {
		t.Fatal("the rule's exposure was not counted")
	}
	// The experiment on the same page did not also count this visitor.
	if d.Goals["exp/price/a/seen"]+d.Goals["exp/price/b/seen"] != 0 {
		t.Fatal("a personalised visitor was counted in the experiment")
	}
	// Without the campaign, the experiment runs as before.
	if body := visitAs(st, "/pricing", "203.0.113.6").Body.String(); strings.Contains(body, "Thanks") {
		t.Fatal("the rule applied without its condition")
	}
}
