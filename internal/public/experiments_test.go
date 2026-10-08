// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/experiment"
)

func experimentSite(t *testing.T) (*Site, *analytics.Counter) {
	t.Helper()
	st := published(t, map[string]any{
		"index":     map[string]any{"title": "Home"},
		"pricing":   map[string]any{"title": "Pricing A"},
		"pricing-b": map[string]any{"title": "Pricing B"},
		"thanks":    map[string]any{"title": "Thanks"},
	})
	c, err := analytics.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	set := &experiment.Set{}
	if err := set.Put(experiment.Experiment{Name: "price", Page: "pricing", Goal: "page:/thanks",
		Running: true, Variants: []experiment.Variant{
			{Name: "a", Page: "pricing", Weight: 1}, {Name: "b", Page: "pricing-b", Weight: 1}}}); err != nil {
		t.Fatal(err)
	}
	st.Experiments = func() (*experiment.Set, error) { return set, nil }
	return st, c
}

func visitAs(st *Site, path, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = ip + ":1"
	r.Header.Set("User-Agent", browser)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	return w
}

func TestAVariantIsServedAtTheSameAddress(t *testing.T) {
	st, _ := experimentSite(t)
	saw := map[string]bool{}
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		w := visitAs(st, "/pricing", ip)
		body := w.Body.String()
		switch {
		case strings.Contains(body, "Pricing B"):
			saw["b"] = true
		case strings.Contains(body, "Pricing A"):
			saw["a"] = true
		}
		if !strings.HasPrefix(w.Header().Get("Cache-Control"), "private") {
			t.Fatalf("a variant is cacheable by shared caches: %q", w.Header().Get("Cache-Control"))
		}
		// And the same visitor sees the same variant again.
		if again := visitAs(st, "/pricing", ip).Body.String(); strings.Contains(again, "Pricing B") != strings.Contains(body, "Pricing B") {
			t.Fatal("a visitor switched variants within the day")
		}
	}
	if !saw["a"] || !saw["b"] {
		t.Fatalf("forty visitors did not see both variants: %v", saw)
	}
	// A page with no experiment stays publicly cacheable.
	if cc := visitAs(st, "/thanks", "203.0.113.1").Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public") {
		t.Fatalf("an ordinary page became private: %q", cc)
	}
}

// TestOnlyAVisitorWhoSawAVariantCanConvertForIt.
func TestOnlyAVisitorWhoSawAVariantCanConvertForIt(t *testing.T) {
	st, c := experimentSite(t)
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		visitAs(st, "/pricing", ip)
		if i < 10 {
			visitAs(st, "/thanks", ip)
		}
	}
	// Twenty who never saw the pricing page reach the goal.
	for i := 0; i < 20; i++ {
		visitAs(st, "/thanks", fmt.Sprintf("192.0.2.%d", i))
	}
	d := c.Today()
	seen := d.Goals[experiment.SeenKey("price", "a")] + d.Goals[experiment.SeenKey("price", "b")]
	won := d.Goals[experiment.WonKey("price", "a")] + d.Goals[experiment.WonKey("price", "b")]
	if seen != 20 || won != 10 {
		t.Fatalf("seen %d won %d, want 20 and 10", seen, won)
	}
}

func TestAMissingVariantFallsBackToTheControl(t *testing.T) {
	st, c := experimentSite(t)
	set, _ := st.Experiments()
	e, _ := set.Get("price")
	e.Variants[1].Page = "pricing-z" // not published
	set.Experiments[0] = e
	for i := 0; i < 20; i++ {
		if body := visitAs(st, "/pricing", fmt.Sprintf("203.0.113.%d", i)).Body.String(); !strings.Contains(body, "Pricing A") {
			t.Fatal("a missing variant served something else")
		}
	}
	if c.Today().Goals[experiment.SeenKey("price", "b")] != 0 {
		t.Fatal("exposure was recorded for a variant nobody could see")
	}
}
