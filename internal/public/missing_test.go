// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
)

// An address a person asked for that is not here is counted; one somebody
// hunting for an admin asked for is the shield's, not the owner's report.
func TestAMissingAddressIsCounted(t *testing.T) {
	st, _ := askSite(t, shopBot)
	c, err := analytics.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	h := map[string]string{"User-Agent": browser}
	get(st, "/old-returns-policy", h)
	get(st, "/old-returns-policy", h)
	get(st, "/wp-admin/", h)
	get(st, "/returns", h)
	d := c.Today()
	if d.Missing["/old-returns-policy"] != 2 || len(d.Missing) != 1 {
		t.Fatalf("%+v", d.Missing)
	}
}

// A search that found nothing is counted, with an address in it masked.
func TestAnEmptySearchIsCountedMasked(t *testing.T) {
	st := published(t, map[string]any{
		"index":   map[string]any{"title": "Home"},
		"search":  map[string]any{"title": "Search"},
		"returns": map[string]any{"title": "Returns", "body": "Unopened items within thirty days."},
	})
	c, err := analytics.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	st.IndexLive = true
	h := map[string]string{"User-Agent": browser}
	get(st, "/search?q=laptops+for+ana.lopez%40gmail.com", h)
	get(st, "/search?q=returns", h)
	d := c.Today()
	if len(d.NoResults) != 1 {
		t.Fatalf("%+v", d.NoResults)
	}
	for q := range d.NoResults {
		if !strings.Contains(q, "laptops") || strings.Contains(q, "ana.lopez") {
			t.Fatalf("%q", q)
		}
	}
}
