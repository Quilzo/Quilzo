// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
)

func TestTheAnalyticsScreenShowsTheDays(t *testing.T) {
	srv, token := setup(t)
	srv.Analytics = &Analytics{Read: func(days int) ([]analytics.Day, error) {
		out := make([]analytics.Day, days)
		out[days-1] = analytics.Day{Date: "2026-09-29", Views: 40, Visitors: 12, Prefetch: 5,
			Pages:     map[string]analytics.Page{"/<b>x</b>": {Views: 30, Visitors: 10}},
			Referrers: map[string]int{"news.example": 4},
			Goals:     map[string]int{"form:contact": 3}}
		return out, nil
	}}
	body := get(t, srv, "/analytics?days=7", token).Body.String()
	for _, want := range []string{"<svg", "news.example", "form:contact", "25.0%", "Prefetched"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
	if strings.Contains(body, "<b>x</b>") {
		t.Fatal("a path from a request reached the page unescaped")
	}
	reader, rtoken := asRole(t, auth.RoleReader)
	reader.Analytics = srv.Analytics
	if w := get(t, reader, "/analytics", rtoken); w.Code == 200 {
		t.Fatal("a reader opened the analytics")
	}
}
