// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
)

// Analytics is the site's traffic, counted without a script or a cookie.
type Analytics struct {
	Read func(days int) ([]analytics.Day, error)
}

// bar is one day in the chart, drawn on the server as SVG: no chart library
// and no script, which is the only kind of chart this interface's policy
// allows, and one that prints and reads to a screen reader as a table below.
type bar struct {
	X, Y, H, W float64
	Label      string
	Views      int
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	data := map[string]any{"Nav": "analytics", "Title": "Analytics", "Principal": p}
	if s.Analytics == nil || s.Analytics.Read == nil {
		data["Unavailable"] = "This build was started without analytics."
		s.render(w, r, "analytics.html", data)
		return
	}
	days := 30
	if n, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && (n == 7 || n == 30 || n == 90) {
		days = n
	}
	list, err := s.Analytics.Read(days)
	if err != nil {
		data["Unavailable"] = "The counts could not be read: " + err.Error()
		s.render(w, r, "analytics.html", data)
		return
	}
	sum := analytics.Summarise(list)
	peak := 1
	for _, d := range list {
		if d.Views > peak {
			peak = d.Views
		}
	}
	const width, height = 600.0, 140.0
	step := width / float64(len(list))
	var bars []bar
	for i, d := range list {
		h := float64(d.Views) / float64(peak) * (height - 4)
		bars = append(bars, bar{X: float64(i)*step + 1, Y: height - h, H: h,
			W: step - 2, Label: d.Date, Views: d.Views})
	}
	if len(sum.Pages) > 15 {
		sum.Pages = sum.Pages[:15]
	}
	if len(sum.Referrers) > 15 {
		sum.Referrers = sum.Referrers[:15]
	}
	conv := ""
	if sum.Visitors > 0 {
		total := 0
		for _, g := range sum.Goals {
			total += g.Count
		}
		conv = fmt.Sprintf("%.1f%%", float64(total)/float64(sum.Visitors)*100)
	}
	data["S"], data["Bars"], data["Days"], data["Peak"] = sum, bars, days, peak
	data["Conversion"] = conv
	s.render(w, r, "analytics.html", data)
}
