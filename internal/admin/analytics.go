// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
)

// Analytics is the site's traffic, counted without a script or a cookie.
type Analytics struct {
	Read func(days int) ([]analytics.Day, error)
	// Redirect adds a redirect from an address nobody found to a page, as
	// quilzo redirect add does. Nil offers none.
	Redirect func(r seo.Redirect, by string) error
}

// missingRow is an address people asked for that is not there, with the
// page it most likely meant.
type missingRow struct {
	analytics.Ranked
	Suggest string
}

// handleAnalyticsRedirect sends an address nobody found to a page. It
// changes the live site at once, so it takes what publishing takes.
func (s *Server) handleAnalyticsRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/analytics?"+key+"="+url.QueryEscape(msg)+"#missing", http.StatusSeeOther)
	}
	if s.Analytics == nil || s.Analytics.Redirect == nil {
		back("e", "this build cannot add redirects")
		return
	}
	from, to := strings.TrimSpace(r.FormValue("from")), strings.TrimSpace(r.FormValue("to"))
	if from == "" || to == "" {
		back("e", "a redirect needs where from and where to")
		return
	}
	if !strings.HasPrefix(to, "/") {
		to = "/" + to
	}
	if err := s.Analytics.Redirect(seo.Redirect{From: from, To: to, Permanent: true,
		Note: "from the Analytics screen: asked for and not found"}, p.Name); err != nil {
		back("e", err.Error())
		return
	}
	s.audit("redirect.added", from, map[string]string{"by": p.Name, "to": to})
	back("m", from+" now goes to "+to)
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
	// What people looked for and did not find, and the page each most
	// likely meant: offered as a redirect for a person to confirm.
	var live []string
	if pages, perr := site.PagesAt(s.Store, site.RefLive); perr == nil {
		for name := range site.Visible(pages, time.Now()) {
			live = append(live, name)
		}
	}
	var missing []missingRow
	for i, m := range sum.Missing {
		if i == 20 {
			break
		}
		row := missingRow{Ranked: m}
		if m.Name != analytics.Other {
			row.Suggest, _ = seo.Suggest(m.Name, live)
		}
		missing = append(missing, row)
	}
	if len(sum.NoResults) > 20 {
		sum.NoResults = sum.NoResults[:20]
		data["S"] = sum
	}
	data["Missing"] = missing
	data["CanRedirect"] = s.Analytics.Redirect != nil && s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed
	data["Message"], data["Error"] = r.URL.Query().Get("m"), r.URL.Query().Get("e")
	s.render(w, r, "analytics.html", data)
}
