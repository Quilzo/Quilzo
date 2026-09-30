// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/indicator"
)

// Indicators: what somebody else has said is bad, what each has found, and
// when each stops being believed.
//
// The column that matters is the last one. A list of indicators with no
// view of what they found is a list nobody can prune, and one that is
// never pruned ends as a list of other people's infrastructure. So the
// screen leads with the indicators that raised something, shows how many
// of those a person ruled false, and puts the lapsed ones where they can
// be removed.

// Indicators is what the screen needs from whoever holds the store.
type Indicators struct {
	List func(now time.Time) ([]indicator.Indicator, map[string]IndicatorHits, error)
	// Add stores one and looks back through the events for it, returning
	// how many events carried it and how many findings that opened.
	Add func(kind, value, source, note, until, by string) (hits, opened int,
		known bool, err error)
	Remove func(id, by string) error
}

// IndicatorHits is what one indicator has found.
type IndicatorHits struct {
	Findings, Real, False int
	Last                  time.Time
}

// MaxIndicatorRows is how many the screen lists.
const MaxIndicatorRows = 200

func (s *Server) handleIndicators(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "indicators", "Title": "Indicators",
		"Principal": p, "Message": r.URL.Query().Get("m"),
		"Error": r.URL.Query().Get("e"), "Kinds": indicator.Kinds}
	if s.Indicators == nil || s.Indicators.List == nil {
		data["Unavailable"] = "This build was started without the indicator store."
		s.render(w, r, "indicators.html", data)
		return
	}
	now := time.Now().UTC()
	all, hits, err := s.Indicators.List(now)
	if err != nil {
		data["Unavailable"] = "The indicators could not be read: " + err.Error()
		s.render(w, r, "indicators.html", data)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	data["Q"] = q
	type row struct {
		indicator.Indicator
		Sources, UntilText, Left, LastHit string
		Lapsed                            bool
		H                                 IndicatorHits
	}
	var rows []row
	var live, lapsed, found, doubted int
	for _, i := range all {
		h := hits[i.ID]
		if i.Live(now) {
			live++
		} else {
			lapsed++
		}
		if h.Findings > 0 {
			found++
		}
		if h.False > 0 && h.Real == 0 {
			doubted++
		}
		if q != "" && !strings.Contains(i.Value, q) &&
			!strings.Contains(strings.ToLower(strings.Join(i.Sources, " ")), q) &&
			!strings.Contains(strings.ToLower(i.Note), q) {
			continue
		}
		rw := row{Indicator: i, Sources: strings.Join(i.Sources, ", "),
			UntilText: i.Until.Format("2 Jan 2006"), Lapsed: !i.Live(now), H: h}
		if !rw.Lapsed {
			rw.Left = fmt.Sprintf("%d day(s) left",
				int(i.Until.Sub(now).Hours()/24)+1)
		}
		if h.Findings > 0 {
			rw.LastHit = agoText(now.Sub(h.Last))
		}
		rows = append(rows, rw)
	}
	// What found something first, then what has lapsed, then the rest by
	// how soon it lapses.
	sort.SliceStable(rows, func(a, b int) bool {
		x, y := rows[a], rows[b]
		if (x.H.Findings > 0) != (y.H.Findings > 0) {
			return x.H.Findings > 0
		}
		if x.Lapsed != y.Lapsed {
			return x.Lapsed
		}
		return x.Until.Before(y.Until)
	})
	data["Matching"] = len(rows)
	if len(rows) > MaxIndicatorRows {
		data["More"] = len(rows) - MaxIndicatorRows
		rows = rows[:MaxIndicatorRows]
	}
	data["Rows"], data["Held"] = rows, len(all)
	tiles := []wfTile{
		{Label: "Believed", Value: fmt.Sprint(live)},
		{Label: "Lapsed", Value: fmt.Sprint(lapsed),
			Note: "matching nothing, and worth removing"},
		{Label: "Found something", Value: fmt.Sprint(found)},
		{Label: "Only ever ruled false", Value: fmt.Sprint(doubted),
			Note: "a claim that has not held up here"},
	}
	if doubted > 0 {
		tiles[3].Tone = "serious"
	}
	data["Tiles"] = tiles
	data["Tomorrow"] = now.Add(24 * time.Hour).Format("2006-01-02")
	data["MaxUntil"] = now.Add(indicator.MaxLife - 24*time.Hour).Format("2006-01-02")
	s.render(w, r, "indicators.html", data)
}

func (s *Server) handleIndicatorsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	if s.Indicators == nil || s.Indicators.Add == nil || s.Indicators.Remove == nil {
		http.Error(w, "this build cannot change the indicators",
			http.StatusServiceUnavailable)
		return
	}
	back := func(msg string, err error) {
		v := url.Values{}
		if err != nil {
			v.Set("e", err.Error())
		} else {
			v.Set("m", msg)
		}
		http.Redirect(w, r, "/security/indicators?"+v.Encode(),
			http.StatusSeeOther)
	}
	switch r.FormValue("do") {
	case "add":
		hits, opened, known, err := s.Indicators.Add(r.FormValue("kind"),
			r.FormValue("value"), r.FormValue("source"), r.FormValue("note"),
			r.FormValue("until"), p.Name)
		if err != nil {
			back("", err)
			return
		}
		switch {
		case known:
			back("Already held; the source was added to it.", nil)
		case hits == 0:
			back("Added. Nothing already stored carries it.", nil)
		default:
			back(fmt.Sprintf("Added. %d stored event(s) carry it: %d new "+
				"finding(s) are in the queue.", hits, opened), nil)
		}
	case "remove":
		back("Removed. What it already found stays in the queue.",
			s.Indicators.Remove(r.FormValue("id"), p.Name))
	default:
		http.Error(w, "nothing to do", http.StatusBadRequest)
	}
}
