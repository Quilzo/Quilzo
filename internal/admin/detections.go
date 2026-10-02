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

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/detect"
)

// The Detections screen: what each rule has been worth, which ring it is
// in, what is suppressed, and what the numbers suggest changing.
//
// The rules themselves are not edited here. A rule is a file in a
// repository, reviewed and diffed like code; what this screen changes is
// the two things that belong to whoever is on call — the ring and the
// suppressions — and each change asks for a reason and is written to the
// audit log.

// Detections is what the screen reads and the three things it can do.
type Detections struct {
	Load func(now time.Time) (DetectionView, error)
	Ring func(rule string, ring detect.Ring, because, by string,
		kind audit.Kind) error
	Suppress   func(s detect.Suppression) error
	Unsuppress func(id, by string, kind audit.Kind) error
}

// DetectionView is everything the screen shows.
type DetectionView struct {
	Rules        []detect.Rule
	Stats        []detect.Stats
	Proposals    []detect.Proposal
	Suppressions []detect.Suppression
	Hits         map[string]int
}

// verdictBar is a rule's verdicts as one bar, in viewBox units out of 200.
type verdictBar struct {
	RealW, FalseX, FalseW, BenignX, BenignW, OpenX, OpenW float64
}

func verdictBarOf(s detect.Stats) verdictBar {
	total := float64(s.Decided() + s.Undecided)
	if total == 0 {
		return verdictBar{}
	}
	// Two units of surface between segments, so neighbours read apart
	// without a stroke drawn round them.
	const width, gap = 200.0, 2.0
	seg := func(n int) float64 { return float64(n) / total * width }
	b := verdictBar{RealW: seg(s.Real)}
	x := b.RealW
	place := func(n int) (float64, float64) {
		w := seg(n)
		if w == 0 {
			return x, 0
		}
		start := x
		if start > 0 {
			start += gap
			w -= gap
			if w < 1 {
				w = 1
			}
		}
		x += seg(n)
		return start, w
	}
	b.FalseX, b.FalseW = place(s.False)
	b.BenignX, b.BenignW = place(s.Benign)
	b.OpenX, b.OpenW = place(s.Undecided)
	return b
}

func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Nav": "detections", "Title": "Detections",
		"Principal": p, "Message": r.URL.Query().Get("m"),
		"Error": r.URL.Query().Get("e")}
	if s.Detections == nil || s.Detections.Load == nil {
		data["Unavailable"] = "This build was started without the detections."
		s.render(w, r, "detections.html", data)
		return
	}
	now := time.Now().UTC()
	v, err := s.Detections.Load(now)
	if err != nil {
		data["Unavailable"] = "The detections could not be read: " +
			err.Error() + ". That is not an estate with no rules."
		s.render(w, r, "detections.html", data)
		return
	}
	stats := map[string]detect.Stats{}
	for _, st := range v.Stats {
		stats[st.Rule] = st
	}
	type row struct {
		detect.Rule
		S        detect.Stats
		Bar      verdictBar
		Quality  string
		Enough   bool
		Last     string
		RingTone string
		Severity string
	}
	var rows []row
	var live, trial, off, silent int
	for _, rule := range v.Rules {
		st := stats[rule.ID]
		rw := row{Rule: rule, S: st, Bar: verdictBarOf(st),
			Severity: severityName(rule.Severity)}
		switch st.Ring {
		case detect.Trial:
			trial++
			rw.RingTone = "warning"
		case detect.Off:
			off++
			rw.RingTone = "unknown"
		default:
			live++
			rw.RingTone = "good"
		}
		if rate, low, high, enough := st.Useful(); enough {
			rw.Enough = true
			rw.Quality = fmt.Sprintf("%.0f%% real (likely %.0f–%.0f%%)",
				rate*100, low*100, high*100)
		} else {
			rw.Quality = fmt.Sprintf("%d of the %d verdicts needed",
				st.Decided(), detect.MinVerdicts)
		}
		// One thing is only "most of the noise" when it is: at least three
		// verdicts and half of them. Naming an account from a single false
		// positive — and filling the suppression form in with it — would be
		// nudging somebody to silence a rule for no reason.
		if noise := st.False + st.Benign; st.NoisyCount < 3 ||
			st.NoisyCount*2 < noise {
			rw.S.NoisyEntity, rw.S.NoisyCount = "", 0
		}
		if st.Findings == 0 {
			silent++
		} else {
			rw.Last = plainAge(now.Sub(st.Last)) + " ago"
		}
		rows = append(rows, rw)
	}
	data["Rows"] = rows
	data["Live"], data["Trial"], data["Off"], data["Silent"] = live, trial,
		off, silent
	data["Proposals"] = v.Proposals

	type supRow struct {
		detect.Suppression
		Hidden  int
		Expired bool
		Left    string
	}
	var sups []supRow
	for _, sp := range v.Suppressions {
		sr := supRow{Suppression: sp, Hidden: v.Hits[sp.ID],
			Expired: !sp.Active(now)}
		if !sr.Expired {
			sr.Left = fmt.Sprintf("%d days left", int(sp.Until.Sub(now).Hours()/24)+1)
		}
		sups = append(sups, sr)
	}
	sort.Slice(sups, func(i, j int) bool { return sups[i].Until.Before(sups[j].Until) })
	data["Suppressions"] = sups

	// Techniques, for finding your way and not as a score: which rules name
	// each one, and whether any of them has ever fired.
	type tech struct {
		ID    string
		Rules []string
		Fired bool
	}
	byTech := map[string]*tech{}
	for _, rule := range v.Rules {
		if stats[rule.ID].Ring == detect.Off {
			continue
		}
		for _, id := range rule.Technique {
			t := byTech[id]
			if t == nil {
				t = &tech{ID: id}
				byTech[id] = t
			}
			t.Rules = append(t.Rules, rule.ID)
			t.Fired = t.Fired || stats[rule.ID].Findings > 0
		}
	}
	var techs []tech
	for _, t := range byTech {
		techs = append(techs, *t)
	}
	sort.Slice(techs, func(i, j int) bool { return techs[i].ID < techs[j].ID })
	data["Techniques"] = techs
	data["MaxUntil"] = now.Add(detect.MaxSuppression).Format("2006-01-02")
	data["Tomorrow"] = now.Add(24 * time.Hour).Format("2006-01-02")
	data["Rings"] = detect.Rings()
	s.render(w, r, "detections.html", data)
}

func (s *Server) handleDetectionsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if s.Detections == nil || s.Detections.Ring == nil {
		http.Error(w, "this build cannot change the detections",
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
		http.Redirect(w, r, "/security/detections?"+v.Encode(),
			http.StatusSeeOther)
	}
	rule := strings.TrimSpace(r.FormValue("rule"))
	switch r.FormValue("do") {
	case "ring":
		ring := detect.Ring(r.FormValue("ring"))
		err := s.Detections.Ring(rule, ring, r.FormValue("because"), p.Name,
			audit.KindHuman)
		back(fmt.Sprintf("%s is in the %s ring.", rule, ring), err)
	case "suppress":
		until, perr := time.Parse("2006-01-02", r.FormValue("until"))
		if perr != nil {
			back("", fmt.Errorf("a suppression needs the date it stops"))
			return
		}
		err := s.Detections.Suppress(detect.Suppression{Rule: rule,
			Field: r.FormValue("field"), Value: strings.TrimSpace(r.FormValue("value")),
			Owner:   strings.TrimSpace(r.FormValue("owner")),
			Because: strings.TrimSpace(r.FormValue("because")),
			By:      p.Name, Kind: audit.KindHuman,
			Until: until.Add(24*time.Hour - time.Second)})
		back(fmt.Sprintf("%s is suppressed for %s until %s.", rule,
			r.FormValue("value"), until.Format("2 Jan 2006")), err)
	case "unsuppress":
		err := s.Detections.Unsuppress(r.FormValue("id"), p.Name,
			audit.KindHuman)
		back("The suppression is removed.", err)
	default:
		http.Error(w, "nothing to do", http.StatusBadRequest)
	}
}
