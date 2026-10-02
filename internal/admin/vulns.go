// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/vuln"
)

// The vulnerability workbench.
//
// A scanner's screen is a list of CVEs sorted by severity, and the person
// reading it does three pieces of arithmetic the screen could have done:
// which of these matter, what single change clears the most of them, and
// which have already been looked at. This screen leads with the second —
// the changes, smallest version first — because that is the work; the queue
// underneath is the reasoning, and each row opens onto its working.
//
// Everything decided here is an assessment with a name, a reason and,
// where it takes something out of the queue for a while, a date it comes
// back. Nothing is dismissed.

// Vulns is what the workbench needs from whoever holds the store.
type Vulns struct {
	Load func(now time.Time) (VulnView, error)
	// Assess records one assessment, validated and audited.
	Assess func(a vuln.Assessment) error
	// Tag and Untag change what is said about an asset.
	Tag   func(tag vuln.AssetTag, by string) error
	Untag func(match, by string) error
}

// VulnView is the stored queue, matched.
type VulnView struct {
	Advisories  []vuln.Advisory
	Components  int
	Matched     []vuln.Exposure
	Assessments []vuln.Assessment
	History     []vuln.Tally
	// Tree is the SSVC decision table, nil when none is loaded, and Tags
	// what this organisation says about its assets. Assets is every asset
	// in the inventory, for saying which have no tag.
	Tree   vuln.Tree
	Tags   vuln.Tags
	Assets []string
	// When each list was last loaded. Zero is never.
	AdvisoriesAt, InventoryAt time.Time
}

// StaleAfter is how old the advisory list may be before the screen says so
// above everything else. A queue built from last month's list is missing
// exactly the vulnerabilities published since, and looks the same.
const StaleAfter = 7 * 24 * time.Hour

func vulnHref(id string) string { return "/security/vuln/" + url.PathEscape(id) }

// loadVulns is the shared opening of both screens.
func (s *Server) loadVulns(data map[string]any, now time.Time) (VulnView, bool) {
	if s.Vulns == nil || s.Vulns.Load == nil {
		data["Unavailable"] = "This build was started without the " +
			"vulnerability store."
		return VulnView{}, false
	}
	v, err := s.Vulns.Load(now)
	if err != nil {
		data["Unavailable"] = "The vulnerability store could not be read: " +
			err.Error() + ". That is not an estate with nothing wrong."
		return v, false
	}
	if v.AdvisoriesAt.IsZero() || v.InventoryAt.IsZero() {
		data["Empty"] = true
		data["NoAdvisories"] = v.AdvisoriesAt.IsZero()
		data["NoInventory"] = v.InventoryAt.IsZero()
		return v, false
	}
	if age := now.Sub(v.AdvisoriesAt); age > StaleAfter {
		data["Stale"] = fmt.Sprintf("The advisory list was loaded %s ago. "+
			"Anything published since is not here, and its absence looks "+
			"the same as being safe.", plainAge(age))
	}
	ago := func(d time.Duration) string {
		if d < time.Minute {
			return "just now"
		}
		return plainAge(d) + " ago"
	}
	data["AdvisoriesAge"] = ago(now.Sub(v.AdvisoriesAt))
	data["InventoryAge"] = ago(now.Sub(v.InventoryAt))
	data["AdvisoryCount"], data["ComponentCount"] = len(v.Advisories),
		v.Components
	return v, true
}

func liveOf(matched []vuln.Exposure) []vuln.Exposure {
	var out []vuln.Exposure
	for _, e := range matched {
		if !e.Silenced {
			out = append(out, e)
		}
	}
	return out
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "vulns", "Title": "Vulnerabilities",
		"Principal": p, "Message": r.URL.Query().Get("m"),
		"Error": r.URL.Query().Get("e")}
	now := time.Now().UTC()
	v, ok := s.loadVulns(data, now)
	if !ok {
		s.render(w, r, "vulns.html", data)
		return
	}
	live := liveOf(v.Matched)
	groups := vuln.Groups(live)
	tally := vuln.Summarise(v.Matched, now)
	decided := tally.NotAffected + tally.Fixed + tally.Accepted +
		tally.Investigating

	tiles := []wfTile{
		{Label: "Open vulnerabilities", Value: fmt.Sprint(tally.Vulnerabilities),
			Note: fmt.Sprintf("in %d place(s)", tally.Exposures)},
		{Label: "Being exploited", Value: fmt.Sprint(tally.Exploited),
			Note: "somebody has said so, by name"},
		{Label: "Expected in 30 days", Value: fmt.Sprintf("%.1f", tally.Expected),
			Note: "the sum of the probabilities"},
		{Label: "Decided away", Value: "0",
			Note: "each with a reason and a name"},
	}
	if tally.Exploited > 0 {
		tiles[1].Tone = "critical"
	}
	if tally.Lapsed > 0 {
		tiles = append(tiles, wfTile{Label: "Decisions that ran out",
			Value: fmt.Sprint(tally.Lapsed), Tone: "serious",
			Note: "back in the queue"})
	}
	// The sentence somebody with a Tuesday afternoon needs.
	const head = 10
	if len(groups) > head && tally.Expected > 0 {
		share := vuln.Expected(vuln.Flatten(groups[:head]), now) / tally.Expected
		data["Concentration"] = fmt.Sprintf("The first %d carry %.0f%% of "+
			"the expected exploitation; the other %d carry the rest.", head,
			share*100, len(groups)-head)
	}

	// What to change.
	type upRow struct {
		vuln.Upgrade
		From   string
		Clears []string
		W      float64
		Share  string
	}
	ups := vuln.Upgrades(live, v.Advisories, now)
	var most float64
	for _, u := range ups {
		most = math.Max(most, u.Expected)
	}
	var upRows []upRow
	for i, u := range ups {
		if i == 25 {
			data["MoreUpgrades"] = len(ups) - 25
			break
		}
		row := upRow{Upgrade: u, From: strings.Join(u.Versions, ", "),
			Clears: u.Clears}
		if most > 0 {
			row.W = math.Round(u.Expected/most*1000) / 10
		}
		if tally.Expected > 0 && u.Expected > 0 {
			row.Share = fmt.Sprintf("%.0f%%", u.Expected/tally.Expected*100)
			if row.Share == "0%" {
				row.Share = "under 1%"
			}
		}
		upRows = append(upRows, row)
	}
	data["Upgrades"] = upRows

	// The queue, one row per vulnerability.
	type qRow struct {
		ID, Href, Package, Version, Why string
		Assets                          int
		Exploited, Lapsed               bool
		Weight                          int
		W                               float64
		SSVC, SSVCTone, SSVCNote        string
	}
	var top float64
	if len(groups) > 0 {
		top = groups[0].Worst().Weight(now)
	}
	var queue []qRow
	for i, g := range groups {
		if i == 50 {
			data["MoreQueue"] = len(groups) - 50
			break
		}
		e := g.Worst()
		yes, _ := g.Advisory.Attested()
		row := qRow{ID: g.Advisory.ID, Href: vulnHref(g.Advisory.ID),
			Package: e.Component.Name, Version: e.Component.Version,
			Why: e.Explain(now), Assets: g.Assets(), Exploited: yes,
			Lapsed: e.Assessed.Lapsed(now), Weight: int(e.Weight(now))}
		if top > 0 {
			row.W = math.Round(e.Weight(now)/top*1000) / 10
		}
		if v.Tree != nil {
			var worst vuln.Decision
			for n, x := range g.On {
				if d := v.Tree.Decide(x, v.Tags); n == 0 || d.More(worst) {
					worst = d
				}
			}
			row.SSVC, row.SSVCTone, row.SSVCNote = ssvcWord(worst)
		}
		queue = append(queue, row)
	}
	data["Queue"] = queue

	// SSVC: whether there is a table, what is said about the assets, and
	// which assets nothing is said about.
	data["HasTree"] = v.Tree != nil
	type tagRow struct {
		vuln.AssetTag
		When  string
		Count int
	}
	var tagRows []tagRow
	covered := map[string]int{}
	untagged := 0
	var example []string
	for _, a := range v.Assets {
		if t, ok := v.Tags.For(a); ok {
			covered[t.Match]++
			continue
		}
		untagged++
		if len(example) < 5 {
			example = append(example, a)
		}
	}
	for _, t := range v.Tags {
		tagRows = append(tagRows, tagRow{t, t.At.Format("2 Jan 2006"),
			covered[t.Match]})
	}
	data["Tags"], data["Untagged"] = tagRows, untagged
	data["UntaggedExample"] = strings.Join(example, ", ")
	data["Exposures"], data["Impacts"] = vuln.Exposures, vuln.Impacts

	// What has been decided, soonest to come back first.
	type dRow struct {
		ID, Href, Component, What, Tone, By, Owner, Because, Until, Left string
		Places                                                           int
	}
	byKey := map[string]*dRow{}
	var order []string
	for _, e := range v.Matched {
		if !e.Silenced {
			continue
		}
		a := e.Assessed
		k := a.Key()
		if d, seen := byKey[k]; seen {
			d.Places++
			continue
		}
		d := &dRow{ID: e.Advisory.ID, Href: vulnHref(e.Advisory.ID),
			Component: a.Component, By: a.By, Owner: a.Owner,
			Because: a.Because, Places: 1}
		d.What, d.Tone = decisionWord(a)
		if !a.Until.IsZero() {
			d.Until = a.Until.Format("2 Jan 2006")
			d.Left = fmt.Sprintf("%d day(s) left",
				int(a.Until.Sub(now).Hours()/24)+1)
		}
		byKey[k] = d
		order = append(order, k)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := byKey[order[i]], byKey[order[j]]
		if (a.Until == "") != (b.Until == "") {
			return a.Until != ""
		}
		return a.ID < b.ID
	})
	var decidedRows []dRow
	for _, k := range order {
		decidedRows = append(decidedRows, *byKey[k])
	}
	data["Decided"] = decidedRows
	// Counted as decisions, which is what somebody made; the places each
	// one covers are beside it.
	tiles[3].Value = fmt.Sprint(len(decidedRows))
	if decided > 0 {
		tiles[3].Note = fmt.Sprintf("covering %d place(s), each with a "+
			"reason and a name", decided)
	}
	data["Tiles"] = tiles

	// The trend: open vulnerabilities by day.
	pts, note := vulnTrend(v.History)
	data["Trend"], data["TrendNote"] = pts, note
	if len(pts) > 0 {
		var line []string
		for _, pt := range pts {
			line = append(line, fmt.Sprintf("%.1f,%.1f", pt.X, pt.Y))
		}
		data["TrendLine"] = strings.Join(line, " ")
		data["TrendStart"], data["TrendEnd"] = pts[0], pts[len(pts)-1]
	}
	type day struct {
		Date                                   string
		Open, Exploited, Accepted, NotAffected int
		Expected                               string
	}
	var days []day
	for _, h := range v.History {
		days = append(days, day{Date: h.At.Format("2006-01-02"),
			Open: h.Vulnerabilities, Exploited: h.Exploited,
			Accepted: h.Accepted, NotAffected: h.NotAffected,
			Expected: fmt.Sprintf("%.1f", h.Expected)})
	}
	if len(days) > 90 {
		days = days[len(days)-90:]
	}
	data["History"] = days
	s.render(w, r, "vulns.html", data)
}

// decisionWord names an assessment the way the screen shows it, with the
// tone its label takes.
func decisionWord(a vuln.Assessment) (string, string) {
	switch {
	case a.Accepted():
		return "accepted", "warning"
	case a.Status == vuln.NotAffected:
		return "not affected", "good"
	case a.Status == vuln.Fixed:
		return "fixed", "good"
	case a.Status == vuln.UnderInvestigation:
		return "being looked at", "unknown"
	default:
		return "affected", "serious"
	}
}

// vulnTrend lays out open vulnerabilities over the last ninety days.
func vulnTrend(hist []vuln.Tally) ([]wfPoint, string) {
	if len(hist) > 90 {
		hist = hist[len(hist)-90:]
	}
	if len(hist) < 2 {
		return nil, "The trend appears once the queue has been recorded " +
			"on two different days."
	}
	const w, h, pad, top = 600.0, 120.0, 10.0, 28.0
	most := 1
	for _, d := range hist {
		if d.Vulnerabilities > most {
			most = d.Vulnerabilities
		}
	}
	var pts []wfPoint
	for i, d := range hist {
		pts = append(pts, wfPoint{
			X:    math.Round((pad+float64(i)/float64(len(hist)-1)*(w-2*pad))*10) / 10,
			Y:    math.Round((h-pad-float64(d.Vulnerabilities)/float64(most)*(h-pad-top))*10) / 10,
			Date: d.At.Format("2006-01-02"), Value: fmt.Sprint(d.Vulnerabilities)})
	}
	return pts, ""
}

// handleVuln is one vulnerability: what is known, why it ranks where it
// does, where it is, what has been decided, and the forms to decide.
func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimPrefix(r.URL.Path, "/security/vuln/")
	data := map[string]any{"Nav": "vulns", "Title": "Vulnerability",
		"Principal": p, "Message": r.URL.Query().Get("m"),
		"Error": r.URL.Query().Get("e")}
	now := time.Now().UTC()
	v, ok := s.loadVulns(data, now)
	if !ok {
		s.render(w, r, "vuln.html", data)
		return
	}
	var adv *vuln.Advisory
	for i := range v.Advisories {
		if v.Advisories[i].ID == id {
			adv = &v.Advisories[i]
		}
	}
	if adv == nil {
		http.NotFound(w, r)
		return
	}
	data["Title"] = adv.ID
	data["A"] = adv
	yes, who := adv.Attested()
	data["Exploited"], data["ExploitedBy"] = yes, strings.Join(who, " and ")
	data["EPSS"] = fmt.Sprintf("%.1f%%", adv.EPSS*100)
	data["EPSSStale"] = adv.EPSS > 0 && !adv.Fresh(now)
	data["Known"] = adv.Known.Format("2 Jan 2006")
	data["KnownAge"] = plainAge(now.Sub(adv.Known))

	var mine []vuln.Exposure
	for _, e := range v.Matched {
		if e.Advisory.ID == adv.ID {
			mine = append(mine, e)
		}
	}
	type place struct {
		Where, Version, Reach, ReachNote, State, Tone, Fix string
		SSVC, SSVCTone, SSVCNote                           string
	}
	// Open places whose own source does not name the vulnerable symbols:
	// grounds for a decision, which is still a person's to make.
	unnamed := 0
	var places []place
	packages := map[string]bool{}
	var worst *vuln.Exposure
	for i, e := range mine {
		packages[e.Component.Key()] = true
		pl := place{Where: e.Component.Where.String(),
			Version: e.Component.Version, Reach: "not analysed",
			State: "open", Tone: "serious"}
		if e.Component.Reachable != nil {
			pl.Reach = "not reachable"
			if *e.Component.Reachable {
				pl.Reach = "reachable"
			}
		}
		if e.Reach != nil {
			pl.Reach, pl.ReachNote = "named in its source", e.Reach.Says()
			if !e.Reach.Referenced {
				pl.Reach = "not named in its source"
				if !e.Silenced {
					unnamed++
				}
			}
		}
		if fix, ok := e.Fixable(); ok {
			pl.Fix = fix
		}
		if v.Tree != nil && !e.Silenced {
			pl.SSVC, pl.SSVCTone, pl.SSVCNote = ssvcWord(v.Tree.Decide(e, v.Tags))
		}
		if e.Silenced {
			pl.State, pl.Tone = decisionWord(e.Assessed)
		} else if worst == nil {
			worst = &mine[i]
		}
		if i < 200 {
			places = append(places, pl)
		}
	}
	data["Places"], data["PlaceCount"] = places, len(mine)
	data["HasTree"] = v.Tree != nil
	data["Unnamed"] = unnamed
	if worst != nil {
		type term struct {
			vuln.Term
			Pts string
			W   float64
		}
		var terms []term
		total := worst.Weight(now)
		for _, t := range worst.Terms(now) {
			row := term{Term: t, Pts: fmt.Sprintf("%.0f", t.Points)}
			if total > 0 {
				row.W = math.Round(t.Points/total*1000) / 10
			}
			terms = append(terms, row)
		}
		data["Terms"], data["Weight"] = terms, fmt.Sprintf("%.0f", total)
		data["Open"] = true
	}

	// Every assessment ever made about it, newest first: the record, not
	// only the one in force.
	type said struct {
		vuln.Assessment
		What, Tone, When, UntilText string
		Lapsed                      bool
	}
	var history []said
	for _, a := range v.Assessments {
		if a.Advisory != adv.ID {
			continue
		}
		row := said{Assessment: a, When: a.At.Format("2 Jan 2006"),
			Lapsed: a.Lapsed(now)}
		row.What, row.Tone = decisionWord(a)
		if !a.Until.IsZero() {
			row.UntilText = a.Until.Format("2 Jan 2006")
		}
		history = append(history, row)
	}
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].At.After(history[j].At)
	})
	data["Said"] = history

	data["Packages"] = sortedStrings(packages)
	data["Reasons"] = vuln.Justifications()
	data["Tomorrow"] = now.Add(24 * time.Hour).Format("2006-01-02")
	data["MaxLook"] = now.Add(vuln.MaxInvestigation - 24*time.Hour).Format("2006-01-02")
	limit := vuln.MaxAcceptance
	if yes {
		limit = vuln.MaxAcceptanceExploited
	}
	data["MaxAccept"] = now.Add(limit - 24*time.Hour).Format("2006-01-02")
	data["AcceptDays"] = int(limit.Hours() / 24)
	s.render(w, r, "vuln.html", data)
}

// handleVulnsAct records a decision about one vulnerability in one package.
func (s *Server) handleVulnsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if s.Vulns == nil || s.Vulns.Assess == nil {
		http.Error(w, "this build cannot record an assessment",
			http.StatusServiceUnavailable)
		return
	}
	if do := r.FormValue("do"); do == "tag" || do == "untag" {
		to := func(msg string, err error) {
			v := url.Values{}
			if err != nil {
				v.Set("e", err.Error())
			} else {
				v.Set("m", msg)
			}
			http.Redirect(w, r, "/security/vulns?"+v.Encode(),
				http.StatusSeeOther)
		}
		if s.Vulns.Tag == nil || s.Vulns.Untag == nil {
			http.Error(w, "this build cannot tag assets",
				http.StatusServiceUnavailable)
			return
		}
		match := strings.TrimSpace(r.FormValue("match"))
		if do == "untag" {
			to("The tag is removed.", s.Vulns.Untag(match, p.Name))
			return
		}
		to("Tagged. Decisions for those assets no longer depend on a guess.",
			s.Vulns.Tag(vuln.AssetTag{Match: match,
				Exposure: r.FormValue("exposure"), Impact: r.FormValue("impact"),
				Because: strings.TrimSpace(r.FormValue("because"))}, p.Name))
		return
	}
	id := strings.TrimSpace(r.FormValue("advisory"))
	back := func(msg string, err error) {
		v := url.Values{}
		if err != nil {
			v.Set("e", err.Error())
		} else {
			v.Set("m", msg)
		}
		http.Redirect(w, r, vulnHref(id)+"?"+v.Encode(), http.StatusSeeOther)
	}
	now := time.Now().UTC()
	a := vuln.Assessment{Advisory: id,
		Component: strings.ToLower(strings.TrimSpace(r.FormValue("component"))),
		At:        now, By: p.Name, Kind: audit.KindHuman,
		Because: strings.TrimSpace(r.FormValue("because"))}
	// The end of the named day, so "until the 1st" includes the 1st.
	until := func() (time.Time, bool) {
		d, err := time.Parse("2006-01-02", r.FormValue("until"))
		if err != nil {
			return time.Time{}, false
		}
		return d.UTC().Add(24*time.Hour - time.Second), true
	}
	var done string
	switch r.FormValue("do") {
	case "not_affected":
		a.Status = vuln.NotAffected
		a.Justification = vuln.Justification(r.FormValue("reason"))
		a.Impact = strings.TrimSpace(r.FormValue("impact"))
		done = "Recorded as not affected."
	case "investigate":
		a.Status = vuln.UnderInvestigation
		end, ok := until()
		if !ok {
			back("", fmt.Errorf("looking into it needs the date by which "+
				"there will be an answer"))
			return
		}
		a.Until = end
		done = "Out of the queue until " + end.Format("2 Jan 2006") +
			", and back in it then."
	case "accept":
		a.Status = vuln.Affected
		a.Owner = strings.TrimSpace(r.FormValue("owner"))
		end, ok := until()
		if !ok {
			back("", fmt.Errorf("an acceptance needs the date it ends"))
			return
		}
		a.Until = end
		done = "Accepted until " + end.Format("2 Jan 2006") +
			". It comes back into the queue then."
	case "fixed":
		a.Status = vuln.Fixed
		done = "Recorded as fixed."
	case "reopen":
		// A bare affected statement: the newest assessment wins, and this
		// one silences nothing.
		a.Status = vuln.Affected
		done = "Back in the queue."
	default:
		http.Error(w, "nothing to do", http.StatusBadRequest)
		return
	}
	back(done, s.Vulns.Assess(a))
}

// ssvcWord is an SSVC decision for a table cell: the word, its tone, and
// what it depends on when an input is missing.
func ssvcWord(d vuln.Decision) (word, tone, note string) {
	if d.Worst == "" {
		return "", "", ""
	}
	tone = map[string]string{"immediate": "critical", "out-of-cycle": "serious",
		"scheduled": "warning", "defer": "unknown"}[d.Worst]
	if d.Settled() || d.Worst == d.Best {
		return d.Worst, tone, ""
	}
	return d.Best + " to " + d.Worst, tone,
		"depends on " + strings.Join(d.Unknown, ", and ")
}
