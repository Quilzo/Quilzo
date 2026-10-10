// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Risk: the queue turned on its side.
//
// The findings queue is one row per finding. This is one row per person or
// thing, with everything open about them added up, because three medium
// findings about one account on two platforms are one thing to look at and
// the queue shows them as three things to get to later.
//
// Where the findings about one entity look like one event — several of
// them, from more than one rule — the row offers to declare an incident
// gathering them, with the playbook that fits the rules that raised them.
// That is an offer: a person declares, and a second person or the
// commander approves the playbook, as for any other.

// playbookFor picks the playbook that fits the rules behind a set of
// findings. A table and not a model: which checklist suits a compromised
// account is known in advance, and a fixed answer can be read and argued
// with.
func playbookFor(parts []finding.Part) string {
	votes := map[string]float64{}
	for _, p := range parts {
		src := strings.ToLower(p.Finding.Source)
		switch {
		case strings.HasPrefix(src, "estate/leaver-device"),
			strings.HasPrefix(src, "estate/unmanaged"):
			votes["lost-device"] += p.Points
		case strings.HasPrefix(src, "intel/"):
			votes["malware-endpoint"] += p.Points
		case strings.HasPrefix(src, "okta."), strings.HasPrefix(src, "entra."),
			strings.HasPrefix(src, "workspace."), strings.HasPrefix(src, "corr."),
			strings.HasPrefix(src, "auth."), strings.HasPrefix(src, "github."),
			strings.HasPrefix(src, "agent/"):
			votes["account-compromise"] += p.Points
		case strings.HasPrefix(src, "aws."), strings.HasPrefix(src, "evm."):
			votes["exposed-data"] += p.Points
		}
	}
	best := ""
	for id, v := range votes {
		if best == "" || v > votes[best] || v == votes[best] && id < best {
			best = id
		}
	}
	return best
}

// MaxRiskRows is how many entities the screen lists.
const MaxRiskRows = 100

func (s *Server) handleRisk(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "risk", "Title": "Risk", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Findings == nil || s.Findings.Queue == nil {
		data["Unavailable"] = "This build was started without a finding register."
		s.render(w, r, "risk.html", data)
		return
	}
	now := time.Now().UTC()
	q, produced, err := s.Findings.Queue(now)
	if err != nil {
		data["Unavailable"] = "The register could not be read: " + err.Error()
		s.render(w, r, "risk.html", data)
		return
	}
	data["Produced"] = produced
	var aliases map[string]string
	if s.People != nil {
		aliases = s.People()
	}
	risks := finding.Risk(q, func(id telemetry.ID) string {
		return aliases[id.String()]
	}, now)

	// What an incident already gathers is not offered again.
	gathered := map[string]string{}
	if s.Cases != nil && s.Cases.List != nil {
		if all, cerr := s.Cases.List(); cerr == nil {
			for _, i := range all {
				for _, f := range i.Findings {
					gathered[f] = i.ID
				}
			}
		}
	}
	playbooks := map[string]string{}
	if s.Cases != nil && s.Cases.Playbooks != nil {
		if all, perr := s.Cases.Playbooks(); perr == nil {
			for _, pb := range all {
				playbooks[pb.ID] = pb.Title
			}
		}
	}

	type part struct {
		ID, Title, Sev, Source, Age, Points, Case string
	}
	type row struct {
		Entity, Href, Band, Tone, Why, Score string
		Person                               bool
		Identifiers                          []string
		Parts                                []part
		W                                    float64
		// Offer is the findings an incident would gather, when there are
		// enough of them to look like one event.
		Offer         []string
		OfferTitle    string
		Playbook      string
		PlaybookTitle string
	}
	var rows []row
	top := 0.0
	if len(risks) > 0 {
		top = risks[0].Score
	}
	high := 0
	for n, e := range risks {
		if e.Band == "high" || e.Band == "critical" {
			high++
		}
		if n >= MaxRiskRows {
			continue
		}
		id := telemetry.ID{Value: e.Entity}
		if e.Person {
			id = telemetry.ID{Issuer: "person", Value: e.Entity}
		} else if issuer, value, cut := strings.Cut(e.Entity, ":"); cut {
			id = telemetry.ID{Issuer: issuer, Value: value}
		}
		rw := row{Entity: e.Entity, Href: entityHref(id), Band: e.Band,
			Tone: map[string]string{"critical": "critical", "high": "serious",
				"medium": "warning", "low": "unknown"}[e.Band],
			Why: e.Why(), Score: fmt.Sprintf("%.0f", e.Score), Person: e.Person,
			Identifiers: e.Identifiers}
		if top > 0 {
			rw.W = math.Round(e.Score/top*1000) / 10
		}
		var loose []finding.Part
		for _, pt := range e.Parts {
			rw.Parts = append(rw.Parts, part{ID: pt.Finding.ID,
				Title: withProductNames(pt.Finding.Title), Sev: severityName(pt.Finding.Severity),
				Source: pt.Finding.Source,
				Age:    agoText(now.Sub(pt.Finding.Last)),
				Points: fmt.Sprintf("%.0f", pt.Points), Case: gathered[pt.Finding.ID]})
			if gathered[pt.Finding.ID] == "" {
				loose = append(loose, pt)
			}
		}
		// Several findings, more than one rule, and worth attention: that
		// is when they are probably one thing.
		if len(loose) >= 2 && e.Rules >= 2 && (e.Band == "high" || e.Band == "critical") &&
			s.Cases != nil && s.Cases.Declare != nil {
			for _, pt := range loose {
				rw.Offer = append(rw.Offer, pt.Finding.ID)
			}
			rw.OfferTitle = fmt.Sprintf("%d findings about %s", len(loose), e.Entity)
			if pb := playbookFor(loose); playbooks[pb] != "" {
				rw.Playbook, rw.PlaybookTitle = pb, playbooks[pb]
			}
		}
		rows = append(rows, rw)
	}
	data["Rows"], data["Entities"], data["High"] = rows, len(risks), high
	if len(risks) > MaxRiskRows {
		data["More"] = len(risks) - MaxRiskRows
	}
	s.render(w, r, "risk.html", data)
}
