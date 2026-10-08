// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/estate"
	"github.com/quilzo/quilzo/internal/mcp"
)

// The estate, for an agent: in aggregate, and never by name.
//
// An agent asked "how is our security awareness going" needs the bands,
// the areas, the trend and what could not be checked. It does not need a
// list of who clicked, and a list of named employees and their failings
// inside a model's context is a copy of it in whatever that context is
// logged to. The individual findings stay behind list_findings, where each
// one is read on purpose; the people and their scores are not offered here
// at all.
func registerEstateOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "estate_summary", NeedsRole: "admin",
		Summary: "how many people are at each level of risk, where, and what " +
			"could not be checked — numbers only, no names",
		Detail: "Built from the company's tools as last read: bands, the " +
			"areas the risk is in, the trend by day, which tools were read " +
			"and when, and which cross-tool checks could not run and why. " +
			"No person is named; the findings the checks raised are in " +
			"list_findings.",
		Keywords: []string{"workforce", "risk", "estate", "training",
			"phishing", "devices", "compliance", "people"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActGrant, auth.AreaSecurity); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		now := time.Now().UTC()
		e, o, err := buildEstate(root, now)
		if err != nil {
			return nil, err
		}
		sum := estate.Summarise(e.Scores(now), now)
		byCheck := map[string]int{}
		for _, f := range o.Findings {
			byCheck[f.Source]++
		}
		type tool struct {
			Name     string `json:"name"`
			ReadAt   string `json:"read_at"`
			Complete bool   `json:"complete"`
		}
		var tools []tool
		for name, snap := range e.Sources {
			complete := true
			for _, info := range snap.Endpoints {
				complete = complete && info.Complete
			}
			tools = append(tools, tool{Name: name,
				ReadAt: snap.At.Format(time.RFC3339), Complete: complete})
		}
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		joined := 0
		for _, p := range e.People {
			if len(p.Sources) > 1 {
				joined++
			}
		}
		out := map[string]any{
			"scored": sum.Scored, "mean": sum.Mean, "bands": sum.Bands,
			"areas": sum.Areas, "leavers_with_live_devices": sum.Leavers,
			"people": len(e.People), "people_in_two_or_more_tools": joined,
			"machines": len(e.Machines), "findings_by_check": byCheck,
			"checks_not_run": o.Skipped, "tools": tools,
		}
		if hist, herr := loadHistory(root); herr == nil {
			if len(hist) > 30 {
				hist = hist[len(hist)-30:]
			}
			type day struct {
				Date   string  `json:"date"`
				Mean   float64 `json:"mean"`
				AtRisk int     `json:"high_or_critical"`
			}
			var days []day
			for _, d := range hist {
				days = append(days, day{Date: d.Date, Mean: d.Mean,
					AtRisk: d.Bands[estate.BandHigh] + d.Bands[estate.BandCritical]})
			}
			out["trend"] = days
		}
		b, err := json.Marshal(out)
		return string(b), err
	})
}
