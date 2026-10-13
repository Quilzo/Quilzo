// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// handleAgentCost is what agents cost, from the runs that are kept,
// grouped by agent, person, kind of goal or day: /agents/cost.
func (s *Server) handleAgentCost(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "What agents cost", "Principal": p, "Nav": "agents"}
	if s.Agents == nil || s.Agents.Runs == nil {
		data["Unavailable"] = "This build was started without the run store."
		s.render(w, r, "agent_cost.html", data)
		return
	}
	by := r.URL.Query().Get("by")
	valid := false
	for _, g := range agent.CostGroups {
		valid = valid || g == by
	}
	if !valid {
		by = "agent"
	}
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || days < 1 || days > 366 {
		days = 30
	}
	runs, err := s.Agents.Runs("")
	if err != nil {
		data["Unavailable"] = "The runs could not be read: " + err.Error()
		s.render(w, r, "agent_cost.html", data)
		return
	}
	rep := agent.CostOf(runs, by, time.Now().UTC().AddDate(0, 0, -days))
	currency := s.agentCurrency()
	type row struct {
		Key, Href, Cost     string
		Runs, Steps, Tokens int
		Unpriced, Bar       int
		PerRun              string
	}
	var rows []row
	var top int64
	for _, rr := range rep.Rows {
		if rr.Cost > top {
			top = rr.Cost
		}
	}
	for _, rr := range rep.Rows {
		x := row{Key: rr.Key, Runs: rr.Runs, Steps: rr.Steps, Tokens: rr.Tokens,
			Unpriced: rr.Unpriced, Cost: agent.MoneyText(rr.Cost, currency)}
		if rr.Runs > 0 {
			x.PerRun = agent.MoneyText(rr.Cost/int64(rr.Runs), currency)
		}
		if top > 0 {
			x.Bar = int(100 * rr.Cost / top)
			if rr.Cost > 0 && x.Bar < 2 {
				x.Bar = 2
			}
		}
		if by == "agent" {
			x.Href = "/agents/runs?agent=" + rr.Key
		}
		rows = append(rows, x)
	}
	data["By"], data["Days"], data["Groups"] = by, days, agent.CostGroups
	data["Rows"] = rows
	data["Total"] = rep.Total
	data["TotalCost"] = agent.MoneyText(rep.Total.Cost, currency)
	data["Since"] = rep.Since.Format("2 Jan 2006")
	s.render(w, r, "agent_cost.html", data)
}
