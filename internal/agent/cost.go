// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// What agents cost, from the runs that are kept: by agent, by the person
// who started them, by the kind of goal, or by day. Each step records the
// tokens and money of the model's choice and of whatever the action itself
// charged, so a run's cost is the sum of its steps and a goal's is the sum
// of its runs. Money is at the gateway's prices, in its currency.

// CostRow is one group in a cost report.
type CostRow struct {
	Key    string `json:"key"`
	Runs   int    `json:"runs"`
	Steps  int    `json:"steps"`
	Tokens int    `json:"tokens"`
	// Cost is in millionths of the report's currency.
	Cost int64 `json:"cost_micros"`
	// Unpriced counts runs a model decided and nobody priced: a local model,
	// or a route with no prices. Zero there is not free, it is unknown.
	Unpriced int `json:"unpriced,omitempty"`
}

// CostReport is runs' cost, grouped.
type CostReport struct {
	By       string    `json:"by"`
	Since    time.Time `json:"since"`
	Currency string    `json:"currency,omitempty"`
	Rows     []CostRow `json:"rows"`
	Total    CostRow   `json:"total"`
}

// CostGroups are what a report may group by.
var CostGroups = []string{"agent", "person", "goal", "day"}

var (
	reGoalURL    = regexp.MustCompile(`https?://\S+`)
	reGoalEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reGoalQuoted = regexp.MustCompile(`"[^"]*"|“[^”]*”|'[^']*'`)
	reGoalNumber = regexp.MustCompile(`\d+([.,:/-]\d+)*`)
	reGoalSpace  = regexp.MustCompile(`\s+`)
)

// GoalPattern is a goal with what changes between runs of the same task
// taken out: addresses, quoted words and numbers. "Refund order 1234" and
// "Refund order 98" are one kind of goal.
func GoalPattern(goal string) string {
	g := strings.ToLower(strings.TrimSpace(goal))
	g = reGoalURL.ReplaceAllString(g, "<link>")
	g = reGoalEmail.ReplaceAllString(g, "<address>")
	g = reGoalQuoted.ReplaceAllString(g, "<text>")
	g = reGoalNumber.ReplaceAllString(g, "#")
	g = reGoalSpace.ReplaceAllString(g, " ")
	if g == "" {
		return "(no goal)"
	}
	if r := []rune(g); len(r) > 80 {
		g = string(r[:79]) + "…"
	}
	return g
}

func costKey(rec Record, by string) string {
	switch by {
	case "person":
		return rec.By
	case "goal":
		return GoalPattern(rec.Goal)
	case "day":
		return rec.Started.UTC().Format("2006-01-02")
	}
	return rec.Agent
}

// CostOf groups the runs started since a time. Evaluation runs are left
// out: they are tests, and a test's cost is not the work's.
func CostOf(runs []Record, by string, since time.Time) CostReport {
	rep := CostReport{By: by, Since: since}
	rows := map[string]*CostRow{}
	for _, rec := range runs {
		if rec.Started.Before(since) || rec.Eval != "" {
			continue
		}
		key := costKey(rec, by)
		row := rows[key]
		if row == nil {
			row = &CostRow{Key: key}
			rows[key] = row
		}
		spent := rec.Trace.Spent
		for _, r := range []*CostRow{row, &rep.Total} {
			r.Runs++
			r.Steps += len(rec.Trace.Steps)
			r.Tokens += spent.Tokens
			r.Cost += spent.Cost
			if rec.Model != "" && spent.Cost == 0 {
				r.Unpriced++
			}
		}
	}
	for _, r := range rows {
		rep.Rows = append(rep.Rows, *r)
	}
	sort.Slice(rep.Rows, func(i, j int) bool {
		if by == "day" {
			return rep.Rows[i].Key > rep.Rows[j].Key
		}
		if rep.Rows[i].Cost != rep.Rows[j].Cost {
			return rep.Rows[i].Cost > rep.Rows[j].Cost
		}
		return rep.Rows[i].Key < rep.Rows[j].Key
	})
	rep.Total.Key = "all"
	return rep
}

// MoneyText writes millionths of a currency for a person: four places,
// more only when the amount would otherwise read as nothing.
func MoneyText(micros int64, currency string) string {
	s := fmt.Sprintf("%d.%04d", micros/1_000_000, (micros%1_000_000)/100)
	if micros > 0 && micros < 100 {
		s = fmt.Sprintf("0.%06d", micros)
	}
	if currency != "" {
		s += " " + currency
	}
	return s
}
