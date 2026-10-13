// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/gateway"
)

// `quilzo agent cost`: what runs cost, grouped (see internal/agent/cost.go).

// gatewayCurrency is the currency the gateway prices in, or empty.
func gatewayCurrency(root string) string {
	cfg, err := gateway.Load(gatewayPath(root))
	if err != nil || cfg == nil {
		return ""
	}
	return cfg.Currency
}

// formatCost writes millionths of a currency for a person.
func formatCost(micros int64, currency string) string { return agent.MoneyText(micros, currency) }

// agentCost is `quilzo agent cost [--by agent|person|goal|day] [--since D] [NAME]`.
func agentCost(root string, args []string) error {
	fs := flag.NewFlagSet("agent cost", flag.ContinueOnError)
	by := fs.String("by", "agent", "group by agent, person, goal or day")
	since := fs.Duration("since", 30*24*time.Hour, "how far back to look")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *by {
	case "agent", "person", "goal", "day":
	default:
		return fmt.Errorf("--by is agent, person, goal or day, not %q", *by)
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("usage: quilzo agent cost [--by agent|person|goal|day] [--since 720h] [NAME]")
	}
	runs, err := listAgentRuns(root, fs.Arg(0), 0)
	if err != nil {
		return err
	}
	rep := agent.CostOf(runs, *by, time.Now().UTC().Add(-*since))
	rep.Currency = gatewayCurrency(root)
	if w.JSON(rep) {
		return nil
	}
	if rep.Total.Runs == 0 {
		fmt.Printf("  no runs kept since %s\n", rep.Since.Format("2 Jan 2006"))
		return nil
	}
	fmt.Printf("  %s%-40s %6s %7s %10s %16s%s\n", dim, "by "+*by, "runs", "steps", "tokens", "cost", reset)
	for _, r := range append(rep.Rows, rep.Total) {
		note := ""
		if r.Unpriced > 0 {
			note = fmt.Sprintf("  %s%d unpriced%s", dim, r.Unpriced, reset)
		}
		fmt.Printf("  %-40s %6d %7d %10d %16s%s\n", truncate(r.Key, 40), r.Runs, r.Steps, r.Tokens,
			formatCost(r.Cost, rep.Currency), note)
	}
	fmt.Printf("  %sthe %d runs kept since %s; a run a model decided with no price is counted as unpriced%s\n",
		dim, rep.Total.Runs, rep.Since.Format("2 Jan 2006"), reset)
	return nil
}
