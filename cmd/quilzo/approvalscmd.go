// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/incident"
	"github.com/quilzo/quilzo/internal/memory"
)

// `quilzo approvals`: everything waiting for a person, in one list — what
// agents are waiting on, tool calls held for a second person, acts on
// other tools a case is waiting to have approved, and memories held until
// somebody confirms them. Each line says what deciding commits to and the
// command that decides it.

// waitingItem is one thing waiting, for the command line.
type waitingItem struct {
	Source  string    `json:"source"`
	Agent   string    `json:"agent,omitempty"`
	What    string    `json:"what"`
	Why     string    `json:"why,omitempty"`
	Commits string    `json:"commits"`
	Since   time.Time `json:"since"`
	Decide  string    `json:"decide"`
}

// waitingFor lists what the caller may decide.
func waitingFor(root string, c *Caller, now time.Time) ([]waitingItem, error) {
	var out []waitingItem
	admin := authorise(root, c, auth.ActGrant, "/") == nil
	// A run's question is listed for whoever may decide it, which is its
	// sponsor and whoever holds approve on it, not only administrators.
	runs, err := listAgentRuns(root, "", 0)
	if err != nil {
		return nil, err
	}
	declared, _ := loadAgents(root)
	for _, rec := range runs {
		w := rec.Trace.Waiting
		if w == nil || rec.Eval != "" || now.Sub(w.Since) > agent.PendingTTL || mayApprove(root, c, rec) != nil {
			continue
		}
		if w.Live && (rec.State != agent.Running || now.Sub(rec.Beat) > agent.StaleAfter) {
			continue
		}
		writes := false
		if declared != nil {
			if m, ok := declared.Agents[rec.Agent]; ok {
				for _, t := range m.Tools {
					writes = writes || (t.Name == w.Action.Tool && t.Writes)
				}
			}
		}
		what := w.Action.Op
		if what == "" {
			what = w.Action.Tool
		}
		it := waitingItem{Source: "run", Agent: rec.Agent, What: what, Why: w.Why, Since: w.Since,
			Commits: agent.CommitOf(w.Action, w.Why, w.Kind, writes),
			Decide:  fmt.Sprintf("quilzo agent approve %s %d", rec.ID, w.N)}
		if w.Kind == agent.WaitQuestion {
			var names []string
			for _, q := range w.Questions {
				names = append(names, q.Name+"=…")
			}
			it.What = "answer " + strings.Join(names, " ")
			it.Decide = fmt.Sprintf("quilzo agent answer %s %d %s", rec.ID, w.N, strings.Join(names, " "))
		}
		out = append(out, it)
	}
	// A held tool call through the gateway is decided by whoever holds
	// approve over the store, a feature by whoever may install one.
	if authorise(root, c, auth.ActApprove, "/") == nil {
		held, err := heldCalls(root, now)
		if err != nil {
			return nil, err
		}
		for _, h := range held {
			if h.Principal == c.Name {
				continue
			}
			out = append(out, waitingItem{Source: "gateway", Agent: h.Integration, What: h.Tool,
				Why: "for " + h.Principal + ", held until a second person decides", Commits: "acts",
				Since: h.Asked, Decide: "quilzo integrations approve " + h.ID})
		}
	}
	if authorise(root, c, auth.ActInstall, "/") == nil {
		if pend, err := pendingFeatures(root); err == nil {
			for _, p := range pend {
				if strings.EqualFold(p.RequestedBy, c.Name) {
					continue
				}
				what := "install feature " + p.Name + " " + p.Version
				if p.Rollback {
					what = "roll feature " + p.Name + " back to " + p.Version
				}
				out = append(out, waitingItem{Source: "feature", Agent: p.Name, What: what,
					Why:     "risk " + p.Card.Risk + ": " + strings.Join(p.Card.Because, "; ") + "; asked by " + p.RequestedBy,
					Commits: "installs", Since: p.At, Decide: "quilzo feature approve " + p.ID})
			}
		}
	}
	if admin {
		if list, err := listIncidents(root); err == nil {
			for _, inc := range list {
				for _, a := range inc.Acts {
					if a.State != incident.ActRequested || a.Requested.By == c.Name {
						continue
					}
					out = append(out, waitingItem{Source: "case", Agent: "case " + inc.ID,
						What: a.Title + " on " + a.Target, Why: "asked by " + a.Requested.By,
						Commits: "acts", Since: a.Requested.At,
						Decide: fmt.Sprintf("quilzo incident act-approve %s %d", inc.ID, a.ID)})
				}
			}
		}
	}
	f := memory.Filter{}
	if !admin {
		f.About = c.Name
	}
	if all, err := memoryStore(root).List(f); err == nil {
		for _, e := range all {
			if e.Held && (admin || e.About == c.Name) {
				out = append(out, waitingItem{Source: "memory", Agent: e.Agent, What: "confirm memory " + e.ID,
					Why: "learnt after reading somebody else's words", Commits: "writes", Since: e.Created,
					Decide: "quilzo memory confirm " + e.ID})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out, nil
}

func cmdApprovals(root string, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: quilzo approvals")
	}
	now := time.Now().UTC()
	items, err := waitingFor(root, resolveCaller(root, ""), now)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"waiting": items}) {
		return nil
	}
	if len(items) == 0 {
		fmt.Println("  nothing is waiting for you")
		return nil
	}
	for _, it := range items {
		who := it.Agent
		if who == "" {
			who = it.Source
		}
		fmt.Printf("  %s%-9s%s %-18s %s  %s%s%s\n", bold, it.Commits, reset, truncate(who, 18),
			truncate(printable(it.What), 60), dim, it.Since.Format("2 Jan 15:04"), reset)
		if it.Why != "" {
			fmt.Printf("            %s%s%s\n", dim, truncate(printable(it.Why), 100), reset)
		}
		fmt.Printf("            %s\n", it.Decide)
	}
	return nil
}
