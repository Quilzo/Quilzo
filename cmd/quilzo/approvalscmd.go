// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/site"
)

// `quilzo approvals`: everything waiting for a person, in one list — what
// agents are waiting on, tool calls held for a second person, acts on
// other tools a case is waiting to have approved, features and newsletter
// issues agents proposed, the change to the site waiting for approvals,
// and memories held until somebody confirms them. The admin's Approvals
// and Today read the same sources. Each line says what deciding commits to and the
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
			writes = stepWrites(root, declared.Agents[rec.Agent], w.Action.Tool)
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
	// What agents drafted for a person to read and install: the same list
	// the admin's Approvals has, which the command line left out.
	if authorise(root, c, auth.ActInstall, "/") == nil {
		if list, err := proposals(root); err == nil {
			for _, pr := range list {
				out = append(out, waitingItem{Source: "feature", Agent: pr.By, What: "read " + pr.Title + " " + pr.Version,
					Why:     pr.What + ", proposed by an agent for " + pr.For + "; nothing is installed until you install it",
					Commits: "installs", Since: pr.At, Decide: "quilzo feature proposals"})
			}
		}
	}
	// The change to the site waiting for approvals, for whoever may give
	// one: never its author, nor somebody who already has.
	if item, ok := reviewWaiting(root, c, now); ok {
		out = append(out, item)
	}
	// A newsletter issue an agent proposed, for whoever may send it. It
	// was on the Newsletter screen and nowhere a person looks for what is
	// waiting on them.
	if authorise(root, c, auth.ActPublish, "/") == nil {
		if list, err := openNewsletter(root); err == nil {
			if issues, err := list.Issues(); err == nil {
				for _, is := range issues {
					if is.State != newsletter.Proposed {
						continue
					}
					out = append(out, waitingItem{Source: "newsletter", Agent: is.By,
						What:    "send the issue " + strconv.Quote(is.Subject),
						Why:     nonEmpty(is.Note, "proposed from the page "+is.Page),
						Commits: "sends", Since: is.Proposed,
						Decide: "quilzo newsletter send " + is.Page + " --yes"})
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

// reviewWaiting is the change to the site waiting for approvals, when the
// caller may approve it.
func reviewWaiting(root string, c *Caller, now time.Time) (waitingItem, bool) {
	var none waitingItem
	if authorise(root, c, auth.ActEditDraft, "/") != nil {
		return none, false
	}
	s, err := open(root)
	if err != nil {
		return none, false
	}
	draft := s.GetRef(site.RefDraft)
	if draft == "" || draft == s.GetRef(site.RefLive) {
		return none, false
	}
	pol, err := loadApprovalPolicy(root)
	if err != nil || (pol.Required == 0 && !pol.RequireHumanForAI) {
		return none, false
	}
	prop, _, err := currentProposal(root, s)
	if err != nil || prop.Content != draft || prop.Author == c.Name {
		return none, false
	}
	for _, a := range prop.Approvals {
		if a.Content == draft && a.By == c.Name {
			return none, false
		}
	}
	d := pol.Evaluate(*prop, kindOfPrincipal(root), now)
	if d.Allowed {
		return none, false
	}
	since := now
	if prop.CreatedAt > 0 {
		since = time.Unix(prop.CreatedAt, 0)
	}
	return waitingItem{Source: "review", Agent: nonEmpty(prop.Author, "content"),
		What:    "approve the change to the site",
		Why:     fmt.Sprintf("%d of %d approvals; %s", d.Have, d.Need, clip(prop.Message, 160)),
		Commits: "publishes", Since: since, Decide: "quilzo review approve"}, true
}
