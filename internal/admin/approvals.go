// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/waiting"
)

// Approvals: everything waiting for a person, in one place.
//
// What waits lives where it belongs: an agent's question with its run, a
// held tool call with the gateway, a change with the review queue, a
// memory with the person it is about.
// This screen reads each of them and lists what the person looking may
// decide, grouped by agent and by what deciding commits to, so that
// nothing waits unseen because it waited somewhere nobody opened.
//
// Approving several at once is offered only where it stays honest: the
// same action, with the same input and the same reason, waiting in more
// than one run, when that action reads or merely acts. Anything that
// writes, sends, pays, deletes or publishes is decided one at a time, and
// a question is answered one at a time, because each answer is about its
// own run.

// approvalItem is one thing waiting, as the screens show it.
type approvalItem struct {
	Source, Agent, Title, Detail, Commits, Href, When string
	Since                                             time.Time
	// For a run's question: the run, the step and what kind of question.
	RunID, Kind       string
	Step              int
	Live, Expired     bool
	Confidence, Batch string
}

// batchKey is what makes two waiting actions the same (waiting.BatchKey).
func batchKey(agentName string, w *agent.Pending) string { return waiting.BatchKey(agentName, w) }

// runApprovalsFor is what runs wait for that this session may decide: the
// runs' part of the one list, which is what the screen showed, so letting
// several go ahead together is asked of the same list.
//
// Asked of the command line for every item, administrators included,
// because what decides it is more than a role: the session's own limits,
// sponsorship, the approve permission on an agent or on what it would
// change, and whether the person started the run whose risky step it is
// (agentpermissions.go). An item the person could not decide is not shown
// as if they could.
func (s *Server) runApprovalsFor(p principal, now time.Time) []approvalItem {
	var out []approvalItem
	for _, it := range s.waitingItems(p, now) {
		if it.Source == "run" {
			out = append(out, it)
		}
	}
	return out
}

// waitingItems is everything waiting that a person may decide, as
// Approvals, Today and the assistant's waiting card all list it.
//
// The list is internal/waiting's, the one the command line prints. Built
// here twice over, it drifted: an expired question was on one and not the
// other, and what waited outside agent runs was offered to whoever the
// person was rather than to the session they were using, so a read-only
// session was offered a held call, an install, a newsletter issue and the
// review to decide. `quilzo serve` hands the command line's own list over
// as Waiting; without that hook it is built by the same rules from this
// server's hooks.
func (s *Server) waitingItems(p principal, now time.Time) []approvalItem {
	var list []waiting.Item
	if s.Waiting != nil {
		list, _ = s.Waiting(p.actor(), now)
	} else {
		list, _ = waiting.List(s.waitingSources(p), now)
	}
	var items []approvalItem
	// Held memories are one row here, which opens the page that confirms
	// them; the command line lists each by the ID it is confirmed by.
	memories, first := 0, now
	for _, it := range list {
		if it.Source == "memory" {
			memories++
			if it.Since.Before(first) {
				first = it.Since
			}
			continue
		}
		items = append(items, approvalItem{Source: it.Source, Agent: it.Agent, Title: it.What, Detail: it.Why,
			Commits: it.Commits, Href: it.Href, Since: it.Since, RunID: it.RunID, Kind: it.Kind, Step: it.Step,
			Live: it.Live, Expired: it.Expired, Confidence: it.Confidence, Batch: it.Batch})
	}
	if memories > 0 {
		items = append(items, approvalItem{Source: "memory", Agent: "memory",
			Title:   fmt.Sprintf("Confirm or forget %d held %s", memories, map[bool]string{true: "memory", false: "memories"}[memories == 1]),
			Detail:  "learnt after reading somebody else's words, and not recalled until a person confirms it",
			Commits: "writes", Href: "/memory", Since: first})
	}
	for i := range items {
		items[i].When = agoText(now.Sub(items[i].Since))
	}
	return items
}

// waitingSources are this server's own hooks as the places what waits is
// kept, for a server not handed the command line's list. Every question
// about who may decide is asked of the session, through allows.
func (s *Server) waitingSources(p principal) waiting.Sources {
	src := waiting.Sources{Name: p.Name, ReadOnly: p.Limits.ReadOnly,
		May: func(act auth.Action, resource string) bool { return s.allows(p, act, resource) }}
	if s.Agents != nil && s.Agents.Runs != nil {
		declared := map[string]agent.Manifest{}
		var installed agent.Integrations
		src.Runs = func() ([]agent.Record, error) {
			if s.Agents.Load != nil {
				declared, _ = s.Agents.Load()
			}
			// Whether a tool's step writes is the integration's to say as
			// well as the manifest's: the manifest's label defaults to off,
			// and a write listed as a read was offered to approve with
			// others like it.
			if s.Integrations != nil && s.Integrations.Declared != nil {
				installed, _ = s.Integrations.Declared()
			}
			return s.Agents.Runs("")
		}
		src.Writes = func(rec agent.Record, tool string) bool {
			return installed.ToolWrites(declared[rec.Agent], tool)
		}
		src.MayDecide = func(rec agent.Record) bool {
			if s.Agents.MayApprove == nil {
				return s.allows(p, auth.ActApprove, auth.AreaAgents)
			}
			return s.Agents.MayApprove(rec, p.actor())
		}
	}
	if s.Integrations != nil && s.Integrations.Held != nil {
		src.Held = func() ([]waiting.Held, error) {
			held, err := s.Integrations.Held()
			var out []waiting.Held
			for _, h := range held {
				out = append(out, waiting.Held{ID: h.ID, Integration: h.Integration, Tool: h.Tool,
					For: h.For, App: h.App, Asked: h.Asked})
			}
			return out, err
		}
	}
	if s.Features != nil {
		src.Pending = s.Features.Pending
		if s.Features.Proposals != nil {
			src.Proposals = func() ([]waiting.Proposal, error) {
				list, err := s.Features.Proposals()
				var out []waiting.Proposal
				for _, pr := range list {
					out = append(out, waiting.Proposal{ID: pr.ID, By: pr.By, Title: pr.Title, Version: pr.Version,
						What: pr.What, For: pr.For, At: pr.At})
				}
				return out, err
			}
		}
	}
	if s.Store != nil && s.Approvals != nil && s.Approvals.Policy != nil && s.Approvals.Current != nil {
		src.Review = func() (*waiting.Review, error) {
			draft := s.Store.GetRef(site.RefDraft)
			if draft == "" || draft == s.Store.GetRef(site.RefLive) {
				return nil, nil
			}
			pol, err := s.Approvals.Policy()
			if err != nil {
				return nil, err
			}
			prop, err := s.Approvals.Current()
			if err != nil || prop == nil || prop.Content != draft {
				return nil, err
			}
			kindOf := collab.KindOf(s.Approvals.KindOf)
			if kindOf == nil {
				kindOf = func(string) string { return "human" }
			}
			return &waiting.Review{Policy: pol, Proposal: *prop, KindOf: kindOf}, nil
		}
	}
	if s.Newsletter != nil {
		src.Issues = s.Newsletter.Issues
	}
	if s.Memory != nil && s.Memory.Store != nil {
		src.Memories = s.Memory.Store.List
	}
	return src
}

// commitsOrder is what deciding commits to, most urgent first
// (waiting.CommitsOrder).
var commitsOrder = waiting.CommitsOrder

// approvalGroup is the waiting items of one agent or source.
type approvalGroup struct {
	Name  string
	Items []approvalItem
	// Batches are identical actions waiting in several runs.
	Batches []approvalBatch
}

type approvalBatch struct {
	Key, Title, Commits string
	Count               int
	Runs                []approvalItem
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()
	data := map[string]any{"Title": "Approvals", "Nav": "approvals", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	items := s.waitingItems(p, now)
	only := r.URL.Query().Get("commits")
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Commits]++
	}
	if only != "" {
		kept := items[:0]
		for _, it := range items {
			if it.Commits == only {
				kept = append(kept, it)
			}
		}
		items = kept
	}
	byName := map[string]*approvalGroup{}
	var order []string
	for _, it := range items {
		g := byName[it.Agent]
		if g == nil {
			g = &approvalGroup{Name: it.Agent}
			byName[it.Agent] = g
			order = append(order, it.Agent)
		}
		g.Items = append(g.Items, it)
	}
	var groups []approvalGroup
	for _, name := range order {
		g := byName[name]
		sort.SliceStable(g.Items, func(i, j int) bool { return g.Items[i].Since.Before(g.Items[j].Since) })
		seen := map[string]*approvalBatch{}
		var keys []string
		for _, it := range g.Items {
			if it.Batch == "" {
				continue
			}
			b := seen[it.Batch]
			if b == nil {
				b = &approvalBatch{Key: it.Batch, Title: it.Title, Commits: it.Commits}
				seen[it.Batch] = b
				keys = append(keys, it.Batch)
			}
			b.Count++
			b.Runs = append(b.Runs, it)
		}
		for _, k := range keys {
			if seen[k].Count > 1 {
				g.Batches = append(g.Batches, *seen[k])
			}
		}
		groups = append(groups, *g)
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].Items) > len(groups[j].Items) })
	type chip struct {
		Name  string
		Count int
	}
	var chips []chip
	for _, c := range commitsOrder {
		if counts[c] > 0 {
			chips = append(chips, chip{c, counts[c]})
		}
	}
	data["Groups"], data["Chips"], data["Only"], data["Total"] = groups, chips, only, len(items)
	s.render(w, r, "approvals.html", data)
}

// handleApprovalsAct approves identical actions waiting in several runs,
// after checking again that each is still waiting, unchanged, on a class
// of action that may be approved together.
func (s *Server) handleApprovalsAct(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	back := func(msg string, err error) {
		v := "m=" + url.QueryEscape(msg)
		if err != nil {
			v = "e=" + url.QueryEscape(err.Error())
		}
		http.Redirect(w, r, "/approvals?"+v, http.StatusSeeOther)
	}
	if s.Agents == nil || s.Agents.Answer == nil {
		http.NotFound(w, r)
		return
	}
	key := r.FormValue("batch")
	if key == "" {
		back("", fmt.Errorf("say which actions to let go ahead"))
		return
	}
	now := time.Now().UTC()
	wanted := map[string]bool{}
	for _, v := range r.PostForm["run"] {
		wanted[v] = true
	}
	done, failed := 0, 0
	var why error
	for _, it := range s.runApprovalsFor(p, now) {
		if it.Batch != key || !wanted[it.RunID+":"+strconv.Itoa(it.Step)] || !agent.Batchable(it.Commits) {
			continue
		}
		if err := s.Agents.Answer(it.RunID, it.Step, true, nil, p.actor()); err != nil {
			failed++
			why = err
			continue
		}
		done++
	}
	switch {
	case done == 0 && why != nil:
		back("", why)
	case done == 0:
		back("", fmt.Errorf("none of those is still waiting as it was shown; look again"))
	case failed > 0:
		back(fmt.Sprintf("%d went ahead; %d could not: %v", done, failed, why), nil)
	default:
		back(fmt.Sprintf("%d went ahead, each exactly as it was shown.", done), nil)
	}
}
