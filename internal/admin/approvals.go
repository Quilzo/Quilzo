// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/incident"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/site"
)

// Approvals: everything waiting for a person, in one place.
//
// What waits lives where it belongs: an agent's question with its run, a
// held tool call with the gateway, a change with the review queue, an act
// on another tool with its case, a memory with the person it is about.
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

// approvalItem is one thing waiting.
type approvalItem struct {
	Source, Agent, Title, Detail, Commits, Href, When string
	Since                                             time.Time
	// For a run's question: the run, the step and what kind of question.
	RunID, Kind       string
	Step              int
	Live, Expired     bool
	Confidence, Batch string
}

// batchKey is what makes two waiting actions the same: the agent, the
// action with its input, and the reason it waits.
func batchKey(agentName string, w *agent.Pending) string {
	in, _ := json.Marshal(w.Action.Input)
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", agentName, w.Kind, w.Action.Op, w.Action.Tool, in, w.Why)
}

// runApprovals are the questions agent runs are waiting on.
// runApprovalsFor is what runs wait for that a person may decide: all of
// it for whoever may approve over every agent, and otherwise what the
// command line says they may (their agents', or on what they own).
func (s *Server) runApprovalsFor(p principal, now time.Time) []approvalItem {
	all := s.runApprovals(now)
	if s.Policy == nil || s.Policy.Evaluate(p.Name, auth.ActApprove, auth.AreaAgents).Allowed {
		return all
	}
	if s.Agents == nil || s.Agents.MayApprove == nil || s.Agents.RunGet == nil {
		return nil
	}
	var out []approvalItem
	for _, it := range all {
		if rec, err := s.Agents.RunGet(it.RunID); err == nil && s.Agents.MayApprove(rec, p.Name) {
			out = append(out, it)
		}
	}
	return out
}

func (s *Server) runApprovals(now time.Time) []approvalItem {
	if s.Agents == nil || s.Agents.Runs == nil {
		return nil
	}
	runs, err := s.Agents.Runs("")
	if err != nil {
		return nil
	}
	declared := map[string]agent.Manifest{}
	if s.Agents.Load != nil {
		declared, _ = s.Agents.Load()
	}
	var out []approvalItem
	for _, rec := range runs {
		w := rec.Trace.Waiting
		if w == nil || rec.Eval != "" {
			continue
		}
		if w.Live && (rec.State != agent.Running || now.Sub(rec.Beat) > agent.StaleAfter) {
			continue
		}
		writes := false
		if w.Action.Tool != "" {
			if m, ok := declared[rec.Agent]; ok {
				for _, t := range m.Tools {
					if t.Name == w.Action.Tool {
						writes = t.Writes
					}
				}
			}
		}
		what := w.Action.Op
		if what == "" {
			what = w.Action.Tool
		}
		it := approvalItem{Source: "run", Agent: rec.Agent, RunID: rec.ID, Step: w.N, Kind: w.Kind,
			Since: w.Since, Live: w.Live, Href: "/agents/run/" + rec.ID,
			Expired: now.Sub(w.Since) > agent.PendingTTL,
			Commits: agent.CommitOf(w.Action, w.Why, w.Kind, writes)}
		switch w.Kind {
		case agent.WaitQuestion:
			var asks []string
			low := 1.0
			for _, q := range w.Questions {
				asks = append(asks, q.Ask)
				if q.Confidence < low {
					low = q.Confidence
				}
			}
			it.Title = "Answer: " + strings.Join(asks, "; ")
			it.Confidence = fmt.Sprintf("%.2f", low)
		case agent.WaitReview:
			it.Title = what + ", which the reviewer refused"
		default:
			it.Title = what
		}
		it.Detail = clipText(firstNonEmpty(w.Why, rec.Goal), 240)
		if agent.Batchable(it.Commits) && w.Kind == agent.WaitAsk && !it.Expired {
			it.Batch = batchKey(rec.Agent, w)
		}
		out = append(out, it)
	}
	return out
}

// otherApprovals are what waits outside agent runs, as far as the person
// looking may decide it.
func (s *Server) otherApprovals(p principal, now time.Time) []approvalItem {
	var out []approvalItem
	admin := s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed
	if s.Policy.Evaluate(p.Name, auth.ActApprove, "/").Allowed && s.Integrations != nil && s.Integrations.Held != nil {
		if held, err := s.Integrations.Held(); err == nil {
			for _, h := range held {
				if h.For == p.Name {
					continue
				}
				out = append(out, approvalItem{Source: "gateway", Agent: firstNonEmpty(h.App, h.Integration),
					Title: h.Tool + " on " + h.Integration, Detail: "for " + h.For + ", held until a second person decides",
					Commits: "acts", Href: "/integrations/held", Since: h.Asked})
			}
		}
	}
	if s.Store != nil {
		if draft := s.Store.GetRef(site.RefDraft); draft != "" && draft != s.Store.GetRef(site.RefLive) {
			if st := s.approvalFor(p, draft); st.Configured && st.Proposed && st.Matches && st.CanApprove && st.Have < st.Need {
				out = append(out, approvalItem{Source: "review", Agent: firstNonEmpty(st.Author, "content"),
					Title: "Approve the change to the site", Commits: "publishes", Href: "/review",
					Detail: fmt.Sprintf("%d of %d approvals; %s", st.Have, st.Need, clipText(st.Message, 160)),
					Since:  now})
			}
		}
	}
	if admin && s.Cases != nil && s.Cases.List != nil {
		if list, err := s.Cases.List(); err == nil {
			for _, inc := range list {
				for _, a := range inc.Acts {
					if a.State != incident.ActRequested || a.Requested.By == p.Name {
						continue
					}
					out = append(out, approvalItem{Source: "case", Agent: "case " + inc.ID,
						Title: a.Title + " on " + a.Target, Detail: "asked by " + a.Requested.By + ": " + clipText(a.Requested.Why, 160),
						Commits: "acts", Href: caseHref(inc.ID), Since: a.Requested.At})
				}
			}
		}
	}
	if s.Memory != nil && s.Memory.Store != nil {
		f := memory.Filter{}
		if !admin {
			f.About = p.Name
		}
		if all, err := s.Memory.Store.List(f); err == nil {
			n, first := 0, now
			for _, e := range all {
				if e.Held && (admin || e.About == p.Name) {
					n++
					if e.Created.Before(first) {
						first = e.Created
					}
				}
			}
			if n > 0 {
				out = append(out, approvalItem{Source: "memory", Agent: "memory",
					Title:   fmt.Sprintf("Confirm or forget %d held %s", n, map[bool]string{true: "memory", false: "memories"}[n == 1]),
					Detail:  "learnt after reading somebody else's words, and not recalled until a person confirms it",
					Commits: "writes", Href: "/memory", Since: first})
			}
		}
	}
	return out
}

// waitingItems is everything waiting that a person may decide, as Approvals
// and Today both list it.
func (s *Server) waitingItems(p principal, now time.Time) []approvalItem {
	var items []approvalItem
	items = append(items, s.runApprovalsFor(p, now)...)
	items = append(items, s.otherApprovals(p, now)...)
	items = append(items, s.featureApprovals(p)...)
	for i := range items {
		items[i].When = agoText(now.Sub(items[i].Since))
	}
	return items
}

// commitsOrder is what deciding commits to, most urgent first: a question
// holds a run up, and paying, deleting and publishing cannot be taken back.
var commitsOrder = []string{"answers", "installs", "pays", "deletes", "publishes", "sends", "writes", "acts", "reads"}

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
		if err := s.Agents.Answer(it.RunID, it.Step, true, nil, p.Name); err != nil {
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
