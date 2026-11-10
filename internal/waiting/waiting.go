// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package waiting is the one list of what waits for a person to decide:
// what agents are waiting on, tool calls held for a second person, an
// install or a feature an agent drafted, the change to the site waiting
// for approvals, a newsletter issue an agent proposed, and memories held
// until somebody confirms them.
//
// It was written twice, once for `quilzo approvals` and once for the
// admin's Approvals and Today, and the two drifted. A question asked too
// long ago to agree to was dropped from the command line and shown on the
// screen. The screen asked whether the person might decide what waited
// outside agent runs, and not whether the session might, so a read-only
// credential, or one confined to /blog or capped at reader, was offered a
// held call, an install, a newsletter issue and the review, and was
// refused each when it tried. The command line offered the review to
// anybody who could edit the draft, though approving it takes the publish
// permission. The same thing had a different name on each, and the review
// said it had waited since the moment the screen was opened.
//
// So the rules are here, once: which permission each source takes, asked
// of the session through Sources.May; that a read-only credential decides
// nothing; what each item is called and why it waits; when it is too old to
// agree to; and which runs may be let go ahead together. A surface says
// only where the records are and how to ask about the session in front of
// it. The command line is one such surface, and the admin, as `quilzo
// serve` builds it, reads the command line's list through a hook, so the
// two are the same list and not two that agree.
package waiting

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/newsletter"
)

// Item is one thing waiting for a person to decide.
//
// The JSON is what `quilzo approvals --json` has always printed (source,
// agent, what, why, commits, since, decide); the keys added with the one
// list are left out when empty, so a script reading the old keys reads
// the same thing.
type Item struct {
	// Source is where it waits: run, gateway, feature, review, newsletter
	// or memory.
	Source string `json:"source"`
	// Kind is what sort of wait a run's item is (agent.WaitAsk and the
	// rest); empty for the other sources.
	Kind string `json:"kind,omitempty"`
	// ID is the waiting thing's own identifier where it has one: the held
	// call, the install request, the proposal, the memory.
	ID    string `json:"id,omitempty"`
	Agent string `json:"agent,omitempty"`
	What  string `json:"what"`
	Why   string `json:"why,omitempty"`
	// Commits is what deciding commits to, in CommitsOrder's words.
	Commits string    `json:"commits"`
	Since   time.Time `json:"since"`
	// Decide is the command that decides it, and Href the admin page that
	// does.
	Decide string `json:"decide"`
	Href   string `json:"href,omitempty"`
	// For a run: which run and step, whether it waits in its own process,
	// whether it was asked too long ago to agree to, and how sure the
	// agent was of a question it asked.
	RunID      string `json:"run,omitempty"`
	Step       int    `json:"step,omitempty"`
	Live       bool   `json:"live,omitempty"`
	Expired    bool   `json:"expired,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	// Batch is what makes two waiting actions the same, for letting
	// several go ahead together on the screen; empty for anything that is
	// decided one at a time.
	Batch string `json:"-"`
}

// CommitsOrder is what deciding commits to, most urgent first: a question
// holds a run up, and paying, deleting and publishing cannot be taken back.
var CommitsOrder = []string{"answers", "installs", "pays", "deletes", "publishes", "sends", "writes", "acts", "reads"}

// BatchKey is what makes two waiting actions the same: the agent, the
// action with its input, and the reason it waits.
func BatchKey(agentName string, w *agent.Pending) string {
	in, _ := json.Marshal(w.Action.Input)
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", agentName, w.Kind, w.Action.Op, w.Action.Tool, in, w.Why)
}

// Held is a tool call held at the gateway until a second person decides.
type Held struct {
	ID, Integration, Tool string
	// For is whose call it is, and App the app that made it, when one did.
	For, App string
	Asked    time.Time
}

// Proposal is a feature an agent drafted for a person to read and install.
type Proposal struct {
	ID, By, Title, Version, What, For string
	At                                time.Time
}

// Review is the change to the site waiting for approvals: the proposal for
// the draft as it stands, under the policy that says how many must agree
// and who counts as a person.
type Review struct {
	Policy   collab.Policy
	Proposal collab.Proposal
	KindOf   collab.KindOf
}

// Sources is where a surface keeps what waits, and how it asks about the
// session in front of it. A nil source has nothing waiting.
type Sources struct {
	// Name is who is looking.
	Name string
	// ReadOnly is a credential issued read-only. It decides nothing, so it
	// is offered nothing to decide: every decision here changes something.
	ReadOnly bool
	// May asks whether this session, with its own role cap, path and
	// limits, may take the action. Not whether the person may: the person
	// holding a right somewhere is not the credential in hand holding it.
	May func(act auth.Action, resource string) bool
	// Runs are the agent runs; MayDecide says whether this session may
	// decide what one waits for, which turns on more than a role (its
	// sponsor, approve on the agent or on what it would change); Writes
	// says whether a tool's step writes, as the manifest and the
	// integration offering it say.
	Runs      func() ([]agent.Record, error)
	MayDecide func(agent.Record) bool
	Writes    func(rec agent.Record, tool string) bool
	Held      func() ([]Held, error)
	Pending   func() ([]feature.Pending, error)
	Proposals func() ([]Proposal, error)
	// Review is nil, with no error, when nothing waits for review: the
	// draft is what is live, or there is no proposal for it.
	Review   func() (*Review, error)
	Issues   func() ([]newsletter.Issue, error)
	Memories func(memory.Filter) ([]memory.Entry, error)
}

func (src Sources) may(act auth.Action, resource string) bool {
	return src.May != nil && src.May(act, resource)
}

// List is everything waiting that the session may decide, oldest first.
//
// A source that cannot be read leaves its items out and does not hide the
// rest. The error says which of runs or held calls could not be read, the
// two the command line has always refused to list without; whatever else
// fails to read has nothing listed from it, as before.
func List(src Sources, now time.Time) ([]Item, error) {
	if src.ReadOnly {
		return nil, nil
	}
	var out []Item
	var errs []error
	if src.Runs != nil {
		items, err := runItems(src, now)
		out = append(out, items...)
		errs = append(errs, err)
	}
	// A held tool call through the gateway is decided by whoever holds
	// approve over the store, but never by whoever it was held for.
	if src.Held != nil && src.may(auth.ActApprove, "/") {
		held, err := src.Held()
		errs = append(errs, err)
		for _, h := range held {
			if h.For == src.Name {
				continue
			}
			out = append(out, Item{Source: "gateway", ID: h.ID, Agent: firstNonEmpty(h.App, h.Integration),
				What: h.Tool + " on " + h.Integration, Why: "for " + h.For + ", held until a second person decides",
				Commits: "acts", Since: h.Asked, Href: "/integrations/held",
				Decide: "quilzo integrations approve " + h.ID})
		}
	}
	// An install waiting for a second person, and what agents drafted for
	// a person to read and install, for whoever may install one. The
	// person who asked for an install is not its second person.
	if src.may(auth.ActInstall, "/") {
		if src.Pending != nil {
			if pend, err := src.Pending(); err == nil {
				for _, p := range pend {
					if strings.EqualFold(p.RequestedBy, src.Name) {
						continue
					}
					title := firstNonEmpty(p.Card.Title, p.Name)
					what := "Install " + title + " " + p.Version
					if p.Rollback {
						what = "Roll " + title + " back to " + p.Version
					}
					out = append(out, Item{Source: "feature", ID: p.ID, Agent: "feature " + p.Name, What: what,
						Why:     "risk " + p.Card.Risk + ": " + strings.Join(p.Card.Because, "; ") + "; asked by " + p.RequestedBy,
						Commits: "installs", Since: p.At, Href: "/make", Decide: "quilzo feature approve " + p.ID})
				}
			}
		}
		if src.Proposals != nil {
			if list, err := src.Proposals(); err == nil {
				for _, pr := range list {
					out = append(out, Item{Source: "feature", ID: pr.ID, Agent: pr.By, What: "Read " + pr.Title + " " + pr.Version,
						Why:     pr.What + ", proposed by an agent for " + pr.For + "; nothing is installed until you install it",
						Commits: "installs", Since: pr.At, Href: "/make/proposal?id=" + pr.ID, Decide: "quilzo feature proposals"})
				}
			}
		}
	}
	// The change to the site waiting for approvals, for whoever may give
	// one. An approval counts towards publishing, so it takes what
	// publishing takes: offering it to anybody who could edit the draft
	// offered it to people `quilzo review approve` then refused.
	if src.Review != nil && src.may(auth.ActPublish, "/") {
		if r, err := src.Review(); err == nil && r != nil {
			if it, ok := reviewItem(*r, src.Name, now); ok {
				out = append(out, it)
			}
		}
	}
	// A newsletter issue an agent proposed, for whoever may send it. It
	// was on the Newsletter screen and nowhere a person looks for what is
	// waiting on them.
	if src.Issues != nil && src.may(auth.ActPublish, "/") {
		if issues, err := src.Issues(); err == nil {
			for _, is := range issues {
				if is.State != newsletter.Proposed {
					continue
				}
				out = append(out, Item{Source: "newsletter", ID: is.Page, Agent: firstNonEmpty(is.By, "newsletter"),
					What:    "Send the issue “" + is.Subject + "”",
					Why:     firstNonEmpty(is.Note, "proposed from the page "+is.Page) + "; nothing is sent until a person sends it",
					Commits: "sends", Since: is.Proposed, Href: "/newsletter",
					Decide: "quilzo newsletter send " + is.Page + " --yes"})
			}
		}
	}
	// A memory held until somebody confirms it: one about the person
	// looking, or anybody's for an administrator, one item each. The
	// screen gathers them into one row (internal/admin); the command line
	// gives each its own line, because each is confirmed by its own ID.
	if src.Memories != nil {
		admin := src.may(auth.ActGrant, "/")
		f := memory.Filter{}
		if !admin {
			f.About = src.Name
		}
		if all, err := src.Memories(f); err == nil {
			for _, e := range all {
				if e.Held && (admin || e.About == src.Name) {
					out = append(out, Item{Source: "memory", ID: e.ID, Agent: e.Agent,
						What:    "Confirm or forget the memory " + e.ID,
						Why:     "learnt after reading somebody else's words, and not recalled until a person confirms it",
						Commits: "writes", Since: e.Created, Href: "/memory", Decide: "quilzo memory confirm " + e.ID})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out, errors.Join(errs...)
}

// runItems is what runs wait for that the session may decide.
//
// A question asked too long ago to agree to is listed, and marked: it still
// holds its run up, and the command line used to leave it out, so a run
// waited unseen there while the screen showed it.
func runItems(src Sources, now time.Time) ([]Item, error) {
	runs, err := src.Runs()
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, rec := range runs {
		w := rec.Trace.Waiting
		if w == nil || rec.Eval != "" {
			continue
		}
		// One waiting in its own process is listed while that process is
		// alive to take the answer.
		if w.Live && (rec.State != agent.Running || now.Sub(rec.Beat) > agent.StaleAfter) {
			continue
		}
		if src.MayDecide == nil || !src.MayDecide(rec) {
			continue
		}
		writes := src.Writes != nil && src.Writes(rec, w.Action.Tool)
		it := Item{Source: "run", Kind: w.Kind, Agent: rec.Agent, RunID: rec.ID, Step: w.N,
			Since: w.Since, Live: w.Live, Href: "/agents/run/" + rec.ID,
			Expired: now.Sub(w.Since) > agent.PendingTTL,
			Commits: agent.CommitOf(w.Action, w.Why, w.Kind, writes),
			Why:     clip(firstNonEmpty(w.Why, rec.Goal), 240),
			Decide:  fmt.Sprintf("quilzo agent approve %s %d", rec.ID, w.N)}
		what := w.Action.Name()
		switch w.Kind {
		case agent.WaitQuestion:
			var asks, names []string
			low := 1.0
			for _, q := range w.Questions {
				asks = append(asks, q.Ask)
				names = append(names, q.Name+"=…")
				low = min(low, q.Confidence)
			}
			it.What = "Answer: " + strings.Join(asks, "; ")
			it.Confidence = fmt.Sprintf("%.2f", low)
			it.Decide = fmt.Sprintf("quilzo agent answer %s %d %s", rec.ID, w.N, strings.Join(names, " "))
		case agent.WaitReview:
			it.What = what + ", which the reviewer refused"
		default:
			it.What = what
		}
		// Several runs may be let go ahead together only on the same
		// action that merely reads or acts, asked first and still fresh.
		if agent.Batchable(it.Commits) && w.Kind == agent.WaitAsk && !it.Expired {
			it.Batch = BatchKey(rec.Agent, w)
		}
		out = append(out, it)
	}
	return out, nil
}

// reviewItem is the change waiting for approvals, when name may still give
// one: never its author or whoever else asked for it (collab.Policy.
// Requested), nor somebody who already has, and only while the policy is
// not yet met.
func reviewItem(r Review, name string, now time.Time) (Item, bool) {
	prop := r.Proposal
	if r.Policy.Requested(prop, name) {
		return Item{}, false
	}
	for _, a := range prop.Approvals {
		if a.Content == prop.Content && a.By == name {
			return Item{}, false
		}
	}
	d := r.Policy.Evaluate(prop, r.KindOf, now)
	if d.Allowed {
		return Item{}, false
	}
	// Said as a number of approvals even when only the rule about a model's
	// work applies, so it does not read "0 of 0 approvals" beside a
	// refusal.
	need := max(r.Policy.Required, r.Policy.RequiredHumans, 1)
	// Since it was proposed, not since somebody looked.
	since := now
	if prop.CreatedAt > 0 {
		since = time.Unix(prop.CreatedAt, 0).UTC()
	}
	return Item{Source: "review", Agent: firstNonEmpty(prop.Author, "content"),
		What:    "Approve the change to the site",
		Why:     fmt.Sprintf("%d of %d approvals; %s", d.Have, need, clip(prop.Message, 160)),
		Commits: "publishes", Since: since, Href: "/review", Decide: "quilzo review approve"}, true
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// clip shortens s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n-len("…")]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}
