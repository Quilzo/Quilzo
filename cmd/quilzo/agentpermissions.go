// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Who decides what an agent waits for. See internal/auth/permission.go.
//
// An agent waits for a person before an action its declaration says to ask
// about, and that person used to be any administrator and only an
// administrator. Approval now follows ownership, as it does in the identity
// providers that govern agents: the person who answers for the agent (its
// sponsor) decides, as does anybody granted the approve permission on the
// agent, or on the page the action would change. A model never decides, and
// nobody decides for a run whose permission they do not hold because they
// hold a role somewhere else.

// mayApprove says whether a caller may decide what a run waits for.
//
// The session decides, not the person: a credential that is read-only
// decides nothing, and every other limit it carries (its role, the part of
// the site it is confined to) caps sponsorship and the approve permission
// alike, as auth.CheckGranted caps a permission granted on its own.
func mayApprove(root string, caller *Caller, rec agent.Record) error {
	if caller.Kind == audit.KindAI {
		return errors.New("a person answers what an agent asks. A model that could would be approving itself")
	}
	if caller.Limits.ReadOnly {
		return errors.New("this credential is read-only, and deciding what an agent waits for decides what " +
			"happens next")
	}
	if set, err := loadAgents(root); err == nil {
		if id := set.identityOf(rec.Agent); id != nil && caller.Verified && id.Sponsor == caller.Name &&
			sponsorReaches(caller, rec.Agent) {
			return nil
		}
	}
	err := authorise(root, caller, auth.ActApprove, auth.AgentResource(rec.Agent))
	if err == nil {
		return nil
	}
	if page := waitingPage(rec); page != "" && authorise(root, caller, auth.ActApprove, pageResource(page)) == nil {
		return nil
	}
	return fmt.Errorf("deciding what %s waits for takes being its sponsor, or the approve permission on "+
		"%s or on what it would change: %w", rec.Agent, auth.AgentResource(rec.Agent), err)
}

// sponsorReaches says whether a sponsor's credential reaches the agent.
//
// Answering for an agent is a right over that one agent, like the approve
// permission granted on it, so it is capped the same way: by the part of
// the site the credential is confined to and by its limits, and not by its
// role, which for a sponsor who is a reader is reader by nature.
func sponsorReaches(caller *Caller, agentName string) bool {
	if !caller.Role.Valid() {
		return false
	}
	return auth.CheckCredential(auth.RoleAdmin, caller.Scope, caller.Limits, auth.ActApprove,
		auth.AgentResource(agentName)) == nil
}

// A second person for what a run commits to.
//
// The person who starts a run and the person who lets its riskiest steps go
// ahead used to be allowed to be the same, so asking first could become
// asking yourself (NIST SP 800-53 AC-5). Now a step that pays, publishes,
// deletes, sends or writes to another system is let go ahead by somebody
// other than whoever started the run, whenever such a person exists. When
// nobody else could decide it, which is every installation run by one
// person, the starter still may: the approval is recorded as made alone,
// and posture says how many were, so the gap is a known one rather than a
// silent one. Declining is never refused, and nor is answering a question.

// riskyStep is the class of what a run waits for, and whether a second
// person should see it.
func riskyStep(root string, rec agent.Record) (string, bool) {
	w := rec.Trace.Waiting
	if w == nil || w.Kind == agent.WaitQuestion {
		return "", false
	}
	writes := false
	if set, err := loadAgents(root); err == nil {
		if m, ok := set.Agents[rec.Agent]; ok {
			for _, t := range m.Tools {
				writes = writes || (t.Name == w.Action.Tool && t.Writes)
			}
		}
	}
	class := agent.CommitOf(w.Action, w.Why, w.Kind, writes)
	switch class {
	case "pays", "publishes", "deletes", "sends":
		return class, true
	case "writes":
		// A tool's write lands in another system; a page or a workspace
		// file is a draft, which publishing gates separately.
		return class, w.Action.Tool != ""
	}
	return class, false
}

// secondPerson decides whether caller may let a run's waiting step go
// ahead given who started it, and whether they would be doing it alone.
func secondPerson(root string, caller *Caller, rec agent.Record) (alone bool, err error) {
	if !strings.EqualFold(rec.By, caller.Name) {
		return false, nil
	}
	class, risky := riskyStep(root, rec)
	if !risky {
		return false, nil
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return false, err
	}
	sponsor := ""
	if set, err := loadAgents(root); err == nil {
		if id := set.identityOf(rec.Agent); id != nil {
			sponsor = id.Sponsor
		}
	}
	page := waitingPage(rec)
	others := othersWho(root, pol, func(name string) bool {
		if name == sponsor && pol.Evaluate(name, auth.ActView, "/").Allowed {
			return true
		}
		if pol.Evaluate(name, auth.ActApprove, auth.AgentResource(rec.Agent)).Allowed {
			return true
		}
		return page != "" && pol.Evaluate(name, auth.ActApprove, pageResource(page)).Allowed
	}, caller.Name)
	if len(others) == 0 {
		return true, nil
	}
	return false, fmt.Errorf("you started this run, so a step that %s goes ahead when somebody else lets it: %s",
		class, nameSome(others))
}

// othersWho are the people, other than those excluded, who may do
// something by the policy as it stands. Agents and services are not
// people, so they are never the second person.
func othersWho(root string, pol *auth.Policy, may func(string) bool, exclude ...string) []string {
	var out []string
	for _, name := range pol.Principals() {
		if strings.HasPrefix(name, "agent/") || principalKind(root, name) != "human" {
			continue
		}
		excluded := false
		for _, x := range exclude {
			excluded = excluded || strings.EqualFold(x, name)
		}
		if !excluded && may(name) {
			out = append(out, name)
		}
	}
	return out
}

// nameSome names a few people, and says how many more there are.
func nameSome(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:3], ", "), len(names)-3)
}

// draftStarters are the people whose agent runs wrote pages in the draft
// as it stands, read from the provenance each agent write leaves.
func draftStarters(root string, s *store.Store) []string {
	idx, err := loadProvenance(root)
	if err != nil {
		return nil
	}
	ids, err := site.PageIDsAt(s, site.RefDraft)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for page, id := range ids {
		rec, ok := idx.Get(page)
		if !ok || rec.ContentHash != id || rec.SourceType == provenance.HumanEdits || rec.SourceType == "" ||
			rec.Author == "" || seen[rec.Author] {
			continue
		}
		seen[rec.Author] = true
		out = append(out, rec.Author)
	}
	sort.Strings(out)
	return out
}

// secondPersonForDraft is the same rule for a draft a model wrote: the
// person whose run wrote it approves it only when nobody else may publish.
func secondPersonForDraft(root string, s *store.Store, prop collab.Proposal, by string) (alone bool, err error) {
	if prop.AuthorKind != "ai" {
		return false, nil
	}
	starters := draftStarters(root, s)
	mine := false
	for _, st := range starters {
		mine = mine || strings.EqualFold(st, by)
	}
	if !mine {
		return false, nil
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return false, err
	}
	others := othersWho(root, pol, func(name string) bool {
		return pol.Evaluate(name, auth.ActPublish, "/").Allowed
	}, append(starters, by)...)
	if len(others) == 0 {
		return true, nil
	}
	return false, fmt.Errorf("an agent run you started wrote this draft, so somebody else approves it: %s",
		nameSome(others))
}

// waitingPage is the page a run's waiting action would change, when it is
// a change to a page.
func waitingPage(rec agent.Record) string {
	w := rec.Trace.Waiting
	if w == nil || (w.Action.Op != "write_page" && w.Action.Op != "publish") {
		return ""
	}
	if v, ok := w.Action.Input["page"].(string); ok {
		return v
	}
	if v, ok := w.Action.Input["name"].(string); ok {
		return v
	}
	return ""
}

// manageAgent checks the permission to change one agent.
func manageAgent(root string, caller *Caller, name string) error {
	return authorise(root, caller, auth.ActManageAgents, auth.AgentResource(name))
}
