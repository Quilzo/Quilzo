// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
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
func mayApprove(root string, caller *Caller, rec agent.Record) error {
	if caller.Kind == audit.KindAI {
		return errors.New("a person answers what an agent asks. A model that could would be approving itself")
	}
	if set, err := loadAgents(root); err == nil {
		if id := set.identityOf(rec.Agent); id != nil && caller.Verified && id.Sponsor == caller.Name {
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
