// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentmodel"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// Agents as principals: who answers for each, until when it may run, and
// what the access policy grants it of its own. See internal/agent/identity.go.

// hasStanding reports whether somebody can still act here: the access
// policy grants them something, and nothing (an identity provider's
// suspension, an administrator's deny) refuses it. With no policy in use
// nothing is enforced, so nothing is refused here either. An agent's
// sponsor and a person who connected an app are both asked this.
func hasStanding(root, who string) bool {
	inUse, err := policyInUse(root)
	if err != nil {
		return false
	}
	if !inUse {
		return true
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return false
	}
	for _, b := range pol.Snapshot() {
		if b.Principal == who && !b.Deny && pol.Evaluate(who, auth.ActView, b.Resource).Allowed {
			return true
		}
	}
	return false
}

// roleOrder is the roles from the most to the least, with the action that
// proves each.
var roleOrder = []struct {
	role auth.Role
	act  auth.Action
}{
	{auth.RoleAdmin, auth.ActGrant}, {auth.RolePublisher, auth.ActPublish},
	{auth.RoleAuthor, auth.ActEditDraft}, {auth.RoleReader, auth.ActView},
}

// agentGrants is an agent's own standing in the access policy, as a caller
// that bounds its runs: nil when the policy says nothing about it. An agent
// the policy names and refuses everywhere does not run at all.
func agentGrants(root, name string) (*Caller, error) {
	pol, err := loadPolicy(root)
	if err != nil || pol == nil {
		return nil, nil
	}
	principal := agent.Principal(name)
	var mine []auth.Binding
	for _, b := range pol.Snapshot() {
		if b.Principal == principal {
			mine = append(mine, b)
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	c := &Caller{Name: principal, Kind: audit.KindAI, Verified: true, Scope: "/"}
	for _, r := range roleOrder {
		if pol.Evaluate(principal, r.act, "/").Allowed {
			c.Role = r.role
			return c, nil
		}
	}
	// Granted somewhere below the root: bounded to that subtree, when it is
	// one. Several subtrees are not something a run can be bounded to, and
	// running it as if it had the whole site would be the wrong direction.
	var allowed []auth.Binding
	for _, b := range mine {
		if !b.Deny && pol.Evaluate(principal, auth.ActView, b.Resource).Allowed {
			allowed = append(allowed, b)
		}
	}
	switch len(allowed) {
	case 0:
		return nil, fmt.Errorf("the access policy refuses %s everything", principal)
	case 1:
		c.Role, c.Scope = allowed[0].Role, allowed[0].Resource
		return c, nil
	}
	return nil, fmt.Errorf("%s is granted roles on %d separate parts of the site; a run is bounded to one, so grant it one subtree", principal, len(allowed))
}

// agentIdentityCmd is `quilzo agent sponsor NAME PERSON` and `quilzo agent
// renew NAME`.
func agentIdentityCmd(root, verb string, args []string) error {
	fs := flag.NewFlagSet("agent "+verb, flag.ContinueOnError)
	lifetime := fs.Duration("for", agent.DefaultLifetime, "how long until somebody has to renew it again")
	want := 1
	if verb == "sponsor" {
		want = 2
	}
	if len(args) < want {
		if verb == "sponsor" {
			return errors.New("quilzo agent sponsor NAME PERSON [--for 2160h]")
		}
		return errors.New("quilzo agent renew NAME [--for 2160h]")
	}
	if err := fs.Parse(args[want:]); err != nil {
		return err
	}
	name := args[0]
	caller := resolveCaller(root, flagToken)
	if caller.Kind == audit.KindAI {
		return errors.New("who answers for an agent is a person's decision")
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	if _, ok := set.Agents[name]; !ok {
		return fmt.Errorf("no agent called %s is declared", name)
	}
	now := time.Now()
	cur := set.identityOf(name)
	var id agent.Identity
	detail := map[string]string{"agent": name}
	switch verb {
	case "sponsor":
		// Naming who answers for an agent is an administrator's: nobody
		// makes somebody else accountable for a thing by themselves.
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		person := args[1]
		if !hasStanding(root, person) {
			return fmt.Errorf("%s has no access here, so cannot answer for an agent", person)
		}
		id, err = agent.NewIdentity(person, caller.Name, *lifetime, now)
		if cur != nil {
			id.Created, id.CreatedBy = cur.Created, cur.CreatedBy
			id.Renewed, id.RenewedBy = now, caller.Name
		}
		detail["sponsor"] = person
	case "renew":
		if cur == nil {
			return fmt.Errorf("%s has no sponsor yet: quilzo agent sponsor %s PERSON", name, name)
		}
		// Its sponsor renews it, or an administrator.
		if caller.Name != cur.Sponsor || !caller.Verified {
			if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
				return fmt.Errorf("%s is renewed by its sponsor, %s, or an administrator: %w", name, cur.Sponsor, err)
			}
		}
		id, err = cur.Renew(caller.Name, *lifetime, now)
		detail["sponsor"] = cur.Sponsor
	}
	if err != nil {
		return err
	}
	set.Identities[name] = id
	if err := saveJSON(agentsPath(root), set); err != nil {
		return err
	}
	detail["until"] = id.Expires.UTC().Format(time.RFC3339)
	if err := recordE(root, caller.auditRecord("agent."+verb, "/", audit.Success, detail)); err != nil {
		return err
	}
	fmt.Printf("%s is answered for by %s until %s\n", name, id.Sponsor, id.Expires.UTC().Format("2 January 2006"))
	return nil
}

// modelChoices are the tools and delegates a model may choose in a run:
// the manifest's tools whose definition a person pinned and the server
// still gives as pinned, and the manifest's delegates, each described by
// what the operator wrote about it.
func modelChoices(ctx context.Context, root string, m agent.Manifest, set *agentSet) ([]agentmodel.ToolChoice, []agentmodel.DelegateChoice) {
	var tools []agentmodel.ToolChoice
	if len(m.Tools) > 0 {
		if installed, err := loadIntegrations(root); err == nil && installed != nil {
			client := newMCPClient(root)
			for _, t := range m.Tools {
				in, err := installed.Resolve(t.Name)
				if err != nil || in.Pins[t.Name] == "" {
					continue
				}
				tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defs, err := client.Definitions(tctx, in)
				cancel()
				if err != nil {
					continue
				}
				for _, d := range defs {
					if d.Name == t.Name && d.Allowed && d.Matches() {
						tools = append(tools, agentmodel.ToolChoice{Name: t.Name, Purpose: t.Purpose, Args: d.Args()})
					}
				}
			}
		}
	}
	var delegates []agentmodel.DelegateChoice
	for _, name := range m.Delegates {
		if d, ok := set.Agents[name]; ok {
			delegates = append(delegates, agentmodel.DelegateChoice{Name: name, Purpose: d.Purpose})
		}
	}
	return tools, delegates
}
