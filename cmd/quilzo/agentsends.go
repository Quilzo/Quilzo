// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
)

// Sends from runs nobody started.
//
// A run a trigger starts is capped at the author role, so nothing it does
// on the site goes further than a draft or a proposal, and the manual says
// that anything that goes out is still a person's decision. A tool that
// writes to another system was not held by that cap: whether its call
// waited for a person was read from the declaration's ask_first alone, so
// a social post the model chose in a run a page going live had started
// went out as soon as it was chosen, with nobody asked.
//
// So a triggered run's call of a tool that writes waits for a person, as
// asking first does. (Its delegates choose no tools: a model deciding for
// a delegate is offered none.) Administrators may lift the hold for one
// tool of one agent: one proposes it with a reason, a second approves it
// (internal/dual), and the record says what it widened. Lifting it takes
// nothing else away: what the declaration asks first, a payment beyond a
// mandate and the exfiltration breaker still wait for a person.

// viaTrigger is a triggered run's Caller.Via.
const viaTrigger = "trigger"

// unattendedSend is one tool an agent may send through from runs nobody
// started.
type unattendedSend struct {
	Tool string `json:"tool"`
	// Host is where the tool reached when the grant was made. A
	// declaration that points the tool somewhere else afterwards has not
	// been granted that.
	Host string `json:"host"`
	// Why is the reason it was proposed with, By who proposed it, and
	// ApprovedBy who approved it: the same person, Alone, when nobody else
	// administers the store.
	Why        string    `json:"why"`
	By         string    `json:"by"`
	ApprovedBy string    `json:"approved_by"`
	Alone      bool      `json:"alone,omitempty"`
	At         time.Time `json:"at"`
}

// unattendedRun reports whether a run is one nobody started: it reached
// its sponsor some other way than at a keyboard (Caller.Via), as a
// trigger's run does and a visitor's request to a chatbot does, or it is
// such a run taken on after a person answered it. A person who lets one
// step go ahead has decided that step; what the model chooses next was
// chosen with nobody watching, as the step before was.
//
// Only a trigger's run was asked about at first, so the post a visitor's
// request to a chatbot led to went out at once, with a stranger's words
// in the goal, while the same run's next post, taken on after a person
// answered something else, waited.
func unattendedRun(caller *Caller, from *agentResume) bool {
	if caller != nil && caller.Via != "" {
		return true
	}
	return from != nil && from.Prior != nil && from.Prior.Trigger != ""
}

// outwardAsks is why a run's action waits for a person beyond what its
// declaration asks first: then's reason (a payment beyond a mandate); for
// a run nobody started, a write to another system it has not been let
// make unattended; and for any run, a write that says what the brand
// rules hold (outwardClaims). A payment's reason comes first, so the step
// is classed as one that pays (agent.CommitOf).
func outwardAsks(root string, m agent.Manifest, unattended bool, then func(agent.Action) string) func(agent.Action) string {
	return func(a agent.Action) string {
		var why []string
		if then != nil {
			if w := then(a); w != "" {
				why = append(why, w)
			}
		}
		if a.Tool == "" || !stepWrites(root, m, a.Tool) {
			return strings.Join(why, "; and ")
		}
		if host := toolHost(m, a.Tool); unattended && !sendsUnattended(root, m.Name, a.Tool, host) {
			why = append(why, fmt.Sprintf("%s: %s writes to %s, which is a person's decision unless "+
				"administrators let %s send through it unattended", agent.UnattendedPrefix, a.Tool, host, m.Name))
		}
		if c := outwardClaims(root, a.Tool, a.Input); c != "" {
			why = append(why, c)
		}
		return strings.Join(why, "; and ")
	}
}

// toolHost is the host a manifest says a tool reaches.
func toolHost(m agent.Manifest, tool string) string {
	for _, t := range m.Tools {
		if strings.EqualFold(strings.TrimSpace(t.Name), strings.TrimSpace(tool)) {
			return strings.ToLower(strings.TrimSpace(t.Host))
		}
	}
	return ""
}

// sendsUnattended reports whether administrators let an agent send through
// a tool, at the host it reaches now, from runs nobody started. Read at
// each call, so a grant taken back holds the next one.
func sendsUnattended(root, name, tool, host string) bool {
	set, err := loadAgents(root)
	if err != nil || host == "" {
		return false
	}
	return slices.ContainsFunc(set.Sends[name], func(g unattendedSend) bool {
		return strings.EqualFold(g.Tool, tool) && g.Host == host
	})
}

// agentSendsCmd is `quilzo agent sends NAME [grant TOOL --why REASON |
// revoke TOOL]`.
func agentSendsCmd(root string, args []string) error {
	return agentSendsCmdAs(root, args, resolveCaller(root, flagToken))
}

const sendsUsage = "quilzo agent sends NAME [grant TOOL --why REASON | revoke TOOL]"

// agentSendsCmdAs is agentSendsCmd for a caller already known.
func agentSendsCmdAs(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("agent sends", flag.ContinueOnError)
	why := fs.String("why", "", "why it should send through the tool with nobody deciding each call")
	args, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(args) != 1 && len(args) != 3 {
		return errors.New(sendsUsage)
	}
	name := args[0]
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %s is declared", name)
	}
	if len(args) == 1 {
		return listSends(name, set.Sends[name])
	}
	verb, tool := args[1], strings.TrimSpace(args[2])
	if verb != "grant" && verb != "revoke" {
		return errors.New(sendsUsage)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("what an agent sends with nobody asked is a person's decision. A model that " +
			"could make it could let itself post anything")
	}
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return fmt.Errorf("what an agent sends from runs nobody started is an administrator's decision: %w", err)
	}
	if verb == "revoke" {
		return revokeSends(root, name, tool, caller)
	}
	host := toolHost(m, tool)
	switch {
	case host == "":
		return fmt.Errorf("%s declares no tool called %s", name, tool)
	case !stepWrites(root, m, tool):
		return fmt.Errorf("%s does not write to another system, so its calls from runs nobody started do "+
			"not wait for a person and there is nothing to grant", tool)
	case strings.TrimSpace(*why) == "":
		return fmt.Errorf("say why %s should send through %s with nobody deciding each call: --why REASON. "+
			"It is the reason the second administrator reads", name, tool)
	case sendsUnattended(root, name, tool, host):
		return fmt.Errorf("%s already sends through %s to %s unattended", name, tool, host)
	}
	ch := dual.SendsChange{Agent: name, Tool: tool, Host: host}
	apply, err := proposeSecond(root, caller, dual.Sends, sendsWhat(ch), ch, *why)
	if err != nil || !apply {
		return err
	}
	if err := grantSends(root, ch, *why, caller.Name, caller.Name, true, caller); err != nil {
		return err
	}
	w.Human("%s sends through %s to %s from runs nobody started; what it asks first still waits\n",
		name, tool, host)
	return nil
}

// sendsWhat is a Sends request in the words the second administrator
// reads, and the widening the record keeps.
func sendsWhat(ch dual.SendsChange) string {
	return fmt.Sprintf("let %s send through %s to %s from runs nobody started, with nobody deciding each call",
		ch.Agent, ch.Tool, ch.Host)
}

// grantSends makes an approved Sends request: by proposed it and approver
// approved it, the same person when alone. Recorded as the widening it is,
// in the words a declaration's widening is recorded in.
func grantSends(root string, ch dual.SendsChange, why, by, approver string, alone bool, caller *Caller) error {
	if err := updateAgents(root, func(set *agentSet) error {
		if _, ok := set.Agents[ch.Agent]; !ok {
			return fmt.Errorf("no agent called %s is declared", ch.Agent)
		}
		if set.Sends == nil {
			set.Sends = map[string][]unattendedSend{}
		}
		kept := slices.DeleteFunc(set.Sends[ch.Agent], func(g unattendedSend) bool {
			return strings.EqualFold(g.Tool, ch.Tool)
		})
		set.Sends[ch.Agent] = append(kept, unattendedSend{Tool: ch.Tool, Host: ch.Host, Why: strings.TrimSpace(why),
			By: by, ApprovedBy: approver, Alone: alone, At: time.Now().UTC()})
		return nil
	}); err != nil {
		return err
	}
	detail := map[string]string{"agent": ch.Agent, "tool": ch.Tool, "proposed_by": by, "approved_by": approver,
		"widened": "sends through " + ch.Tool + " to " + ch.Host + " from runs nobody started, with nobody deciding each call"}
	if alone {
		detail["alone"] = "true"
	}
	return recordE(root, caller.auditRecord("agent.changed", "/", audit.Success, detail))
}

// revokeSends takes a grant back, at once: narrowing waits for nobody.
func revokeSends(root, name, tool string, caller *Caller) error {
	found := false
	if err := updateAgents(root, func(set *agentSet) error {
		before := len(set.Sends[name])
		set.Sends[name] = slices.DeleteFunc(set.Sends[name], func(g unattendedSend) bool {
			return strings.EqualFold(g.Tool, tool)
		})
		found = len(set.Sends[name]) < before
		if len(set.Sends[name]) == 0 {
			delete(set.Sends, name)
		}
		return nil
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s does not send through %s unattended", name, tool)
	}
	if err := recordE(root, caller.auditRecord("agent.changed", "/", audit.Success, map[string]string{
		"agent": name, "tool": tool, "narrowed": "no longer sends through " + tool + " from runs nobody started"})); err != nil {
		return err
	}
	w.Human("%s's calls of %s from runs nobody started wait for a person again\n", name, tool)
	return nil
}

func listSends(name string, grants []unattendedSend) error {
	if w.JSON(map[string]any{"agent": name, "sends": grants}) {
		return nil
	}
	if len(grants) == 0 {
		w.Human("%s sends nothing from runs nobody started without a person deciding each call\n", name)
		return nil
	}
	for _, g := range grants {
		alone := ""
		if g.Alone {
			alone = ", alone"
		}
		w.Human("%s%s%s to %s  %sgranted by %s, approved by %s%s on %s: %s%s\n", bold, g.Tool, reset, g.Host, dim,
			g.By, g.ApprovedBy, alone, g.At.Format("2 Jan 2006"), g.Why, reset)
	}
	return nil
}
