// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// Could an agent do something, and why: answered by the code that decides
// it when the agent runs. The declaration is bounded by boundManifest, as
// a run's is, and then the session's own gates are asked: Check for a
// capability, Retrieve or Mutate for a page, MayCallTool for a tool,
// MayReach for a host. Nothing here restates a rule, so nothing here can
// disagree with what a run does. What it adds is the reasons in order, and
// what will happen on the way: a person asked first, the exfiltration
// breaker, the budget.

// couldAnswer is the answer.
type couldAnswer struct {
	Agent   string      `json:"agent"`
	What    string      `json:"what"`
	As      string      `json:"as"`
	Decider string      `json:"decided_by"`
	Could   bool        `json:"could"`
	Why     string      `json:"why,omitempty"`
	Bounded []narrowing `json:"bounded_by,omitempty"`
	// Then are what happens on the way when it can: a person asked, a
	// person deciding before anything goes live.
	Then []string `json:"then,omitempty"`
	// Spent is today's spending against the agent's budget, when it has one.
	Spent string `json:"spent,omitempty"`
}

// callerFor is how a person stands in the access policy, as a caller a
// run is bounded by: their broadest role, or the one subtree they hold.
func callerFor(root, person string) (*Caller, error) {
	pol, err := loadPolicy(root)
	if err != nil {
		return nil, err
	}
	c := &Caller{Name: person, Kind: audit.KindHuman, Verified: true, Scope: "/"}
	if pol == nil {
		c.Role = auth.RoleAdmin
		return c, nil
	}
	for _, r := range roleOrder {
		if pol.Evaluate(person, r.act, "/").Allowed {
			c.Role = r.role
			return c, nil
		}
	}
	for _, b := range pol.Snapshot() {
		if b.Principal == person && !b.Deny && pol.Evaluate(person, auth.ActView, b.Resource).Allowed {
			c.Role, c.Scope = b.Role, b.Resource
			return c, nil
		}
	}
	return nil, fmt.Errorf("%s holds nothing here, so no run they started could do anything", person)
}

// could answers for one agent, one decider, one thing.
func could(root, name, what, page string, withModel, program bool, caller *Caller) (couldAnswer, error) {
	a := couldAnswer{Agent: name, What: what, As: caller.Name, Decider: "walking its declaration"}
	switch {
	case withModel:
		a.Decider = "a model"
	case program:
		a.Decider = "its program"
	}
	set, err := loadAgents(root)
	if err != nil {
		return a, err
	}
	decl, ok := set.Agents[name]
	if !ok {
		return a, fmt.Errorf("no agent called %q", name)
	}
	if program && decl.Program == nil {
		a.Why = name + " declares no program"
		return a, nil
	}
	m, trail, err := boundManifest(root, set, name, withModel, false, caller)
	a.Bounded = trail
	if err != nil {
		a.Why = err.Error()
		return a, nil
	}
	s := agent.NewSession(m, nil)
	if program {
		s.DecidedBy(decl.Program.Command[0])
	}
	unpublished := m.Retrieval.Ref != "" && !strings.EqualFold(m.Retrieval.Ref, "live")

	switch {
	case strings.HasPrefix(what, "tool:"):
		tool := strings.TrimPrefix(what, "tool:")
		if err := s.MayCallTool(tool, ""); err != nil {
			a.Why = err.Error()
			return a, nil
		}
		if installed, err := loadIntegrations(root); err == nil && installed != nil {
			in, err := installed.Resolve(tool)
			switch {
			case err != nil:
				a.Why = err.Error()
				return a, nil
			case in.Pins[tool] == "":
				a.Then = append(a.Then, "nobody pinned what "+tool+" is, so a model is never offered it; a walk or a program still calls it")
			default:
				if c, ok := loadToolChanges(root)[in.Name+"/"+tool]; ok && c.Pinned == in.Pins[tool] {
					a.Why = in.Name + " changed what " + tool + " is since it was pinned, so nothing calls it until somebody pins it again"
					return a, nil
				}
			}
		}
		if s.AsksFirst(agent.Action{Tool: tool}) {
			a.Then = append(a.Then, "a person approves the exact call first")
		}
		if unpublished {
			a.Then = append(a.Then, "once it has read the "+m.Retrieval.Ref+", the call waits for a person (the exfiltration breaker)")
		}
	case strings.HasPrefix(what, "host:"):
		host := strings.TrimPrefix(what, "host:")
		if err := s.MayReach(host); err != nil {
			a.Why = err.Error()
			return a, nil
		}
		if unpublished || program {
			a.Then = append(a.Then, "once it has read the "+nonEmpty(m.Retrieval.Ref, "draft")+
				", a connection is refused: a program cannot wait for a person (the exfiltration breaker)")
		}
	default:
		if err := s.Check(what); err != nil {
			a.Why = err.Error()
			return a, nil
		}
		if page != "" {
			st, err := open(root)
			if err != nil {
				return a, err
			}
			ref := refOf(m)
			typ, loc := pageTypeOf(root)(page), pageLocaleOf(st, ref)(page)
			if agent.IsWrite(what) {
				err = s.Mutate(ref, page, typ, loc)
			} else {
				err = s.Retrieve(ref, page, typ, loc)
			}
			if err != nil {
				a.Why = err.Error()
				return a, nil
			}
		}
		if s.AsksFirst(agent.Action{Op: what}) {
			a.Then = append(a.Then, "a person approves the exact call first")
		}
		if what == "publish" || agent.IsWrite(what) {
			a.Then = append(a.Then, "what it read was written by somebody, so a person decides before anything it produced goes live")
		}
	}
	a.Could = true
	if gw, cfg, err := modelGateway(root); err == nil && gw != nil && cfg != nil {
		for _, b := range cfg.Budgets {
			if b.Consumer == "agent:"+name && b.MoneyPerDay != "" {
				a.Spent = fmt.Sprintf("%s of %s %s today", gw.TodaySpend("agent:"+name, time.Now()), b.MoneyPerDay, cfg.Currency)
			}
		}
	}
	return a, nil
}

// agentCould is `quilzo agent could NAME [--model | --program] [--as PERSON] WHAT [PAGE]`.
func agentCould(root string, args []string) error {
	usage := errors.New("quilzo agent could NAME [--model | --program] [--as PERSON] OPERATION [PAGE] | tool:NAME | host:HOST")
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet("agent could", flag.ContinueOnError)
	withModel := fs.Bool("model", false, "a model deciding")
	program := fs.Bool("program", false, "its program deciding")
	as := fs.String("as", "", "the person starting the run; you, unless you administer")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	args = append(pos, fs.Args()...)
	if len(args) < 2 || len(args) > 3 || (*withModel && *program) {
		return usage
	}
	caller := resolveCaller(root, flagToken)
	run := caller
	if *as != "" && *as != caller.Name {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("asking what somebody else's run could do is an administrator's: %w", err)
		}
		c, err := callerFor(root, *as)
		if err != nil {
			return err
		}
		run = c
	}
	page := ""
	if len(args) == 3 {
		page = args[2]
	}
	a, err := could(root, args[0], args[1], page, *withModel, *program, run)
	if err != nil {
		return err
	}
	if w.JSON(a) {
		return nil
	}
	verdict, colour := "no", red
	if a.Could {
		verdict, colour = "yes", green
	}
	w.Human("%s%s%s  %s could %s%s, decided by %s, started by %s\n", colour, verdict, reset, a.Agent, a.What,
		map[bool]string{true: " " + page, false: ""}[page != ""], a.Decider, a.As)
	for _, n := range a.Bounded {
		w.Human("  %sbounded by %s: %s", dim, n.By, n.Why)
		if len(n.Lost) > 0 {
			w.Human("; loses %s", strings.Join(n.Lost, ", "))
		}
		if n.Autonomy != "" {
			w.Human("; autonomy %s", n.Autonomy)
		}
		w.Human("%s\n", reset)
	}
	if a.Why != "" {
		w.Human("  %s\n", a.Why)
	}
	for _, t := range a.Then {
		w.Human("  then: %s\n", t)
	}
	if a.Spent != "" {
		w.Human("  %sspent %s%s\n", dim, a.Spent, reset)
	}
	return nil
}
