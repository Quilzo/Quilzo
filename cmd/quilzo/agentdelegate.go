// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/agentmodel"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/store"
)

// Running the agent a supervisor handed work to.
//
// internal/agentexec holds the gate — may this agent delegate, to this name,
// with what is left of its budget — and this holds the machinery, because
// running an agent means a store, a model and a dispatcher, and the gate
// should not know about any of them.
//
// The child is a whole run: its own session over the narrowed manifest, its
// own decider, its own dispatcher, and its own outcome record. That is what
// makes the accountability claim on the agent card true rather than
// decorative — the log says which supervisor handed what to whom, and the
// child's record stands on its own even if the parent's run later fails.

// MaxDelegateDepth bounds how far work may be handed onward.
//
// A delegate may itself be a supervisor, and validation refuses an agent that
// delegates to itself and not two that delegate to each other. The budget
// bounds this already — every hand-off spends a step of the parent's budget
// and the child gets what is left — so this is the seatbelt rather than the
// limit, and it is here because "bounded by arithmetic somewhere else" is a
// worse thing to rely on for recursion than a number.
const MaxDelegateDepth = 4

// delegation runs a named delegate.
type delegation struct {
	root  string
	store *store.Store
	// model is nil when the run was started without one, in which case a
	// delegate walks its manifest exactly as `agent run` does — which is the
	// mode that costs nothing and still proves the pipeline is wired.
	model assist.Model
	// parent names the supervisor, for the record. A delegated run with no
	// note of who asked for it is the accountability gap with extra steps.
	parent string
	depth  int
}

// Run carries out one delegated run and returns what the delegate answered.
func (d delegation) Run(ctx context.Context, name string, child *agent.Session,
	instruction string) (string, error) {
	if d.depth >= MaxDelegateDepth {
		return "", fmt.Errorf(
			"work has been handed on %d times and this is as far as it goes. "+
				"A delegate may itself be a supervisor, and two that name "+
				"each other are a cycle validation does not refuse",
			MaxDelegateDepth)
	}
	if strings.TrimSpace(instruction) == "" {
		// A supervisor exists to decompose. Handing a stage onward without
		// saying what the stage is leaves the delegate to guess from its own
		// purpose, which is a goal chosen at run time by the agent least able
		// to see the whole job.
		return "", fmt.Errorf(
			"%s was handed nothing to do. A delegation carries the "+
				"instruction for that stage", name)
	}

	m := child.Manifest()
	decide, err := d.decider(child, m)
	if err != nil {
		return "", err
	}

	caller := resolveCaller(d.root, "")
	runner := agent.Runner{
		Decide: decide,
		Perform: agentexec.Dispatch(
			agentexec.Reader{
				Store:  d.store,
				Types:  pageTypeOf(d.root),
				Locale: pageLocaleOf(d.store, refOf(m)),
			},
			agentexec.Writer{
				Store: d.store,
				// The delegate, not the supervisor. A commit attributed to
				// whoever started the pipeline is a history that names the
				// wrong agent, and the review queue reads the author.
				Author:  "agent/" + m.Name,
				Gate:    pageGate(d.root),
				Propose: proposeCommit(d.root, d.store),
			},
			agentexec.Tools{
				Installed: func() (agent.Integrations, error) {
					set, lerr := loadIntegrations(d.root)
					if lerr != nil || set == nil {
						return agent.Integrations{}, lerr
					}
					return *set, lerr
				},
				Call: newMCPClient(d.root),
			},
			d.next(m.Name),
			child,
		),
		Record: func(rc agent.Receipt) {
			detail := rc.Detail()
			// The half that makes this delegation with accountability rather
			// than delegation. Without it the log holds two runs that look
			// unrelated, and the question an auditor actually asks — who told
			// it to do that — has no answer in the record.
			detail["delegated_by"] = d.parent
			record(d.root, actorRecord(caller, "agent.delegate", outcomeOf(rc),
				m, d.model, detail))
		},
	}

	trace, runErr := runner.Run(ctx, child, instruction)
	if runErr != nil {
		return "", runErr
	}
	answer := strings.TrimSpace(trace.Answer)
	if answer == "" {
		answer = fmt.Sprintf("%s finished %d step(s) and said nothing",
			m.Name, len(trace.Steps))
	}
	return answer, nil
}

// next is the delegate surface the child itself gets, one level deeper.
func (d delegation) next(parent string) agentexec.Delegates {
	deeper := delegation{
		root: d.root, store: d.store, model: d.model,
		parent: parent, depth: d.depth + 1,
	}
	return agentexec.Delegates{
		Manifest: manifestLoader(d.root),
		Run:      deeper,
	}
}

// decider is how the child chooses its actions.
//
// With no model it walks its own manifest, which is the same thing `agent run`
// does without --model: it costs nothing, needs no endpoint, and answers the
// question an operator asks first, which is whether the pipeline is wired at
// all rather than whether it is clever.
func (d delegation) decider(child *agent.Session, m agent.Manifest) (agent.Decide, error) {
	if d.model == nil {
		return walkOf(m), nil
	}
	return agentmodel.Decider{
		Model:   d.model,
		Session: child,
		Tokens:  child.Tokens,
	}.Decide(), nil
}

// walkOf is the scripted plan: every capability and every tool, once.
func walkOf(m agent.Manifest) agent.Decide {
	plan := make([]agent.Action, 0, len(m.Capabilities)+len(m.Tools)+1)
	for _, c := range m.Capabilities {
		plan = append(plan, agent.Action{Op: c})
	}
	for _, t := range m.Tools {
		plan = append(plan, agent.Action{Tool: t.Name})
	}
	for _, name := range m.Delegates {
		plan = append(plan, agent.Action{
			Delegate: name,
			Say:      "checking that this stage is wired",
		})
	}
	plan = append(plan, agent.Action{Say: "checked"})

	i := 0
	return func(context.Context, string, []agent.Observation) (agent.Action, error) {
		if i >= len(plan) {
			return agent.Action{Say: "checked"}, nil
		}
		a := plan[i]
		i++
		return a, nil
	}
}

// manifestLoader reads a named agent's own declaration.
//
// Re-validated against this build, for the reason `agent run` re-validates:
// a manifest written when an operation existed and no longer does describes a
// permission nothing grants, and a supervisor would hand a stage to an agent
// that cannot work and read the refusals as the store's answer.
func manifestLoader(root string) func(string) (agent.Manifest, error) {
	return func(name string) (agent.Manifest, error) {
		set, err := loadAgents(root)
		if err != nil {
			return agent.Manifest{}, err
		}
		m, ok := set.Agents[name]
		if !ok {
			return agent.Manifest{}, fmt.Errorf(
				"no agent called %q; the supervisor names it as a delegate "+
					"and this install has no such manifest", name)
		}
		if err := m.Validate(knownCapabilities(root)); err != nil {
			return agent.Manifest{}, err
		}
		return m, nil
	}
}
