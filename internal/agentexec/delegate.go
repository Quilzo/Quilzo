// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// Handing work to another agent.
//
// Manifest.Delegates was validated, refused on anything that is not a
// supervisor, copied out of the supervisor archetype, and published on the
// agent card as this program's answer to the governance gap the research calls
// delegation with accountability. Nothing read it. A supervisor's whole reason
// for existing — decompose, hand each stage to a named specialist, aggregate —
// did not happen, and the card said it did.
//
// # Why the child is not simply run
//
// Because a supervisor that runs a delegate as declared is a way to launder
// capability. Delegate to an agent holding more, and every restriction on the
// supervisor was decoration. So the child that runs is the parent's manifest
// narrowed by the child's declaration — the intersection, never the union —
// and a delegate declaring a wider scope than its parent simply gets less than
// it asked for rather than being refused, because "narrower than the parent"
// is a property of the run and not a mistake in the declaration.
//
// # Why the budget is the remainder and not the smaller total
//
// Narrow takes the smaller of the two budgets, which is the right question to
// ask of two manifests and the wrong one to ask of a run in progress. A
// supervisor with ten steps and three delegates declaring ten each would hand
// out thirty. The child gets what its parent has left.
//
// # Why the result is not trusted
//
// Whatever a delegate returns is folded back with its taint. A tainted child
// answering into a clean parent would defeat the taint rule with one
// indirection: read untrusted content through a delegate, receive it as a
// string, publish. The child's costs and refusals come back for the same
// reason — an operator reading "refused four times" afterwards is owed the
// refusals that happened one level down.

// Runner performs one delegated run. The caller supplies it, because running
// an agent means a model, a store and a dispatcher, and this package holds the
// gate rather than the machinery.
type Runner interface {
	Run(ctx context.Context, name string, child *agent.Session,
		instruction string) (string, error)
}

// Delegates executes the delegate branch.
type Delegates struct {
	// Manifest returns a named agent's own declaration.
	Manifest func(name string) (agent.Manifest, error)
	// Run performs the child's work under the session this builds for it.
	Run Runner
}

// MaxInstruction bounds what a supervisor may say to a delegate.
//
// The instruction is the one part of a delegation a model composes freely, so
// it is the one part that can be made arbitrarily long. Four kilobytes is far
// past any real instruction and far short of anything worth spending this
// process's memory on.
const MaxInstruction = 4 << 10

// Perform returns the delegate branch of the dispatcher.
func (d Delegates) Perform(s *agent.Session) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		name := strings.TrimSpace(a.Delegate)
		// Asked first, and of the session rather than of the manifest this
		// function could read directly. The refusal is the record, and a
		// check that does not go through the gate produces no record.
		if err := s.MayDelegate(name); err != nil {
			return "", err
		}
		if d.Manifest == nil || d.Run == nil {
			return "", fmt.Errorf(
				"%s is a declared delegate of this agent and this build "+
					"cannot run one; nothing was handed to it", name)
		}

		declared, err := d.Manifest(name)
		if err != nil {
			return "", fmt.Errorf(
				"%s is a declared delegate and could not be loaded: %w",
				name, err)
		}
		// The parent narrows the child, never the other way round.
		bound := s.Manifest().Narrow(declared)
		// And the run gets what is left rather than what was declared.
		bound.Budget = smaller(bound.Budget, s.Remaining())
		if bound.Budget.Steps <= 0 {
			return "", fmt.Errorf(
				"nothing is left of this run's budget to give %s. A delegate "+
					"spends its parent's budget as well as its own, so a "+
					"supervisor cannot buy more by splitting the work", name)
		}

		child := agent.NewSession(bound, nil)
		// Folded whatever happens. A delegate that failed halfway still spent
		// what it spent and still read what it read, and a parent that only
		// inherited from successful children would be a parent that could read
		// untrusted content by arranging to fail.
		defer s.Fold(child)

		out, err := d.Run.Run(ctx, name, child, instruction(a))
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		return out, nil
	}
}

// instruction is what the supervisor said to the delegate, bounded.
func instruction(a agent.Action) string {
	said := strings.TrimSpace(a.Say)
	if said == "" {
		if v, ok := a.Input["instruction"].(string); ok {
			said = strings.TrimSpace(v)
		}
	}
	if len(said) > MaxInstruction {
		said = said[:MaxInstruction]
	}
	return said
}

func smaller(a, b agent.Budget) agent.Budget {
	out := a
	if b.Steps < out.Steps {
		out.Steps = b.Steps
	}
	if b.Tools < out.Tools {
		out.Tools = b.Tools
	}
	if b.Duration < out.Duration {
		out.Duration = b.Duration
	}
	return out
}
