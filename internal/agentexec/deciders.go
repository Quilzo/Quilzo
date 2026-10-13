// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentexec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/decide"
)

// The deciders, for an agent: the bounded-question pattern this program
// offers over MCP, performed inside a run — because the point of a typed
// answer with a confidence is that the agent asking it keeps control of
// what happens, and until now an agent that held the capability was told
// at runtime that nobody had connected it.
//
// An escalated answer is not an answer, and the observation says so in the
// same words the MCP operation does: where escalate is true a person
// decides, and the agent does not act on it. The state it asked about is
// somebody's words — a ticket, a comment, a log line — so the run is
// marked as having read them, and the breaker holds any later attempt to
// carry them to another host.

// Deciders performs the typed questions an agent may ask.
type Deciders struct {
	// Load reads the declared deciders; the same load the CLI and the
	// admin screen make.
	Load func() (*decide.Set, error)
	// Model is the model a decider is asked with, by its name; nil means
	// none is configured and every question escalates, which is the
	// package's own failure mode and the right one.
	Model func(name string) decide.Model
}

// Perform carries out the decider operations.
func (dd Deciders) Perform(s *agent.Session) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		switch a.Op {
		case "list_deciders":
			return dd.list()
		case "decide":
			return dd.ask(ctx, s, a)
		}
		return "", fmt.Errorf("%q is not one of the deciders' operations", a.Op)
	}
}

func (dd Deciders) list() (string, error) {
	set, err := dd.Load()
	if err != nil {
		return "", err
	}
	var lines []string
	for _, d := range set.Deciders {
		what := ""
		for _, q := range d.Questions {
			if what != "" {
				what += ", "
			}
			what += q.Name + " (" + string(q.Kind) + ")"
		}
		lines = append(lines, fmt.Sprintf("%s — %s: %s", d.Name, d.Title, what))
	}
	if len(lines) == 0 {
		return "no deciders are declared on this store", nil
	}
	return strings.Join(lines, "\n"), nil
}

func (dd Deciders) ask(ctx context.Context, s *agent.Session, a agent.Action) (string, error) {
	name, _ := a.Input["name"].(string)
	if strings.TrimSpace(name) == "" {
		return "", errors.New("decide needs the name of a decider")
	}
	state, has := a.Input["state"]
	if !has {
		return "", errors.New("decide needs the state to ask about")
	}
	set, err := dd.Load()
	if err != nil {
		return "", err
	}
	d, ok := set.Get(name)
	if !ok {
		return "", fmt.Errorf("there is no decider called %q on this store", name)
	}
	var m decide.Model
	if dd.Model != nil {
		m = dd.Model(name)
	}
	res, err := decide.Decide(ctx, d, m, state)
	if err != nil {
		return "", err
	}
	// Somebody's words reached a model, and this run will act on what came
	// back: the breaker should know that from here on.
	s.ReadFiles("the state given to the decider " + name)

	var out strings.Builder
	escalated := false
	for _, ans := range res.Answers {
		if ans.Escalate {
			escalated = true
			fmt.Fprintf(&out, "%s: a person decides (confidence %.2f is under the %.2f threshold) — do not act on this answer\n",
				ans.Question, ans.Confidence, d.MinConfidence)
			continue
		}
		fmt.Fprintf(&out, "%s: %v (confidence %.2f)\n", ans.Question, ans.Value, ans.Confidence)
		if ans.Why != "" {
			fmt.Fprintf(&out, "  %s\n", clip(ans.Why, 300))
		}
	}
	if escalated {
		out.WriteString("escalated: a person decides; ask something else or finish\n")
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
