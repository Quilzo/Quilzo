// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/decide"
	"github.com/quilzo/quilzo/internal/mcp"
)

// Deciders, for an agent. The bounded-question pattern JevAI offers its
// agent skill: the agent keeps control of what happens, and asks a typed
// question with a confidence instead of improvising a judgement. Declaring
// deciders stays off this surface — above its threshold a decider's answer
// drives things with no person involved, and what may drive what is a
// person's decision.

func registerDecideOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "list_deciders", NeedsRole: "reader",
		Summary:  "the site's typed questions, with their options and thresholds",
		Keywords: []string{"decide", "classify", "route", "score", "triage"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		set, err := decide.Load(decidersPath(root))
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(set.Deciders)
		return string(b), err
	})

	srv.Register(mcp.Operation{
		Name: "decide", NeedsRole: "reader",
		Summary: "answer a decider's typed questions about some state",
		// The sentence on confidence says what decide.Decide reports, which
		// a test holds it to: it once said confidence was agreement alone,
		// and a client reading that would take a steady model's low stated
		// number for disagreement between asks.
		Detail: "Each answer comes with a confidence, an agreement and escalate. " +
			"Where escalate is true a person decides — do not act on that answer. " +
			"The question is asked several times; agreement is how far the asks " +
			"agreed (the share that gave the same answer, or for a score how " +
			"close the numbers were), and confidence is the lower of that and " +
			"the model's own stated confidence averaged over those asks, since " +
			"a model that changes its answer between asks is not as sure as it says.",
		Args: map[string]string{
			"name":  "the decider",
			"state": "any JSON value: the ticket, the comment, the alert",
		},
		// The words somebody uses for a judgement they want made: an agent
		// asking for "triage a support ticket" was sent to agent_activity.
		Keywords: []string{"decide", "classify", "route", "score", "gate", "triage",
			"ticket", "label", "judge", "categorise", "categorize"},
	}, func(a map[string]any) (any, error) {
		// A read. What it spends is bounded by the gateway's budget for
		// "decider:NAME", which is where a cost limit belongs.
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		name, _ := a["name"].(string)
		d, err := loadDecider(root, name)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		m, _ := deciderModel(root, d.Name)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := decide.Decide(ctx, d, m, a["state"])
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		recordAsk(root, caller, res, a["state"])
		b, err := json.Marshal(res)
		return string(b), err
	})
}
