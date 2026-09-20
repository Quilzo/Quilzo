// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
)

// Who acted, when the actor was an agent.
//
// # What was wrong
//
// An agent run was recorded under the principal of whoever started it, with
// the manifest's name as a detail field. cmd/quilzo/assist.go already says why
// that is the wrong way round:
//
//	The model is the actor, and it is recorded as one. Logging this as the
//	human who typed the command would lose the fact the log exists to
//	preserve.
//
// The MCP surface does it that way, the assistant does it that way, and the
// runner built specifically for agents did not.
//
// # What it cost
//
// internal/agentwatch exists to notice a model behaving badly — an agent
// hammering at operations it keeps being refused — and its only input is the
// audit log, filtered to events where the actor was a model. Every agent run
// was recorded as a human, so the watchdog could not see a single one. Six
// runs in the log, and:
//
//	$ quilzo agents
//	no model has acted in the last 24h0m0s
//
// The principal matters as much as the kind: agentwatch buckets by it, so with
// the human there, every agent one person runs would have merged into one
// report. "The support bot is hammering at publish" and "the archivist is
// fine" would have averaged into a number about neither.
//
// # Why only a run that had a model
//
// A run without --model is not a model acting. The plan is the manifest, every
// capability tried once in a fixed order, and nothing chose anything — so it
// cannot misbehave in the way the watchdog looks for, and recording it as a
// model would need a model name this program would have to invent. The audit
// package refuses an AI principal that does not name its model, and it is
// right to.
//
// So a probe stays what it is: a person checking a manifest.

// actorRecord builds the audit record for one agent run.
//
// caller is who started it and stays in the record, because accountability
// does not move to the agent — somebody chose to run it, and on_behalf_of is
// where every other AI-actor record in this program puts them.
func actorRecord(caller *Caller, action string, outcome audit.Outcome,
	m agent.Manifest, model assist.Model, detail map[string]string) audit.Record {

	if model == nil {
		// A manifest walk. The person is the actor because the person is the
		// only thing that decided anything.
		return caller.auditRecord(action, "/", outcome, detail)
	}
	if detail == nil {
		detail = map[string]string{}
	}
	detail["on_behalf_of"] = caller.Name
	if !caller.Verified {
		// Kept, and about the human rather than the agent. An agent's identity
		// is not something a credential proves; the question the log is
		// answering here is whether the person who started it was known.
		detail["started_by_unverified"] = caller.Why
	}
	return audit.Record{
		Action: action, Resource: "/", Outcome: outcome,
		// Named for the manifest, because that is the unit the watchdog
		// reports on and the unit an operator would quarantine.
		Principal: "agent/" + m.Name,
		Kind:      audit.KindAI,
		Model:     model.Name(),
		// Verified when a verified identity stands behind the act, which is
		// the question this field is answering.
		//
		// Not a claim that the agent proved itself — nothing could, since an
		// agent is a manifest in this store rather than a credential holder.
		// The claim is the one internal/agentwatch reads it as: its
		// Unattributed strike is "an action recorded with no verified
		// identity behind it, from a surface that should have one", and this
		// is such a surface. A person presented a token, the policy let that
		// token run this manifest, and on_behalf_of above names them.
		//
		// False when nobody did, which is the case the strike exists for.
		Verified: caller.Verified,
		Detail:   detail,
	}
}

// outcomeOf is how a run is recorded, which is not the same question as
// whether it is billable.
//
// Both call sites asked Billable and wrote Denied when it said no. Billable
// asks "is there an outcome to charge for"; Denied means the gate refused
// something. They are different, and conflating them mattered as soon as
// agent runs became visible to internal/agentwatch: three runs that could not
// reach the model were recorded as denied, and the watchdog reported an agent
// repeatedly refused — which is its signal for an agent that has not accepted
// the answer, and describes a broken endpoint not at all.
func outcomeOf(rc agent.Receipt) audit.Outcome {
	if rc.Refused > 0 {
		return audit.Denied
	}
	if ok, _ := rc.Billable(); ok {
		return audit.Success
	}
	// Finished nothing and was refused nothing: the model was unreachable, the
	// run was cancelled, the budget went. A failure, which is a thing that
	// happened to the agent rather than something it did.
	return audit.Failure
}
