// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
)

// The state files where a lost write undoes a security decision: who may
// do what, which credentials are live, what agents may do and who answers
// for them, and where events are sent. Each is changed under its lock,
// on what is stored at that moment (atomicfile.Update), rather than loaded
// early and written back whole later.

// updatePolicy changes the access policy as it is stored now, and returns
// it as it was written.
//
// An administrator who stops being one is noted, before the policy is
// written, for the day in which the one left does not approve alone
// (dual.Settle). Here because every change to who may do what comes this
// way: revoked or denied on the command line or on People, or
// deprovisioned by the identity provider.
func updatePolicy(root string, change func(*auth.Policy) error) (*auth.Policy, error) {
	var out *auth.Policy
	err := atomicfile.Update(policyPath(root), func(p *auth.Policy) error {
		out = p
		before := dual.Administrators(p)
		if err := change(p); err != nil {
			return err
		}
		return dualStore(root).NoteAdministrators(before, dual.Administrators(p), time.Now())
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// saveTokens writes a token store merged with the one stored now, so a
// token added or revoked elsewhere since ts was read is neither lost nor
// brought back (auth.TokenStore.MergeInto).
func saveTokens(root string, ts *auth.TokenStore) error {
	return atomicfile.Update(tokensPath(root), func(stored *auth.TokenStore) error {
		ts.MergeInto(stored, time.Now())
		return nil
	})
}

// updateAgents changes the agent declarations as they are stored now.
func updateAgents(root string, change func(*agentSet) error) error {
	return atomicfile.Update(agentsPath(root), func(set *agentSet) error {
		if set.Agents == nil {
			set.Agents = map[string]agent.Manifest{}
		}
		if set.Identities == nil {
			set.Identities = map[string]agent.Identity{}
		}
		return change(set)
	})
}

// updateHooks changes the webhook endpoints and deliveries as they are
// stored now.
func updateHooks(root string, change func(*hookFile) error) error {
	return atomicfile.Update(hooksPath(root), change)
}
