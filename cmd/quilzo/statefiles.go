// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync"
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

// useWrittenEvery is how often one token's use is written down by a server.
// `token list` shows the day and staleness is counted in days, so an hour
// loses nothing anybody reads, and a write per request would rewrite the
// file every other process reloads when it changes.
const useWrittenEvery = time.Hour

// useRecorder writes down when a token was used, for the admin's doors that
// take a token and never save the store: the content API and /mcp.
//
// Authenticating notes a use only in the checking process's copy of the
// store. The command line saves its copy, and so do the app connections,
// but these two did not, so on the reference stack a token used three
// times at each was listed as used "never", and `token stale` would have
// offered integration tokens in daily use for revocation.
//
// Only the use, on the token as it is stored now, so nothing else about
// the token, a revocation included, is undone by it. A use that cannot be
// written is not a reason to refuse the request it came with.
func useRecorder(root string) func(auth.Token) {
	var mu sync.Mutex
	written := map[string]time.Time{}
	return func(tok auth.Token) {
		now := time.Now()
		mu.Lock()
		if at, ok := written[tok.ID]; ok && now.Sub(at) < useWrittenEvery {
			mu.Unlock()
			return
		}
		if len(written) > 10000 {
			written = map[string]time.Time{}
		}
		written[tok.ID] = now
		mu.Unlock()
		_ = atomicfile.Update(tokensPath(root), func(stored *auth.TokenStore) error {
			if !stored.NoteUsed(tok.ID, now) {
				return atomicfile.ErrUnchanged
			}
			return nil
		})
	}
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
