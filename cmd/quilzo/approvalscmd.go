// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	// Named so, because a test helper in this package is called waiting.
	waitlist "github.com/quilzo/quilzo/internal/waiting"
)

// `quilzo approvals`: everything waiting for a person, in one list — what
// agents are waiting on, tool calls held for a second person, acts on
// other tools a case is waiting to have approved, features and newsletter
// issues agents proposed, the change to the site waiting for approvals,
// and memories held until somebody confirms them. Each line says what
// deciding commits to and the command that decides it.
//
// The list itself is internal/waiting's, built from this store's records
// for the caller's own credential. The admin's Approvals, Today and the
// assistant's waiting card read this same list through a hook (serve.go),
// rather than building their own: they did, and it drifted from this one.

// waitingItem is one thing waiting.
type waitingItem = waitlist.Item

// waitingFor lists what the caller may decide.
func waitingFor(root string, c *Caller, now time.Time) ([]waitingItem, error) {
	return waitingIn(root, nil, c, now)
}

// waitingIn is waitingFor over the store already open, as the server holds
// one; nil opens it, as a command does.
func waitingIn(root string, s *store.Store, c *Caller, now time.Time) ([]waitingItem, error) {
	return waitlist.List(waitingSources(root, s, c, now), now)
}

// waitingSources are where this store keeps what waits, asked about the
// caller through authorise, which is the session's check and not only the
// person's.
func waitingSources(root string, s *store.Store, c *Caller, now time.Time) waitlist.Sources {
	var declared *agentSet
	return waitlist.Sources{
		Name:     c.Name,
		ReadOnly: c.Limits.ReadOnly,
		May: func(act auth.Action, resource string) bool {
			return authorise(root, c, act, resource) == nil
		},
		// A run's question is listed for whoever may decide it, which is
		// its sponsor and whoever holds approve on it, not only
		// administrators.
		Runs: func() ([]agent.Record, error) {
			declared, _ = loadAgents(root)
			return listAgentRuns(root, "", 0)
		},
		MayDecide: func(rec agent.Record) bool { return mayApprove(root, c, rec) == nil },
		Writes: func(rec agent.Record, tool string) bool {
			return declared != nil && stepWrites(root, declared.Agents[rec.Agent], tool)
		},
		Held: func() ([]waitlist.Held, error) {
			held, err := heldCalls(root, now)
			var out []waitlist.Held
			for _, h := range held {
				out = append(out, waitlist.Held{ID: h.ID, Integration: h.Integration, Tool: h.Tool,
					For: h.Principal, App: h.Client, Asked: h.Asked})
			}
			return out, err
		},
		Pending: func() ([]feature.Pending, error) { return pendingFeatures(root) },
		Proposals: func() ([]waitlist.Proposal, error) {
			list, err := proposals(root)
			var out []waitlist.Proposal
			for _, pr := range list {
				out = append(out, waitlist.Proposal{ID: pr.ID, By: pr.By, Title: pr.Title, Version: pr.Version,
					What: pr.What, For: pr.For, At: pr.At})
			}
			return out, err
		},
		Review: func() (*waitlist.Review, error) { return reviewWaiting(root, s) },
		Issues: func() ([]newsletter.Issue, error) {
			list, err := openNewsletter(root)
			if err != nil {
				return nil, err
			}
			return list.Issues()
		},
		Memories: memoryStore(root).List,
	}
}

func cmdApprovals(root string, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: quilzo approvals")
	}
	now := time.Now().UTC()
	items, err := waitingFor(root, resolveCaller(root, ""), now)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"waiting": items}) {
		return nil
	}
	if len(items) == 0 {
		fmt.Println("  nothing is waiting for you")
		return nil
	}
	for _, it := range items {
		who := it.Agent
		if who == "" {
			who = it.Source
		}
		fmt.Printf("  %s%-9s%s %-18s %s  %s%s%s\n", bold, it.Commits, reset, truncate(who, 18),
			truncate(printable(it.What), 60), dim, it.Since.Format("2 Jan 15:04"), reset)
		if it.Why != "" {
			fmt.Printf("            %s%s%s\n", dim, truncate(printable(it.Why), 100), reset)
		}
		// Said, as the screen says it: approving it now would be agreeing
		// to something decided about a different state of things.
		if it.Expired {
			fmt.Printf("            %sasked too long ago to agree to%s\n", yellow, reset)
		}
		fmt.Printf("            %s\n", it.Decide)
	}
	return nil
}

// reviewWaiting is the change to the site waiting for approvals: the
// proposal for the draft as it stands, when the draft is not what is live,
// under the policy publishing is asked about. Whether the caller may give
// an approval is internal/waiting's to say.
//
// It reads the store it is handed, the server's own, and opens one only
// when it is handed none. Opening the store reads the key to an encrypted
// one, and the screens ask for this list on every Approvals, Today and
// assistant page: a server given its key by a command (QUILZO_KEY_COMMAND,
// a KMS or a password manager) ran that command each time anybody looked,
// where it had run it once, when it started.
func reviewWaiting(root string, s *store.Store) (*waitlist.Review, error) {
	if s == nil {
		var err error
		if s, err = open(root); err != nil {
			return nil, err
		}
	}
	draft := s.GetRef(site.RefDraft)
	if draft == "" || draft == s.GetRef(site.RefLive) {
		return nil, nil
	}
	pol, err := loadApprovalPolicy(root)
	if err != nil {
		return nil, err
	}
	prop, _, err := currentProposal(root, s)
	if err != nil || prop.Content != draft {
		return nil, err
	}
	return &waitlist.Review{Policy: pol, Proposal: *prop, KindOf: kindOfPrincipal(root)}, nil
}
