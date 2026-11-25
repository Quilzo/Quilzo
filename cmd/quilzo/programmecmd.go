// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
)

// What the security programme's four commands share: `quilzo requirement`,
// `quilzo soa`, `quilzo control` and `quilzo population` (requirementcmd.go,
// soacmd.go, controlcmd.go, populationcmd.go), each a module of its own.
//
// Each writes through registerWriter, so the audit log, the policy gate as
// the caller and the register's own rules come with every write. A decision
// is made the one way internal/programme makes it: the only person who may
// approve it decides alone, and it is marked so; anybody else's waits for
// somebody else, who approves it with `quilzo ... approve ID`.

// Each of the four commands' own row asks what its strictest line asks,
// and the lines that read narrow it to view, so a line added later without
// a row of its own arrives over-guarded rather than open to a reader. Run
// bare, each only reads, and is asked as the line it runs (bareRuns): the
// entries are added here, beside the commands, so the modules edit no list
// another module edits.
func init() {
	bareRuns["requirement"] = "starters"
	bareRuns["soa"] = "scopes"
	bareRuns["control"] = "list"
	bareRuns["population"] = "list"
}

// programmeKeeper is where the programme keeps who each pseudonym is and
// the words of justifications: beside the store, where they can be erased,
// and on a store encrypted at rest, no words at all.
func programmeKeeper(root string, s *store.Store) programme.Keeper {
	return &programme.FileKeeper{Dir: filepath.Join(root, "programme"), NoWords: s.Encrypted()}
}

// openProgramme is the programme of the store at root, for reading.
func openProgramme(root string) (*programme.Programme, error) {
	r, err := openRegister(root)
	if err != nil {
		return nil, err
	}
	return &programme.Programme{Reg: r, Keep: programmeKeeper(root, r.Store)}, nil
}

// programmeWriter is the programme of the store at root, wired to write as
// the caller, and the caller as the register names a writer: a person by
// the pseudonym the programme keeps for them.
func programmeWriter(root string, c *Caller) (*programme.Programme, register.Actor, error) {
	r, by, err := registerWriter(root, c)
	if err != nil {
		return nil, register.Actor{}, err
	}
	p := &programme.Programme{Reg: r, Keep: programmeKeeper(root, r.Store)}
	if c.Kind == audit.KindHuman {
		if by.Subject, err = p.Keep.Pseudonym(c.Name, "person"); err != nil {
			return nil, register.Actor{}, err
		}
	}
	return p, by, nil
}

// deciderFor is the caller deciding a decision of a kind: how many people
// may approve one, as the policy has it, and what the caller was proved
// by.
func deciderFor(root string, c *Caller, by register.Actor, kind register.Kind) programme.Decider {
	spec, _ := register.SpecOf(string(kind))
	proof := "unverified: " + c.Why
	if c.Verified {
		proof = "verified by the credential " + c.Credential
	}
	return programme.Decider{By: by, Eligible: eligibleFor(root, auth.ActApprove, spec.Resource()),
		MayApprove: authorise(root, c, auth.ActApprove, spec.Resource()) == nil, Proof: proof}
}

// eligibleFor is how many principals the policy lets act on a resource. A
// store with no policy has one: whoever runs the command. A policy that
// cannot be read is taken to have more than one, so nobody decides alone
// on a guess.
func eligibleFor(root string, act auth.Action, resource string) int {
	inUse, err := policyInUse(root)
	if err != nil {
		return 2
	}
	if !inUse {
		return 1
	}
	p, err := loadPolicy(root)
	if err != nil {
		return 2
	}
	n := 0
	for _, name := range p.Principals() {
		if p.Evaluate(name, act, resource).Allowed {
			n++
		}
	}
	return n
}

// sayDecided says what became of a decision: written, alone or not, or
// waiting, with the line that approves it.
func sayDecided(d programme.Decided, approve string) error {
	if w.JSON(d) {
		return nil
	}
	switch {
	case d.Waits:
		fmt.Printf("  %swaits%s for somebody else who may approve it; they run:\n    quilzo %s approve %s\n",
			bold, reset, approve, d.ID)
	case d.Alone:
		fmt.Printf("  %sapproved alone%s: you are the only person who may approve it, so it is marked so, and a review "+
			"by somebody else is due by %s\n", bold, reset, time.Now().Add(programme.ReviewWithin).UTC().Format("2 Jan 2006"))
	default:
		fmt.Printf("  %sapproved%s\n", bold, reset)
	}
	if d.Receipt.Commit != "" {
		fmt.Printf("  %sthe register stands at %s; receipt %s%s\n", dim, d.Receipt.Commit, d.Receipt.Digest, reset)
	}
	return nil
}

// approveDecision approves a waiting decision of one of the kinds a
// command decides.
func approveDecision(root, id string, command string, kinds ...register.Kind) error {
	caller := resolveCaller(root, flagToken)
	p, by, err := programmeWriter(root, caller)
	if err != nil {
		return err
	}
	waiting, err := p.Reg.Proposals()
	if err != nil {
		return err
	}
	for _, w := range waiting {
		if string(w.ID) != id {
			continue
		}
		for _, k := range kinds {
			if w.Kind == k {
				d, err := p.Approve(deciderFor(root, caller, by, k), w.ID)
				if err != nil {
					return programmeError(err)
				}
				return sayDecided(d, command)
			}
		}
		return errMisused{fmt.Errorf("%s is a waiting %s, which `quilzo %s approve` does not decide", id, w.Kind, command)}
	}
	return errNotFound{fmt.Errorf("no decision with the identifier %s is waiting; `quilzo register proposals` lists what waits", clip(id, 40))}
}

// programmeError is an error of the programme as the command line answers
// it, as registerError does the register's: a decision somebody else
// decides is a refusal, and a record the register finds not valid is a
// command given what it does not take.
func programmeError(err error) error {
	switch {
	case errors.Is(err, programme.ErrWaits):
		return errBlocked{err}
	case errors.Is(err, register.ErrInvalid):
		// What the register refuses as not valid is what the command was
		// given, which is how it was used.
		return errMisused{err}
	}
	return registerError(err)
}

// programmeMay is the check an operation of the programme's makes before it
// reads: a view of the register's area, as the caller.
func programmeMay(root string, caller *Caller) func() error {
	return func() error {
		if err := authorise(root, caller, auth.ActView, register.Area); err != nil {
			return &mcp.Refusal{Reason: err.Error()}
		}
		return nil
	}
}

// opError is an error of the programme as the agent interface answers it.
func opError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, register.ErrNotFound):
		return &mcp.Refusal{Reason: err.Error()}
	case errors.Is(err, register.ErrRefused), errors.Is(err, register.ErrModel):
		return &mcp.Refusal{Reason: err.Error()}
	case errors.Is(err, register.ErrInvalid):
		return &mcp.ArgumentError{Reason: err.Error()}
	}
	return err
}

// view is the register at its head.
func headView(p *programme.Programme) (*register.View, error) { return p.Reg.At("") }
