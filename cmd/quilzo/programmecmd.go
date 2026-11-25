// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// What the security programme's four commands share: `quilzo requirement`,
// `quilzo soa`, `quilzo control` and `quilzo population` (requirementcmd.go,
// soacmd.go, controlcmd.go, populationcmd.go), each a module of its own.
//
// Each writes through registerWriter, so the audit log, the policy gate as
// the caller and the register's own rules come with every write. A decision
// is raised as a proposal and approved through the approvals module, as
// every decision in the register is: by somebody else on Sign-off in the
// admin, or at the console with `quilzo ... approve ID --surface HASH`, and
// by its raiser alone only when they are the only person who may.

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

// openProgramme is the programme of the store at root, for reading.
func openProgramme(root string) (*programme.Programme, error) {
	r, err := openRegister(root)
	if err != nil {
		return nil, err
	}
	return &programme.Programme{Reg: r}, nil
}

// programmeWriter is the programme of the store at root, wired to write as
// the caller through the register's one writer, which names them by their
// pseudonym in the subject map, and to have its decisions approved through
// the approvals module, as every decision in the register is.
func programmeWriter(root string, c *Caller) (*programme.Programme, register.Actor, error) {
	r, by, err := registerWriter(root, c)
	if err != nil {
		return nil, register.Actor{}, err
	}
	m, err := approvalsOn(root, r)
	if err != nil {
		return nil, register.Actor{}, err
	}
	return &programme.Programme{Reg: r, Approvals: m}, by, nil
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

// sayDecided says what became of a decision: waiting for its approvers,
// with how they approve it and the hash they are shown, or written, alone
// or not.
func sayDecided(d programme.Decided, approve string) error {
	if w.JSON(d) {
		return nil
	}
	line := fmt.Sprintf("quilzo %s approve %s --surface %s", approve, d.ID, d.Surface)
	switch {
	case d.Waits && d.Signed > 0:
		fmt.Printf("  %sapproved%s: %d of the %d approvals it needs; it waits for the rest\n", bold, reset, d.Signed, d.Needed)
	case d.Waits && d.Yours:
		fmt.Printf("  %swaits%s for your approval: you are the only person who may approve it, so you approve it alone, "+
			"and it is marked so, with a review by somebody else due. Read what it is, then type back its hash:\n"+
			"    quilzo approval show %s\n    %s\n", bold, reset, d.ID, line)
	case d.Waits:
		fmt.Printf("  %swaits%s for somebody else who may approve it: on Sign-off in the admin with their passkey, or at "+
			"the console, typing back its hash:\n    %s\n", bold, reset, line)
	case d.Alone:
		fmt.Printf("  %sapproved alone%s: you are the only person who may approve it, so it is marked so, and a review "+
			"by somebody else is due by %s\n", bold, reset, time.Now().Add(programme.ReviewWithin).UTC().Format("2 Jan 2006"))
	default:
		fmt.Printf("  %sapproved%s\n", bold, reset)
	}
	if d.Surface != "" && !d.Waits {
		fmt.Printf("  %swhat was approved is %s%s\n", dim, d.Surface, reset)
	}
	if d.Receipt.Commit != "" {
		fmt.Printf("  %sthe register stands at %s; receipt %s%s\n", dim, d.Receipt.Commit, d.Receipt.Digest, reset)
	}
	return nil
}

// approveDecision approves a waiting decision of one of the kinds a
// command decides, at the console, through the approvals module: the
// person typing back the hash of what it shows, as `quilzo approval
// approve` takes it, under the separation policy and every rule of the
// engine. args are the line's own, an identifier and --surface.
func approveDecision(root string, args []string, command string, kinds ...register.Kind) error {
	fs := flag.NewFlagSet(command+" approve", flag.ContinueOnError)
	surface := fs.String("surface", "", "the hash of what it shows, as `quilzo approval show ID` gives it, typed back")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 || strings.TrimSpace(*surface) == "" {
		return errMisused{fmt.Errorf("usage: quilzo %s approve ID --surface HASH; `quilzo approval show ID` shows what "+
			"it approves and the hash to type back", command)}
	}
	id := pos[0]
	caller := resolveCaller(root, flagToken)
	p, _, err := programmeWriter(root, caller)
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
				who, err := consolePerson(root, caller)
				if err != nil {
					return err
				}
				d, err := p.Approve(who, w.ID, approval.Proof{Console: &approval.ConsoleProof{
					Typed: register.Digest(strings.TrimSpace(*surface)), Verified: caller.Verified}})
				if err != nil && (d.Receipt.Commit == "" || !errors.Is(err, register.ErrUnrecorded)) {
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
