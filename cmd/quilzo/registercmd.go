// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
	waitlist "github.com/quilzo/quilzo/internal/waiting"
)

// `quilzo register`: the security register, read. What kinds of record it
// holds and how many of each, one kind's records, one record by its
// identifier, and what waits on its proposals ref for a person.
//
// Read-only on every surface. Records are written through register.Put by
// the modules that own them, each with its own command; this is the module
// every later one copies, so it registers its command, its operations, its
// screens and its routes in the content API from its own files (this one,
// internal/admin/registerscreen.go and internal/api/registerapi.go) and
// edits no list.

func init() {
	registerCLI(cliModule{
		module:  "register",
		command: "register",
		heading: "security register (typed records on their own ref, written only through register.Put; read here)",
		help: "  quilzo register kinds | proposals        the kinds of record it holds and how many of each, or what\n" +
			"                                            waits on its proposals ref for a person to accept\n" +
			"  quilzo register list KIND [--offset N] [--limit N]  one kind's records, in the order of their identifiers\n" +
			"  quilzo register show ID                  one record, with the hash it is stored under\n",
		run: cmdRegister,
		// Reading the register is a view of the compliance area's part of
		// the policy, which a role over the site reaches only as
		// administrator: somebody who may read the site's pages does not
		// thereby read its risks.
		needs:  map[string]need{"register": {action: auth.ActView}},
		area:   register.Area,
		reads:  [][]string{{"register", "kinds"}, {"register", "list", "Control"}, {"register", "proposals"}},
		absent: []string{"register", "show", "00000000000000000000000000000000"},
		ops:    registerRegisterOps,
		notForRuns: "the register holds restricted records, and which of them a run may read is decided by the " +
			"data classes its model route accepts, which are not yet declared; an outside agent reads them " +
			"under its person's own grant",
	})
}

func cmdRegister(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"kinds"}
	}
	switch args[0] {
	case "kinds":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return registerKinds(root)
	case "list":
		fs := flag.NewFlagSet("register list", flag.ContinueOnError)
		offset := fs.Int("offset", 0, "how many records to skip")
		limit := fs.Int("limit", 50, "how many records to show")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo register list KIND [--offset N] [--limit N]; `quilzo register kinds` names the kinds")}
		}
		if *offset < 0 || *limit < 1 {
			return errMisused{fmt.Errorf("--offset is 0 or more and --limit 1 or more")}
		}
		return registerList(root, pos[0], *offset, *limit)
	case "show":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo register show ID")}
		}
		return registerShow(root, pos[0])
	case "proposals":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return registerProposals(root)
	default:
		return errMisused{fmt.Errorf("unknown register command %q; try kinds, list, show or proposals", args[0])}
	}
}

// openRegister is the register of the store at root, for reading.
func openRegister(root string) (*register.Register, error) {
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	return register.Open(s), nil
}

func registerKinds(root string) error {
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	views, err := r.Census()
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"kinds": views, "head": r.Head()}) {
		return nil
	}
	for _, v := range views {
		fmt.Printf("  %s%-16s%s %-22s %6d  %s%s%s\n", bold, v.Kind, reset, v.Collection, v.Records, dim, v.Summary, reset)
	}
	if head := r.Head(); head != "" {
		fmt.Printf("\n  %sat %s%s\n", dim, head, reset)
	} else {
		fmt.Printf("\n  %snothing has been written to the register yet%s\n", dim, reset)
	}
	return nil
}

// specNamed is the kind a command line named, or not there.
func specNamed(name string) (register.Spec, error) {
	spec, ok := register.SpecOf(name)
	if !ok {
		return register.Spec{}, errNotFound{fmt.Errorf("the register has no kind called %q; `quilzo register kinds` names them", clip(name, 40))}
	}
	return spec, nil
}

func registerList(root, kind string, offset, limit int) error {
	spec, err := specNamed(kind)
	if err != nil {
		return err
	}
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	entries, total, err := r.List(spec.Kind, offset, limit)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"kind": spec.Kind, "total": total, "offset": offset, "limit": limit,
		"records": entries, "head": r.Head()}) {
		return nil
	}
	if total == 0 {
		fmt.Printf("  the register holds no %s records\n", spec.Kind)
		return nil
	}
	for _, e := range entries {
		fmt.Printf("  %s  %-40s %s%s%s\n", e.ID, truncate(printable(register.Label(e.Record)), 40),
			dim, e.Updated.At().Format("2 Jan 2006 15:04 UTC"), reset)
	}
	if shown := offset + len(entries); shown < total {
		fmt.Printf("\n  %s%d to %d of %d; --offset %d for the next%s\n", dim, offset+1, shown, total, shown, reset)
	}
	return nil
}

func registerShow(root, id string) error {
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	e, err := r.Get(register.ID(id))
	if errors.Is(err, register.ErrNotFound) {
		return errNotFound{err}
	}
	if err != nil {
		return err
	}
	if w.JSON(e) {
		return nil
	}
	fields, _ := json.MarshalIndent(e.Record, "  ", "  ")
	fmt.Printf("  %s%s%s %s\n", bold, e.Kind, reset, e.ID)
	fmt.Printf("  %sstored as %s, written %s, changed %s%s\n", dim, e.Object,
		e.Created.At().Format(time.RFC3339), e.Updated.At().Format(time.RFC3339), reset)
	fmt.Printf("  %s\n", printable(string(fields)))
	return nil
}

func registerProposals(root string) error {
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	list, err := r.Proposals()
	if err != nil {
		return err
	}
	if list == nil {
		list = []register.Proposal{}
	}
	if w.JSON(map[string]any{"proposals": list}) {
		return nil
	}
	if len(list) == 0 {
		fmt.Println("  nothing waits on the register's proposals ref")
		return nil
	}
	for _, p := range list {
		fmt.Printf("  %s%-14s%s %s  proposed by %s, %s\n", bold, p.Kind, reset, p.ID,
			printable(proposerOf(p)), p.At.At().Format("2 Jan 2006 15:04 UTC"))
		if p.Why != "" {
			fmt.Printf("                 %s%s%s\n", dim, truncate(printable(p.Why), 100), reset)
		}
	}
	fmt.Printf("\n  %snone of these is in the register, and no figure reads them, until a person accepts it%s\n", dim, reset)
	return nil
}

// proposerOf is who proposed a record: an agent by its name, a person by
// their pseudonym.
func proposerOf(p register.Proposal) string {
	if p.Agent != "" {
		return p.Agent
	}
	return string(p.Subject)
}

// registerWaiting is what waits on the register's proposals ref, for the
// one list of what waits for a person (approvalscmd.go).
func registerWaiting(root string) func() ([]waitlist.Proposed, error) {
	return func() ([]waitlist.Proposed, error) {
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		list, err := r.Proposals()
		var out []waitlist.Proposed
		for _, p := range list {
			spec, _ := register.SpecOf(string(p.Kind))
			out = append(out, waitlist.Proposed{ID: string(p.ID), Kind: string(p.Kind), By: proposerOf(p), Why: p.Why,
				Resource: spec.Resource(), At: p.At.At()})
		}
		return out, err
	}
}

// registerRegisterOps is the register's operations on the agent interface:
// the same three reads as the command line, and nothing that writes.
func registerRegisterOps(srv *mcp.Server, root string, caller *Caller) {
	may := func() error {
		if err := authorise(root, caller, auth.ActView, register.Area); err != nil {
			return &mcp.Refusal{Reason: err.Error()}
		}
		return nil
	}
	srv.Register(mcp.Operation{
		Name: "register_kinds", NeedsRole: "reader", Area: register.Area,
		Summary: "the kinds of record the security register holds, each with its schema and how many there are",
		Detail: "Each kind's name, its collection, what a record of it is, how far it may travel (its class), " +
			"whether it is a decision that carries its approval, and its fields with their types. Read-only: " +
			"records are written by the modules that own them, through one path that a model cannot take.",
		Keywords: []string{"register", "security", "kinds", "schema", "controls", "evidence", "risks"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		views, err := r.Census()
		if err != nil {
			return nil, err
		}
		return map[string]any{"kinds": views, "head": r.Head()}, nil
	})
	srv.Register(mcp.Operation{
		Name: "register_list", NeedsRole: "reader", Area: register.Area,
		Summary: "one kind's records in the security register, a page at a time",
		Args: map[string]string{"kind": "the kind, as register_kinds names it", "offset": "optional, how many to skip",
			"limit": "optional, how many to return, at most 200"},
		Types:    map[string]string{"offset": "number", "limit": "number"},
		Keywords: []string{"register", "list", "records", "controls", "risks", "evidence"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		name, _ := a["kind"].(string)
		spec, ok := register.SpecOf(name)
		if !ok {
			return nil, &mcp.ArgumentError{Reason: "register_list needs arguments.kind, one of the kinds register_kinds names"}
		}
		offset, limit := numberArg(a, "offset", 0), numberArg(a, "limit", 50)
		if offset < 0 || limit < 1 || limit > 200 {
			return nil, &mcp.ArgumentError{Reason: "offset is 0 or more, and limit from 1 to 200"}
		}
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		entries, total, err := r.List(spec.Kind, offset, limit)
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": spec.Kind, "total": total, "offset": offset, "limit": limit,
			"records": entries, "head": r.Head()}, nil
	})
	srv.Register(mcp.Operation{
		Name: "register_show", NeedsRole: "reader", Area: register.Area,
		Summary:  "one record of the security register, by its identifier, with the hash it is stored under",
		Args:     map[string]string{"id": "the record's identifier: 32 hexadecimal characters"},
		Keywords: []string{"register", "show", "record", "control", "risk", "evidence"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		id, _ := a["id"].(string)
		if !register.ID(id).Valid() {
			return nil, &mcp.ArgumentError{Reason: "register_show needs arguments.id, a record's identifier of 32 hexadecimal characters"}
		}
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		e, err := r.Get(register.ID(id))
		if errors.Is(err, register.ErrNotFound) {
			return nil, &mcp.Refusal{Reason: "the register holds no record " + id}
		}
		return e, err
	})
}

// numberArg is a whole-number argument of an operation, or def when it was
// not given.
func numberArg(a map[string]any, name string, def int) int {
	if v, ok := a[name].(float64); ok {
		return int(v)
	}
	return def
}
