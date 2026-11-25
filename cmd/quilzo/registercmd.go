// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
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
			"  quilzo register list KIND [--filter FIELD=VALUE]... [--offset N] [--limit N]  one kind's records, in the\n" +
			"                                            order of their identifiers, those whose field holds the value\n" +
			"  quilzo register show ID                  one record, with the hash it is stored under and what it names\n" +
			"                                            beside it: a subject or text erased says so\n" +
			"  quilzo register history ID [--limit N]   the commits that changed a record, newest first\n" +
			"  quilzo register export KIND [--filter FIELD=VALUE]... [--top N] [--out FILE]  a kind as CSV, a column per\n" +
			"                                            field and every cell safe for a spreadsheet; --top N the risks\n" +
			"                                            rated highest\n" +
			"  quilzo register inventory                the data inventory: what each kind holds about people, how long\n" +
			"                                            and who may read it, for a record of processing\n" +
			"  quilzo register erase --subject ID | --name NAME --basis BASIS  ask for a person's erasure from beside\n" +
			"                                            the register; somebody else decides it (quilzo approval approve)\n" +
			"                                            and the signed record of it is written; the register still\n" +
			"                                            checks. --requested-by subject for the person, or ID; --yes\n" +
			"  quilzo register expire                   delete now the text and files each kind's retention has ended,\n" +
			"                                            as the server does every quarter of an hour\n",
		run: cmdRegister,
		// Reading the register is a view of the compliance area's part of
		// the policy, which a role over the site reaches only as
		// administrator: somebody who may read the site's pages does not
		// thereby read its risks.
		//
		// The command's own row is the widest of its lines, deciding an
		// erasure, so a line added later arrives guarded, and each line
		// that reads narrows it to a view; a bare `quilzo register` lists
		// the kinds, and is asked as that line is.
		needs: map[string]need{
			"register":       {action: auth.ActApprove, hint: "an erasure is decided by somebody who may approve the register's records"},
			"register kinds": {action: auth.ActView}, "register list": {action: auth.ActView},
			"register show": {action: auth.ActView}, "register history": {action: auth.ActView},
			"register export": {action: auth.ActView}, "register inventory": {action: auth.ActView},
			"register proposals": {action: auth.ActView},
			"register erase":     {action: auth.ActApprove, hint: "an erasure is decided by somebody who may approve the register's records"},
			// Expiring early what retention ends writes what the server would.
			"register expire": {action: auth.ActEditDraft}},
		bare: "kinds",
		area: register.Area,
		reads: [][]string{{"register", "kinds"}, {"register", "list", "Control"}, {"register", "proposals"},
			{"register", "export", "Control"}, {"register", "inventory"}},
		absent: []string{"register", "show", "00000000000000000000000000000000"},
		ops:    registerRegisterOps,
		jobs:   registerJobs,
		notForRuns: "the register holds restricted records, and which of them a run may read is decided by the " +
			"data classes its model route accepts, which are not yet declared; an outside agent reads them " +
			"under its person's own grant",
	})
}

func cmdRegister(root string, args []string) error {
	// Bare, it runs the line it is asked by (cliModule.bare), so the two
	// cannot drift apart.
	if len(args) == 0 {
		args = []string{bareRuns["register"]}
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
		var filters multiFlag
		fs.Var(&filters, "filter", "FIELD=VALUE: only the records whose field holds the value; more than one are all asked")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo register list KIND [--filter FIELD=VALUE]... [--offset N] [--limit N]; " +
				"`quilzo register kinds` names the kinds")}
		}
		if *offset < 0 || *limit < 1 {
			return errMisused{fmt.Errorf("--offset is 0 or more and --limit 1 or more")}
		}
		parsed, err := parseFilters(filters)
		if err != nil {
			return err
		}
		return registerList(root, pos[0], parsed, *offset, *limit)
	case "show":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo register show ID")}
		}
		id, err := identifierWord(pos[0], "a record", "register list KIND")
		if err != nil {
			return err
		}
		return registerShow(root, string(id))
	case "proposals":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return registerProposals(root)
	case "history":
		return registerHistoryCmd(root, args[1:])
	case "export":
		return registerExportCmd(root, args[1:])
	case "inventory":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return registerInventory()
	case "erase":
		return registerEraseCmd(root, args[1:])
	case "expire":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return registerExpireCmd(root)
	default:
		return errMisused{fmt.Errorf("unknown register command %q; try kinds, list, show, history, export, inventory, "+
			"proposals, erase or expire", args[0])}
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

// registerWriter is the register of the store at root, wired to write,
// and the caller as the register names a writer.
//
// Its audit entries go to this store's audit log, and it writes nothing
// while that log cannot take an entry (auditReady); its policy gate is
// authorise, the caller's own check with their credential's limits, as
// every command asks. A module's command writes the register through this
// and register.Put, and nothing else: the register's own invariants, the
// receipt and the one commit for a batch come with it.
func registerWriter(root string, c *Caller) (*register.Register, register.Actor, error) {
	s, err := open(root)
	if err != nil {
		return nil, register.Actor{}, err
	}
	r := register.Open(s)
	r.Audit = func(rec audit.Record) error { return recordE(root, rec) }
	r.Ready = func() error { return auditReady(root) }
	by := register.Actor{Name: c.Name, Kind: c.Kind, Verified: c.Verified, Model: c.Model,
		May: func(act auth.Action, resource string) error { return authorise(root, c, act, resource) }}
	// A person or a service is named in the record by their pseudonym,
	// minted in the subject map the first time they write, so that what
	// they wrote is theirs without their name in a store that cannot
	// forget it, and a person's proposal is decided by somebody the
	// register can tell apart from them. A model proposes under the name
	// of its agent, and has none.
	if typ, ok := subjectTypeOf(c); ok {
		id, err := r.SubjectFor(c.Name, typ)
		if err != nil {
			return nil, register.Actor{}, fmt.Errorf("the subject map cannot name the writer: %w", err)
		}
		by.Subject = id
	}
	return r, by, nil
}

// subjectTypeOf is what sort of subject a caller is in the subject map: a
// person, or a service's account. A model, and a caller with no name, is
// none.
func subjectTypeOf(c *Caller) (register.SubjectType, bool) {
	if strings.TrimSpace(c.Name) == "" {
		return "", false
	}
	switch c.Kind {
	case audit.KindHuman:
		return "person", true
	case audit.KindService:
		return "service-account", true
	}
	return "", false
}

// mayReadRegisterAt is nil unless ref names the register, and then asks
// whether the caller may read it, as its own surfaces ask. A command that
// reads whatever ref it is told to (`quilzo log --ref`) asks this first: the
// register's history is what was written, why and under whose pseudonym,
// and a reader of the site reading it read the compliance area's records.
func mayReadRegisterAt(root string, s *store.Store, ref string) error {
	if !register.Holds(s, ref) {
		return nil
	}
	if err := authorise(root, resolveCaller(root, flagToken), auth.ActView, register.Area); err != nil {
		return errBlocked{err}
	}
	return nil
}

// identifierWord is a word of the command line as a record's identifier,
// and a word no record can be called refused as the command line's mistake,
// exit 2: of names what the identifier is of, and listed the line that
// shows the ones there are.
//
// `quilzo evidence show ab` refuses the word so (fileName), the built-in
// commands refuse an id of the wrong shape so (`agent receipt ab`, `feature
// approve ab`), and the agent interface refuses it as an argument. Every
// other line of the modules looked the word up: `register show ab` said "no
// such record in the register: "ab" is not a record's identifier" and
// exited 4, the code of a record that is not there, and so did `register
// history`, the approvals' show, check, reject, approve and review, and the
// programme's approve, run, explain and replay. An identifier of the right
// shape that names nothing is still not found, 4.
func identifierWord(word, of, listed string) (register.ID, error) {
	if id := register.ID(word); id.Valid() {
		return id, nil
	}
	return "", errMisused{fmt.Errorf("%q is not %s's identifier, which is 32 hexadecimal characters; `quilzo %s` shows them",
		clip(word, 40), of, listed)}
}

// registerError is an error of the register as the command line answers
// it: a refusal by the access policy, or a model's write, exits 3 as every
// refusal by a gate does; a record that is not there exits 4; the rest are
// a command that ran and failed.
func registerError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, register.ErrRefused), errors.Is(err, register.ErrModel):
		return errBlocked{err}
	case errors.Is(err, register.ErrNotFound):
		return errNotFound{err}
	}
	return err
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

func registerList(root, kind string, filters []register.Filter, offset, limit int) error {
	spec, err := specNamed(kind)
	if err != nil {
		return err
	}
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	entries, total, err := r.Find(spec.Kind, filters, offset, limit)
	if err != nil {
		return registerFindError(err)
	}
	if entries == nil {
		entries = []register.Entry{}
	}
	if filters == nil {
		filters = []register.Filter{}
	}
	if w.JSON(map[string]any{"kind": spec.Kind, "total": total, "offset": offset, "limit": limit,
		"filters": filters, "records": entries, "head": r.Head()}) {
		return nil
	}
	if total == 0 {
		if len(filters) > 0 {
			fmt.Printf("  the register holds no %s records with %s\n", spec.Kind, printable(filterWords(filters)))
			return nil
		}
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
	if err != nil {
		return registerError(err)
	}
	named := r.Named(e.Record)
	if named == nil {
		named = []register.Named{}
	}
	if w.JSON(struct {
		register.Entry
		Named []register.Named `json:"named"`
	}{e, named}) {
		return nil
	}
	fields, _ := json.MarshalIndent(e.Record, "  ", "  ")
	fmt.Printf("  %s%s%s %s\n", bold, e.Kind, reset, e.ID)
	fmt.Printf("  %sstored as %s, written %s, changed %s%s\n", dim, e.Object,
		e.Created.At().Format(time.RFC3339), e.Updated.At().Format(time.RFC3339), reset)
	fmt.Printf("  %s\n", printable(string(fields)))
	printNamed(named)
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
// one list of what waits for a person (approvalscmd.go), read from the
// store that list reads, which a server holds and a command opens once.
func registerWaiting(held func() (*store.Store, error)) func() ([]waitlist.Proposed, error) {
	return func() ([]waitlist.Proposed, error) {
		s, err := held()
		if err != nil {
			return nil, err
		}
		list, err := register.Open(s).Proposals()
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
	may := func() error { return registerMayRead(root, caller) }
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
			"limit":  "optional, how many to return, at most 200",
			"filter": "optional, FIELD=VALUE: only the records whose field holds the value"},
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
		filters, ferr := filterArg(a)
		if ferr != nil {
			return nil, ferr
		}
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		entries, total, err := r.Find(spec.Kind, filters, offset, limit)
		if errors.Is(err, register.ErrInvalid) {
			return nil, &mcp.ArgumentError{Reason: err.Error()}
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": spec.Kind, "total": total, "offset": offset, "limit": limit,
			"filters": filters, "records": entries, "head": r.Head()}, nil
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
		if err != nil {
			return nil, err
		}
		return struct {
			register.Entry
			Named []register.Named `json:"named"`
		}{e, r.Named(e.Record)}, nil
	})
	registerGenericOps(srv, root, caller, may)
}

// numberArg is a whole-number argument of an operation, or def when it was
// not given.
func numberArg(a map[string]any, name string, def int) int {
	if v, ok := a[name].(float64); ok {
		return int(v)
	}
	return def
}
