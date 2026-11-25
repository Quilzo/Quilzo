// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// The register's generic reads and its personal data, on the command line
// and the agent interface: a record's history, a kind filtered and
// exported as CSV, the data inventory, the erasure of a person, and the
// sweep of what retention ends.
//
// One implementation over every kind, read from the kinds' schemas, so a
// kind added later is listed, filtered, exported and followed through its
// history here without a line changed. Everything reads the register
// through internal/register and nothing else; the erasure and the sweep
// write through it, through registerWriter, with the policy asked as the
// caller and an entry in the audit log.

// parseFilters reads each --filter FIELD=VALUE; one that is not is a line
// misused, exit 2.
func parseFilters(raw []string) ([]register.Filter, error) {
	var out []register.Filter
	for _, s := range raw {
		f, err := register.ParseFilter(s)
		if err != nil {
			return nil, errMisused{err}
		}
		out = append(out, f)
	}
	return out, nil
}

// filterWords is the filters as a sentence says them.
func filterWords(filters []register.Filter) string {
	var parts []string
	for _, f := range filters {
		parts = append(parts, f.String())
	}
	return strings.Join(parts, " and ")
}

// registerFindError is a register's refusal of a filter or a top as a
// line misused, exit 2, and anything else as registerError answers it.
func registerFindError(err error) error {
	if errors.Is(err, register.ErrInvalid) {
		return errMisused{err}
	}
	return registerError(err)
}

// printNamed is what a record names beside it, a line each: the field, the
// pseudonym or digest, and what the side store holds of it.
func printNamed(named []register.Named) {
	if len(named) == 0 {
		return
	}
	fmt.Printf("\n  %swhat it names beside the register%s\n", bold, reset)
	for _, n := range named {
		said := n.Said
		if n.Erased != nil {
			said += ", " + n.Erased.At.Format("2 January 2006") + " (" + printable(n.Erased.Basis) + ")"
		}
		fmt.Printf("  %-28s %s  %s\n", printable(n.Field), n.Value, said)
	}
}

// registerHistoryCmd is `quilzo register history ID [--limit N]`.
func registerHistoryCmd(root string, args []string) error {
	fs := flag.NewFlagSet("register history", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "how many changes to show, newest first; 0 is every one")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errMisused{fmt.Errorf("usage: quilzo register history ID [--limit N]")}
	}
	if *limit < 0 {
		return errMisused{fmt.Errorf("--limit is 0 or more")}
	}
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	changes, err := r.History(register.ID(pos[0]), *limit)
	if err != nil {
		return registerError(err)
	}
	if w.JSON(map[string]any{"id": pos[0], "changes": changes, "head": r.Head()}) {
		return nil
	}
	for _, c := range changes {
		what := "changed"
		if c.New {
			what = "written"
		}
		by := string(c.By)
		if by == "" {
			by = "a service"
		}
		fmt.Printf("  %s  %s%s%s %s by %s\n      %s%s, stored as %s%s\n", c.At.At().Format("2 Jan 2006 15:04 UTC"), bold,
			shortHash(c.Commit), reset, what, by, dim, printable(c.Why), c.Object, reset)
	}
	return nil
}

// shortHash is the first twelve characters of a hash, as the screens show
// one beside its whole.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// registerExportCmd is `quilzo register export KIND [--filter F=V]...
// [--top N] [--out FILE]`.
func registerExportCmd(root string, args []string) error {
	fs := flag.NewFlagSet("register export", flag.ContinueOnError)
	var filters multiFlag
	fs.Var(&filters, "filter", "FIELD=VALUE: only the records whose field holds the value; more than one are all asked")
	top := fs.Int("top", 0, "only the N records rated highest, highest first, for a kind with a rating (risks)")
	outPath := fs.String("out", "", "write the CSV to this file, readable by its owner only, in place of standard output")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errMisused{fmt.Errorf("usage: quilzo register export KIND [--filter FIELD=VALUE]... [--top N] [--out FILE]")}
	}
	if *top < 0 {
		return errMisused{fmt.Errorf("--top is 0 or more")}
	}
	parsed, err := parseFilters(filters)
	if err != nil {
		return err
	}
	spec, err := specNamed(pos[0])
	if err != nil {
		return err
	}
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	entries, err := exportEntries(r, spec, parsed, *top)
	if err != nil {
		return registerFindError(err)
	}
	cols, rows, err := register.ExportRows(spec, entries)
	if err != nil {
		return err
	}
	if parsed == nil {
		parsed = []register.Filter{}
	}
	if w.JSON(map[string]any{"kind": spec.Kind, "filters": parsed, "columns": cols, "rows": rows, "head": r.Head()}) {
		return nil
	}
	var b bytes.Buffer
	if err := register.WriteCSV(&b, spec, entries); err != nil {
		return err
	}
	if *outPath == "" {
		_, err := os.Stdout.Write(b.Bytes())
		return err
	}
	if err := atomicfile.Write(*outPath, b.Bytes(), 0o600); err != nil {
		return err
	}
	w.Notes().Human("  %swrote %s to %s%s\n", dim, count(len(entries), string(spec.Kind)+" record"), *outPath, reset)
	return nil
}

// exportEntries is what an export holds: the kind's records the filters
// keep, and of those the top n by rating when n is more than none.
func exportEntries(r *register.Register, spec register.Spec, filters []register.Filter, top int) ([]register.Entry, error) {
	entries, _, err := r.Find(spec.Kind, filters, 0, 0)
	if err != nil {
		return nil, err
	}
	if top > 0 {
		zero, _ := spec.New().(register.Record)
		if _, rated := register.Rating(zero); zero == nil || !rated {
			return nil, fmt.Errorf("%w: a %s has no rating to put the highest first by; --top is for risks",
				register.ErrInvalid, strings.ToLower(string(spec.Kind)))
		}
		return register.Top(entries, top)
	}
	return entries, nil
}

// registerInventory is `quilzo register inventory`.
func registerInventory() error {
	inv := register.Inventory()
	if w.JSON(inv) {
		return nil
	}
	names := func(fs []register.InventoryField) string {
		if len(fs) == 0 {
			return "none"
		}
		var out []string
		for _, f := range fs {
			out = append(out, f.Field)
		}
		return strings.Join(out, ", ")
	}
	for _, k := range inv.Kinds {
		keep := "until a person erases them"
		if k.RetainDays > 0 {
			keep = fmt.Sprintf("%d days after a record last names them", k.RetainDays)
		}
		fmt.Printf("  %s%s%s (%s), %s\n", bold, k.Kind, reset, k.Collection, k.Class)
		fmt.Printf("    people:  %s\n    text:    %s\n    files:   %s\n    kept:    %s\n", names(k.People), names(k.Text),
			names(k.Files), keep)
		fmt.Printf("    readers: %s\n", strings.Join(k.Readers, "; "))
	}
	fmt.Printf("\n  %sthe subject map%s  %s\n", bold, reset, inv.SubjectMap)
	fmt.Printf("  %sthe side store%s   %s\n", bold, reset, inv.SideStore)
	fmt.Printf("  %san erasure%s       %s\n", bold, reset, inv.Erasure)
	fmt.Printf("  %sthe audit log%s    %s\n", bold, reset, inv.AuditLog)
	return nil
}

// registerEraseCmd is `quilzo register erase`.
func registerEraseCmd(root string, args []string) error {
	fs := flag.NewFlagSet("register erase", flag.ContinueOnError)
	subject := fs.String("subject", "", "the pseudonym of the person to erase")
	name := fs.String("name", "", "the name the systems that name them use, found in the subject map")
	basis := fs.String("basis", "", "the ground it is erased on: "+strings.Join(register.ErasureBasis("").Values(), ", "))
	requested := fs.String("requested-by", "", "who asked for it: a pseudonym, or subject for the person themselves; empty is you")
	yes := fs.Bool("yes", false, "erase them; at a terminal, without this, only say what would go")
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	if (*subject == "") == (*name == "") {
		return errMisused{fmt.Errorf("name the person by --subject PSEUDONYM or by --name, one of the two")}
	}
	if !slices.Contains(register.ErasureBasis("").Values(), *basis) {
		return errMisused{fmt.Errorf("--basis is one of %s", strings.Join(register.ErasureBasis("").Values(), ", "))}
	}
	if *subject != "" && !register.ID(*subject).Valid() {
		return errMisused{fmt.Errorf("--subject is a pseudonym: 32 hexadecimal characters")}
	}
	c := resolveCaller(root, flagToken)
	r, by, err := registerWriter(root, c)
	if err != nil {
		return err
	}
	id := register.ID(*subject)
	if *name != "" {
		found, ok, err := r.Side().Lookup(*name)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound{fmt.Errorf("the subject map names nobody by that name; a person erased already is " +
				"found by their pseudonym, in the Erasure records")}
		}
		id = register.ID(found)
	}
	var asked register.ID
	switch *requested {
	case "":
	case "subject":
		asked = id
	default:
		if !register.ID(*requested).Valid() {
			return errMisused{fmt.Errorf("--requested-by is a pseudonym, or subject for the person themselves")}
		}
		asked = register.ID(*requested)
	}
	about, err := r.Side().About(string(id))
	if err != nil {
		return err
	}
	if erasureHeld(*yes, fmt.Sprintf("this would erase the person behind %s: the subject map's entry for them and %s "+
		"about them, and write the signed record of it", id, count(len(about), "entry of text and files"))) {
		return nil
	}
	eligible := 1
	if pol, err := loadPolicy(root); err == nil {
		spec, _ := register.SpecOf(string(register.KindErasure))
		eligible = max(register.Eligible(pol, auth.ActApprove, spec.Resource()), 1)
	}
	rc, err := r.Erase(by, register.ErasureRequest{Subject: id, Basis: register.ErasureBasis(*basis),
		RequestedBy: asked, Eligible: eligible, Evidence: consoleEvidence(c)})
	if err != nil {
		return registerError(err)
	}
	if w.JSON(map[string]any{"erasure": register.ErasureID(id), "subject": id, "receipt": rc}) {
		return nil
	}
	fmt.Printf("  erased the person behind %s: the subject map's entry and %s about them\n", id,
		count(len(about), "entry of text and files"))
	fmt.Printf("  %sthe record of it is %s, in commit %s; the register still checks%s\n", dim,
		register.ErasureID(id), rc.Commit, reset)
	return nil
}

// consoleEvidence is the authentication evidence a decision made at the
// command line is bound to: who the program proved the caller to be, and
// by which credential. It is weaker than a passkey's assertion over the
// record's hash, and the approval's rule says which it was.
func consoleEvidence(c *Caller) []byte {
	return []byte("console\x00" + c.Name + "\x00" + c.Credential + "\x00" + strconv.FormatBool(c.Verified))
}

// registerExpireCmd is `quilzo register expire`.
func registerExpireCmd(root string) error {
	c := resolveCaller(root, flagToken)
	r, by, err := registerWriter(root, c)
	if err != nil {
		return err
	}
	n, err := expireSide(root, r, by.Name, by.Kind)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"expired": n}) {
		return nil
	}
	fmt.Printf("  %s whose retention had ended\n", count(n, "entry of text and files deleted"))
	return nil
}

// expireSide runs the side store's retention sweep and records what it
// deleted in the audit log, as who ran it. A sweep that found nothing is
// not recorded: it ran every quarter of an hour, and did nothing.
func expireSide(root string, r *register.Register, who string, kind audit.Kind) (int, error) {
	if _, err := os.Stat(r.Side().Dir()); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	n, err := r.ExpireSide()
	if n > 0 {
		if aerr := recordE(root, audit.Record{Action: "register.expire", Resource: register.Area,
			Outcome: audit.Success, Principal: who, Kind: kind, Verified: true,
			Detail: map[string]string{"entries": strconv.Itoa(n), "basis": "retention"}}); aerr != nil && err == nil {
			err = aerr
		}
	}
	return n, err
}

// registerJobs is the register's work on the server's upkeep timer: the
// side store's retention, enforced every quarter of an hour, so a kind's
// declared period is a thing the program does and not a sentence.
func registerJobs(root string) []upkeep.Job {
	return []upkeep.Job{{Name: "register-retention", Do: func(now time.Time) (int, error) {
		if _, err := os.Stat(filepath.Join(root, "side")); errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		r, err := openRegister(root)
		if err != nil {
			return 0, err
		}
		// The upkeep loop's moment is the sweep's, so the sweep is the
		// same on a test's clock as on the server's.
		r.Now = func() time.Time { return now }
		return expireSide(root, r, "upkeep", audit.KindService)
	}}}
}

// registerMayRead is whether a caller at the agent interface may read the
// register: a view of its area, as every surface asks, and not an app
// connected through OAuth unless the organisation switched that on.
//
// The register holds restricted records (incidents, board decisions, who
// was erased), and an app a person connected with a click is a model's
// vendor reading them under that person's grant. Which of its records a
// model route may be sent is decided by data classes it does not yet
// declare, so until it does, an app reads nothing here without a recorded
// decision: the mcp.register_for_apps setting.
func registerMayRead(root string, c *Caller) error {
	if err := authorise(root, c, auth.ActView, register.Area); err != nil {
		return &mcp.Refusal{Reason: err.Error()}
	}
	if (c.Client != "" || c.Grant != "") && !mustConfig(root).Bool("mcp.register_for_apps") {
		return &mcp.Refusal{Reason: "an app connected through OAuth does not read the security register unless the " +
			"organisation switches it on: quilzo config set mcp.register_for_apps true, with the risk accepted"}
	}
	return nil
}

// filterArg is an operation's filter argument: one FIELD=VALUE, or a list
// of them.
func filterArg(a map[string]any) ([]register.Filter, error) {
	var raw []string
	switch v := a["filter"].(type) {
	case nil:
	case string:
		raw = []string{v}
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, &mcp.ArgumentError{Reason: "filter is FIELD=VALUE, or a list of them"}
			}
			raw = append(raw, s)
		}
	default:
		return nil, &mcp.ArgumentError{Reason: "filter is FIELD=VALUE, or a list of them"}
	}
	var out []register.Filter
	for _, s := range raw {
		f, err := register.ParseFilter(s)
		if err != nil {
			return nil, &mcp.ArgumentError{Reason: err.Error()}
		}
		out = append(out, f)
	}
	return out, nil
}

// registerGenericOps is the register's other reads on the agent interface,
// the command line's history, export and inventory, gated as its first
// three are. Nothing here writes: an erasure is a person's decision, and a
// caller at the agent interface is a model's client.
func registerGenericOps(srv *mcp.Server, root string, caller *Caller, may func() error) {
	srv.Register(mcp.Operation{
		Name: "register_history", NeedsRole: "reader", Area: register.Area,
		Summary:  "the commits that changed one record of the security register, newest first",
		Detail:   "Each change says when, why, under whose pseudonym, and the hash the record was stored under after it.",
		Args:     map[string]string{"id": "the record's identifier: 32 hexadecimal characters", "limit": "optional, how many changes"},
		Types:    map[string]string{"limit": "number"},
		Keywords: []string{"register", "history", "changes", "audit", "record"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		id, _ := a["id"].(string)
		if !register.ID(id).Valid() {
			return nil, &mcp.ArgumentError{Reason: "register_history needs arguments.id, a record's identifier of 32 hexadecimal characters"}
		}
		limit := numberArg(a, "limit", 0)
		if limit < 0 {
			return nil, &mcp.ArgumentError{Reason: "limit is 0 or more"}
		}
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		changes, err := r.History(register.ID(id), limit)
		if errors.Is(err, register.ErrNotFound) {
			return nil, &mcp.Refusal{Reason: "the register holds no record " + id}
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "changes": changes, "head": r.Head()}, nil
	})
	srv.Register(mcp.Operation{
		Name: "register_export", NeedsRole: "reader", Area: register.Area,
		Summary: "one kind of the security register as a table: a column per field, every cell safe for a spreadsheet",
		Detail: "The same table as `quilzo register export`, as columns and rows. filter keeps the records whose " +
			"field holds a value; top keeps the risks rated highest. Free text is its digest, as in the record.",
		Args: map[string]string{"kind": "the kind, as register_kinds names it",
			"filter": "optional, FIELD=VALUE, or a list of them", "top": "optional, the N rated highest (risks)",
			"limit": "optional, how many rows, at most 1000"},
		Types:    map[string]string{"top": "number", "limit": "number"},
		Keywords: []string{"register", "export", "csv", "spreadsheet", "risks", "top risks"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		name, _ := a["kind"].(string)
		spec, ok := register.SpecOf(name)
		if !ok {
			return nil, &mcp.ArgumentError{Reason: "register_export needs arguments.kind, one of the kinds register_kinds names"}
		}
		filters, ferr := filterArg(a)
		if ferr != nil {
			return nil, ferr
		}
		top, limit := numberArg(a, "top", 0), numberArg(a, "limit", 1000)
		if top < 0 || limit < 1 || limit > 1000 {
			return nil, &mcp.ArgumentError{Reason: "top is 0 or more, and limit from 1 to 1000"}
		}
		r, err := openRegister(root)
		if err != nil {
			return nil, err
		}
		entries, err := exportEntries(r, spec, filters, top)
		if errors.Is(err, register.ErrInvalid) {
			return nil, &mcp.ArgumentError{Reason: err.Error()}
		}
		if err != nil {
			return nil, err
		}
		total := len(entries)
		if len(entries) > limit {
			entries = entries[:limit]
		}
		cols, rows, err := register.ExportRows(spec, entries)
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": spec.Kind, "filters": filters, "columns": cols, "rows": rows, "total": total,
			"head": r.Head()}, nil
	})
	srv.Register(mcp.Operation{
		Name: "register_inventory", NeedsRole: "reader", Area: register.Area,
		Summary: "the data inventory of the security register: what each kind holds about people, how long, and who reads it",
		Detail: "Generated from the kinds' schemas and the access policy's roles, for a privacy officer's record of " +
			"processing: the fields naming a person by pseudonym, the free text and raw files kept in the erasable " +
			"side store, their retention, and the jobs and roles that may read each kind.",
		Keywords: []string{"register", "inventory", "privacy", "personal data", "gdpr", "record of processing", "works council"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		return register.Inventory(), nil
	})
}
