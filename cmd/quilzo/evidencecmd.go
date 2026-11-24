// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
)

// `quilzo ingest` and `quilzo evidence`: files brought in as evidence.
//
// ingest seals a file by its hash in the raw evidence store, reads it as
// hostile and writes what it yields through register.Put, graded by how it
// came in; evidence lists the sealed files, shows one with what was read
// from it, and verifies them, the facts of a file whose bytes have been
// erased included. Column maps and pinned keys, which a person decides, are
// made here too. The module's screens are internal/admin/evidencescreen.go
// and its routes internal/api/evidenceapi.go.

func init() {
	ops := func(srv *mcp.Server, root string, caller *Caller) { registerEvidenceOps(srv, root, caller) }
	const heading = "evidence in (files sealed by their hash, read as hostile, graded by how they came, checked after they have gone)"
	why := "the register holds restricted records, and which of them a run may read or write is decided by the data " +
		"classes its model route accepts, which are not yet declared; an outside agent works under its person's own grant"
	registerCLI(cliModule{
		module:  "evidence",
		command: "ingest",
		heading: heading,
		help: "  quilzo ingest FORMAT FILE [--source NAME] [--map NAME] [--preview]  seal a file by its hash, read it and\n" +
			"                                            write what it yields, graded by how it came; --preview writes nothing\n" +
			"  quilzo ingest formats                    the formats read, and what each one reads\n",
		run: cmdIngest,
		needs: map[string]need{"ingest": {action: auth.ActEditDraft, hint: "a file brought in is written to the register"},
			"ingest formats": {action: auth.ActView}},
		area:       register.Area,
		reads:      [][]string{{"ingest", "formats"}},
		absent:     []string{"ingest", "ocsf", "/nonexistent/findings.json", "--preview"},
		ops:        ops,
		notForRuns: why,
	})
	registerCLI(cliModule{
		module:  "evidence",
		command: "evidence",
		heading: heading,
		help: "  quilzo evidence list [--offset N] [--limit N]  the files sealed, with each one's grade and what it yielded\n" +
			"  quilzo evidence show FILE                one sealed file, by its digest or identifier, with what was read\n" +
			"  quilzo evidence verify [FILE]            check each seal, each list of what was read and every fact it\n" +
			"                                            names, whether or not the raw file is still kept\n" +
			"  quilzo evidence expire                   erase the raw files whose time to be kept is up; their facts still check\n" +
			"  quilzo evidence maps | keys              the column maps a person confirmed, or the keys a person pinned\n" +
			"  quilzo evidence draft-map FORMAT FILE --kind KIND [--name NAME] [--sheet NAME]  draft a column map\n" +
			"                                            from a table's headings, with the rows it would read\n" +
			"  quilzo evidence confirm-map MAPFILE      confirm a column map as yours, having looked at what it reads\n" +
			"  quilzo evidence pin NAME KEYFILE [--keyid ID] [--title TEXT]  pin a third party's public key, which\n" +
			"                                            signed files are verified against\n",
		run: cmdEvidence,
		needs: map[string]need{"evidence": {action: auth.ActView},
			"evidence expire":      {action: auth.ActEditDraft, hint: "erasing raw files changes what is kept beside the register"},
			"evidence confirm-map": {action: auth.ActEditDraft, hint: "a confirmed column map is written to the register"},
			"evidence pin":         {action: auth.ActEditDraft, hint: "a pinned key is written to the register"}},
		area:       register.Area,
		reads:      [][]string{{"evidence", "list"}, {"evidence", "verify"}, {"evidence", "maps"}, {"evidence", "keys"}},
		absent:     []string{"evidence", "show", "sha256:" + strings.Repeat("0", 64)},
		notForRuns: why,
	})
	// The admin and the API open the register themselves; this is how
	// their writes are recorded where the command line's are.
	evidence.Recorder = func(reg *register.Register) {
		root := reg.Store.Root()
		reg.Audit = func(rec audit.Record) error { return recordE(root, rec) }
		reg.Ready = func() error { return auditReady(root) }
	}
}

// evidenceIngester is the ingester of the store at root, wired to write as
// the caller.
func evidenceIngester(root string, c *Caller) (*evidence.Ingester, register.Actor, error) {
	r, by, err := registerWriter(root, c)
	if err != nil {
		return nil, register.Actor{}, err
	}
	return evidence.New(r), by, nil
}

// evidenceReader is the ingester of the store at root, for reading.
func evidenceReader(root string) (*evidence.Ingester, error) {
	r, err := openRegister(root)
	if err != nil {
		return nil, err
	}
	return evidence.New(r), nil
}

// evidenceError is an error of the evidence module as the command line
// answers it: a file that cannot be read or a map that is not confirmed is
// misused (2), a file signed by no pinned key is refused (3), and the
// register's own errors are answered as registerError answers them.
func evidenceError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, evidence.ErrUnpinned):
		return errBlocked{err}
	case errors.Is(err, fs.ErrNotExist):
		return errNotFound{err}
	case errors.Is(err, evidence.ErrUnreadable), errors.Is(err, evidence.ErrNoMap):
		return errMisused{err}
	}
	return registerError(err)
}

func cmdIngest(root string, args []string) error {
	if len(args) > 0 && args[0] == "formats" {
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return ingestFormats()
	}
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	source := fs.String("source", "", "the source the facts are filed under")
	mapName := fs.String("map", "", "the confirmed column map a table is read through")
	preview := fs.Bool("preview", false, "read the file and write nothing")
	var pos []string
	if err := parseFlags(fs, args, &pos, 2); err != nil {
		return err
	}
	if len(pos) != 2 {
		return errMisused{fmt.Errorf("usage: quilzo ingest FORMAT FILE [--source NAME] [--map NAME] [--preview]; " +
			"`quilzo ingest formats` names the formats")}
	}
	format, ok := evidence.FormatNamed(pos[0])
	if !ok {
		return errMisused{fmt.Errorf("%q is not a format this reads; `quilzo ingest formats` names them", clip(pos[0], 40))}
	}
	body, err := readInput(pos[1], evidence.MaxFile)
	if err != nil {
		return evidenceError(err)
	}
	caller := resolveCaller(root, flagToken)
	g, by, err := evidenceIngester(root, caller)
	if err != nil {
		return err
	}
	in := evidence.Input{Format: format, Body: body, Source: *source, By: caller.Kind}
	if err := g.Prepare(&in, *mapName); err != nil {
		return evidenceError(err)
	}
	if format == evidence.FormatCSV || format == evidence.FormatXLSX || format == evidence.FormatJSON {
		if in.Map == nil {
			return errMisused{fmt.Errorf("%w; `quilzo evidence draft-map %s FILE --kind KIND` drafts one, "+
				"and `quilzo evidence confirm-map` confirms it", evidence.ErrNoMap, format)}
		}
	}
	if *preview {
		b, err := evidence.Read(in)
		if err != nil {
			return evidenceError(err)
		}
		return printBatch(b, nil)
	}
	res, err := g.Ingest(by, "", in)
	if err != nil {
		return evidenceError(err)
	}
	return printBatch(res.Batch, &res)
}

func ingestFormats() error {
	formats := evidence.Formats()
	if w.JSON(map[string]any{"formats": formats}) {
		return nil
	}
	for _, f := range formats {
		also := ""
		if len(f.Also) > 0 {
			also = " (or " + strings.Join(f.Also, ", ") + ")"
		}
		fmt.Printf("  %s%-10s%s %s%s\n", bold, f.Format, reset, f.Reads, also)
	}
	return nil
}

// printBatch says what a file yielded, and what an import wrote of it.
func printBatch(b *evidence.Batch, res *evidence.Result) error {
	if res == nil {
		if w.JSON(map[string]any{"preview": true, "batch": b}) {
			return nil
		}
	} else if w.JSON(res) {
		return nil
	}
	fmt.Printf("  %s%s%s file %s, %d bytes, graded %s%s%s\n", bold, b.Format, reset, b.Digest, b.Size, bold, b.Grade, reset)
	fmt.Printf("  %s%d record(s) read under the source %s, %d of them from a part a person opening the file would not see%s\n",
		dim, len(b.Facts), b.Source.Name, b.Tainted(), reset)
	shown := 0
	for _, f := range b.Facts {
		if f.Kind != register.KindObservation && f.Kind != register.KindEvidence && shown >= 20 {
			continue
		}
		if shown == 20 {
			fmt.Printf("    %sand %d more%s\n", dim, len(b.Facts)-shown, reset)
			break
		}
		taint := ""
		if f.Taint != "" {
			taint = "  [" + string(f.Taint) + "]"
		}
		fmt.Printf("    %-11s %-40s %-24s %s%s%s%s\n", f.Kind, truncate(printable(f.Name), 40), truncate(printable(f.Value), 24),
			dim, printable(f.Place), reset, taint)
		shown++
	}
	for _, fl := range b.Flags {
		fmt.Printf("  %shidden in the file: %s at %s%s\n", dim, fl.Taint, printable(fl.Where), reset)
	}
	for _, n := range b.Notes {
		fmt.Printf("  %s%s%s\n", dim, printable(n), reset)
	}
	if len(b.Proposed) > 0 {
		fmt.Printf("  %s%d proposal(s) wait for a person: `quilzo register proposals`%s\n", dim, len(b.Proposed), reset)
	}
	switch {
	case res == nil:
		fmt.Printf("\n  %sa preview: nothing was sealed and nothing was written%s\n", dim, reset)
	case res.Receipt.Commit == "":
		fmt.Printf("\n  %sthe register already holds every record this file yields; nothing was written%s\n", dim, reset)
	default:
		fmt.Printf("\n  %swrote %d record(s), %d unchanged, in %s%s\n", dim, len(res.Receipt.Written), res.Receipt.Unchanged,
			res.Receipt.Commit, reset)
	}
	return nil
}

func cmdEvidence(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("evidence list", flag.ContinueOnError)
		offset := fs.Int("offset", 0, "how many files to skip")
		limit := fs.Int("limit", 50, "how many files to show")
		if err := parseFlags(fs, args[1:], nil, 0); err != nil {
			return err
		}
		if *offset < 0 || *limit < 1 {
			return errMisused{fmt.Errorf("--offset is 0 or more and --limit 1 or more")}
		}
		return evidenceList(root, *offset, *limit)
	case "show":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo evidence show FILE, by its digest or its identifier")}
		}
		return evidenceShow(root, pos[0])
	case "verify":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		return evidenceVerify(root, pos)
	case "expire":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return evidenceExpire(root)
	case "maps", "keys":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		kind := register.KindColumnMap
		if args[0] == "keys" {
			kind = register.KindPinnedKey
		}
		return evidenceRecords(root, kind)
	case "draft-map":
		fs := flag.NewFlagSet("evidence draft-map", flag.ContinueOnError)
		kind := fs.String("kind", "", "the kind of record the table is read into")
		name := fs.String("name", "", "the map's machine name")
		sheet := fs.String("sheet", "", "the worksheet a workbook is read from")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 2); err != nil {
			return err
		}
		if len(pos) != 2 || *kind == "" {
			return errMisused{fmt.Errorf("usage: quilzo evidence draft-map FORMAT FILE --kind KIND [--name NAME] [--sheet NAME]")}
		}
		return evidenceDraftMap(pos[0], pos[1], *kind, *name, *sheet)
	case "confirm-map":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo evidence confirm-map MAPFILE, the map as `quilzo evidence draft-map --json` writes it")}
		}
		return evidenceConfirmMap(root, pos[0])
	case "pin":
		fs := flag.NewFlagSet("evidence pin", flag.ContinueOnError)
		keyid := fs.String("keyid", "", "the identifier signed envelopes name the key by")
		title := fs.String("title", "", "whose key it is")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 2); err != nil {
			return err
		}
		if len(pos) != 2 {
			return errMisused{fmt.Errorf("usage: quilzo evidence pin NAME KEYFILE [--keyid ID] [--title TEXT]")}
		}
		return evidencePin(root, pos[0], pos[1], *keyid, *title)
	default:
		return errMisused{fmt.Errorf("unknown evidence command %q; try list, show, verify, expire, maps, keys, draft-map, confirm-map or pin", clip(args[0], 40))}
	}
}

func evidenceList(root string, offset, limit int) error {
	g, err := evidenceReader(root)
	if err != nil {
		return err
	}
	files, total, err := g.Files(offset, limit)
	if err != nil {
		return err
	}
	if files == nil {
		files = []evidence.File{}
	}
	if w.JSON(map[string]any{"files": files, "total": total, "offset": offset, "limit": limit}) {
		return nil
	}
	if total == 0 {
		fmt.Println("  no file has been brought in as evidence; `quilzo ingest FORMAT FILE` brings one")
		return nil
	}
	for _, f := range files {
		held := "kept"
		if !f.Held {
			held = "erased"
		}
		fmt.Printf("  %s%s%s  %-9s %-10s %5d facts %4d tainted  %s, received %s\n", bold, string(f.Record.Digest)[:19], reset,
			f.Record.Format, f.Record.Grade, f.Record.Facts, f.Record.Tainted, held, f.Record.Received.At().Format("2 Jan 2006"))
	}
	if shown := offset + len(files); shown < total {
		fmt.Printf("\n  %s%d to %d of %d; --offset %d for the next%s\n", dim, offset+1, shown, total, shown, reset)
	}
	return nil
}

func evidenceShow(root, name string) error {
	if err := fileName(name); err != nil {
		return err
	}
	g, err := evidenceReader(root)
	if err != nil {
		return err
	}
	f, err := g.FileNamed(name)
	if err != nil {
		return evidenceError(err)
	}
	var lines []string
	if list, err := g.Raw.Yield(f.Record.Yield); err == nil {
		lines = strings.Split(strings.TrimRight(string(list), "\n"), "\n")
	}
	if w.JSON(map[string]any{"file": f, "read": lines}) {
		return nil
	}
	rf := f.Record
	fmt.Printf("  %s%s%s %s\n", bold, rf.Format, reset, rf.Digest)
	fmt.Printf("  %sgraded %s, %d bytes, %d facts, %d of them tainted, received %s%s\n", dim, rf.Grade, rf.Size, rf.Facts,
		rf.Tainted, rf.Received.At().Format(time.RFC3339), reset)
	if f.Sealed != nil {
		if f.Held {
			fmt.Printf("  %skept until %s%s\n", dim, f.Sealed.Until.Format("2 January 2006"), reset)
		} else {
			fmt.Printf("  %serased on %s, when its time to be kept was up%s\n", dim, f.Sealed.Erased.Format("2 January 2006"), reset)
		}
	}
	if rf.Signer != "" {
		fmt.Printf("  %ssigned by the pinned key %s%s\n", dim, rf.Signer, reset)
	}
	for _, l := range lines {
		fmt.Printf("    %s\n", printable(l))
	}
	return nil
}

// fileName refuses what is neither a sealed file's identifier nor a digest:
// a word like that is a misused command, not a file that is not there.
func fileName(name string) error {
	if register.ID(name).Valid() || reFileDigest.MatchString(name) {
		return nil
	}
	return errMisused{fmt.Errorf("%q is neither a sealed file's identifier (32 hexadecimal characters) nor its digest "+
		"(sha256: and 64); `quilzo evidence list` names them", clip(name, 80))}
}

var reFileDigest = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)

func evidenceVerify(root string, names []string) error {
	for _, n := range names {
		if err := fileName(n); err != nil {
			return err
		}
	}
	g, err := evidenceReader(root)
	if err != nil {
		return err
	}
	checks, err := g.Verify(names...)
	if err != nil {
		return evidenceError(err)
	}
	if checks == nil {
		checks = []evidence.Check{}
	}
	bad := 0
	for _, c := range checks {
		if !c.OK() {
			bad++
		}
	}
	if w.JSON(map[string]any{"checks": checks, "files": len(checks), "problems": bad}) {
		if bad > 0 {
			return fmt.Errorf("%d sealed file(s) do not check", bad)
		}
		return nil
	}
	if len(checks) == 0 {
		fmt.Println("  no file has been brought in as evidence, so there is nothing to check")
		return nil
	}
	for _, c := range checks {
		mark := "checks"
		if !c.OK() {
			mark = "DOES NOT CHECK"
		}
		fmt.Printf("  %s%s%s %s: seal %s, list %s, read again %s; %d of %d facts as read, %d replaced by a later file\n",
			bold, string(c.File.Record.Digest)[:19], reset, mark, c.Seal, c.Yield, c.Replay, c.Standing, c.Facts, c.Superseded)
		for _, p := range c.Problems {
			fmt.Printf("    %s\n", printable(p))
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d sealed file(s) do not check", bad)
	}
	return nil
}

func evidenceExpire(root string) error {
	g, by, err := evidenceIngester(root, resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	gone, err := g.Expire(by)
	if err != nil {
		return registerError(err)
	}
	if gone == nil {
		gone = []evidence.Sealed{}
	}
	if w.JSON(map[string]any{"erased": gone}) {
		return nil
	}
	if len(gone) == 0 {
		fmt.Println("  no raw file's time to be kept is up; nothing was erased")
		return nil
	}
	for _, s := range gone {
		fmt.Printf("  erased %s, received %s, kept until %s\n", s.Digest, s.Received.Format("2 Jan 2006"), s.Until.Format("2 Jan 2006"))
	}
	fmt.Printf("\n  %sthe seals and the lists of what was read are kept, so every fact still checks%s\n", dim, reset)
	return nil
}

func evidenceRecords(root string, kind register.Kind) error {
	r, err := openRegister(root)
	if err != nil {
		return err
	}
	entries, total, err := r.List(kind, 0, 200)
	if err != nil {
		return err
	}
	if entries == nil {
		entries = []register.Entry{}
	}
	if w.JSON(map[string]any{"kind": kind, "records": entries, "total": total}) {
		return nil
	}
	if total == 0 {
		if kind == register.KindPinnedKey {
			fmt.Println("  no key has been pinned; `quilzo evidence pin NAME KEYFILE` pins one")
		} else {
			fmt.Println("  no column map has been confirmed; `quilzo evidence draft-map` drafts one")
		}
		return nil
	}
	for _, e := range entries {
		switch rec := e.Record.(type) {
		case register.ColumnMap:
			fmt.Printf("  %s%-24s%s %-5s into %-12s %s\n", bold, rec.Name, reset, rec.Format, rec.Makes, printable(rec.Tool))
		case register.PinnedKey:
			fmt.Printf("  %s%-24s%s %-11s %s  %s\n", bold, rec.Name, reset, rec.Algorithm, rec.Fingerprint, printable(rec.Title))
		}
	}
	return nil
}

func evidenceDraftMap(format, path, kind, name, sheet string) error {
	f, ok := evidence.FormatNamed(format)
	if !ok {
		return errMisused{fmt.Errorf("%q is not a format this reads; a column map reads csv, xlsx or json", clip(format, 40))}
	}
	body, err := readInput(path, evidence.MaxFile)
	if err != nil {
		return evidenceError(err)
	}
	d, err := evidence.DraftMap(f, body, kind, name, sheet)
	if err != nil {
		return evidenceError(err)
	}
	if w.JSON(d) {
		return nil
	}
	b, _ := json.MarshalIndent(d.Map, "  ", "  ")
	fmt.Printf("  a draft, which reads nothing until you confirm it:\n\n  %s\n\n", printable(string(b)))
	fmt.Printf("  %sthe first rows it would read, under %s:%s\n", dim, printable(strings.Join(d.Headings, " | ")), reset)
	for _, row := range d.Sample {
		fmt.Printf("    %s\n", printable(strings.Join(row, " | ")))
	}
	if len(d.Unmapped) > 0 {
		fmt.Printf("  %scolumns it reads nothing from: %s%s\n", dim, printable(strings.Join(d.Unmapped, ", ")), reset)
	}
	fmt.Printf("\n  %ssave the map, change what is wrong, and `quilzo evidence confirm-map MAPFILE`%s\n", dim, reset)
	return nil
}

func evidenceConfirmMap(root, path string) error {
	body, err := readInput(path, 1<<20)
	if err != nil {
		return evidenceError(err)
	}
	var m register.ColumnMap
	// The map as `draft-map --json` writes it, or the map alone.
	var draft struct {
		Map *register.ColumnMap `json:"map"`
	}
	if json.Unmarshal(body, &draft) == nil && draft.Map != nil {
		m = *draft.Map
	} else if err := json.Unmarshal(body, &m); err != nil {
		return errMisused{fmt.Errorf("%s is not a column map: %v", path, err)}
	}
	r, by, err := registerWriter(root, resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	rc, err := r.Put(by, "column map "+m.Name+", confirmed", m)
	if err != nil {
		return registerError(err)
	}
	if w.JSON(rc) {
		return nil
	}
	fmt.Printf("  the column map %s is confirmed; `quilzo ingest %s FILE --map %s` reads through it\n", m.Name, m.Format, m.Name)
	return nil
}

func evidencePin(root, name, path, keyid, title string) error {
	body, err := readInput(path, 64<<10)
	if err != nil {
		return evidenceError(err)
	}
	k, err := evidence.PinKey(name, title, keyid, body, time.Now())
	if err != nil {
		return errMisused{err}
	}
	r, by, err := registerWriter(root, resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	rc, err := r.Put(by, "key "+k.Name+", pinned", k)
	if err != nil {
		return registerError(err)
	}
	if w.JSON(map[string]any{"key": k, "receipt": rc}) {
		return nil
	}
	fmt.Printf("  pinned %s, %s, with the fingerprint\n    %s\n", k.Name, k.Algorithm, k.Fingerprint)
	fmt.Printf("  %scheck it against what the key's owner published; a signed file is read only if this key verifies it%s\n", dim, reset)
	return nil
}

// registerEvidenceOps is the module's operations on the agent interface:
// the reads, a preview that writes nothing, and the import, which a model
// is refused as every write to the register refuses one.
func registerEvidenceOps(srv *mcp.Server, root string, caller *Caller) {
	may := func(act auth.Action) error {
		if err := authorise(root, caller, act, register.Area); err != nil {
			return &mcp.Refusal{Reason: err.Error()}
		}
		return nil
	}
	srv.Register(mcp.Operation{
		Name: "evidence_files", NeedsRole: "reader", Area: register.Area,
		Summary:  "the files brought in as evidence, each sealed by its hash, with its grade and what it yielded",
		Args:     map[string]string{"offset": "optional, how many to skip", "limit": "optional, how many to return, at most 200"},
		Types:    map[string]string{"offset": "number", "limit": "number"},
		Keywords: []string{"evidence", "files", "import", "raw", "sealed", "grade"},
	}, func(a map[string]any) (any, error) {
		if err := may(auth.ActView); err != nil {
			return nil, err
		}
		offset, limit := numberArg(a, "offset", 0), numberArg(a, "limit", 50)
		if offset < 0 || limit < 1 || limit > 200 {
			return nil, &mcp.ArgumentError{Reason: "offset is 0 or more, and limit from 1 to 200"}
		}
		g, err := evidenceReader(root)
		if err != nil {
			return nil, err
		}
		files, total, err := g.Files(offset, limit)
		return map[string]any{"files": files, "total": total, "offset": offset, "limit": limit}, err
	})
	srv.Register(mcp.Operation{
		Name: "evidence_verify", NeedsRole: "reader", Area: register.Area,
		Summary: "check sealed evidence files: each seal, each list of what was read, and every fact it names",
		Detail: "A file whose raw bytes were erased when its time to be kept was up still checks against its seal and " +
			"the list of what was read from it. Name a file by its digest or identifier, or none for every file.",
		Args:     map[string]string{"file": "optional, a sealed file's digest or identifier"},
		Keywords: []string{"evidence", "verify", "seal", "integrity", "provenance"},
	}, func(a map[string]any) (any, error) {
		if err := may(auth.ActView); err != nil {
			return nil, err
		}
		g, err := evidenceReader(root)
		if err != nil {
			return nil, err
		}
		var names []string
		if f, _ := a["file"].(string); f != "" {
			names = []string{f}
		}
		checks, err := g.Verify(names...)
		if errors.Is(err, register.ErrNotFound) {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		return map[string]any{"checks": checks}, err
	})
	srv.Register(mcp.Operation{
		Name: "evidence_expire", NeedsRole: "author", Area: register.Area, Writes: true,
		Summary: "erase the raw files whose time to be kept is up; their seals and what was read from them are kept",
		Detail: "Nothing is erased before its time. Every fact a file yielded still checks after its bytes are erased, " +
			"against the file's seal and the list of what was read from it. The erasure is recorded in the audit log.",
		Keywords: []string{"evidence", "expire", "retention", "erase", "raw"},
	}, func(map[string]any) (any, error) {
		if err := may(auth.ActEditDraft); err != nil {
			return nil, err
		}
		g, by, err := evidenceIngester(root, caller)
		if err != nil {
			return nil, err
		}
		gone, err := g.Expire(by)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		if gone == nil {
			gone = []evidence.Sealed{}
		}
		return map[string]any{"erased": gone}, nil
	})
	srv.Register(mcp.Operation{
		Name: "evidence_ingest", NeedsRole: "author", Area: register.Area, Writes: true,
		Summary: "bring a file in as evidence: seal it by its hash, read it, and write what it yields, graded by how it came",
		Detail: "The file is given as text in content, or as base64 in base64. format is one of " + formatList() +
			". A table (csv, xlsx, json) is read through a column map a person confirmed, named in map. With preview " +
			"true nothing is sealed or written and what would be written is returned. A model does not write the " +
			"register: a call made for one is refused.",
		Args: map[string]string{"format": "the file's format", "content": "the file, as text", "base64": "the file, as base64",
			"source": "optional, the source the facts are filed under", "map": "optional, a confirmed column map's name",
			"preview": "optional, true to read and write nothing"},
		Types:    map[string]string{"preview": "boolean"},
		Keywords: []string{"evidence", "ingest", "import", "ocsf", "sbom", "sarif", "csaf", "vex", "dsse", "osquery", "csv", "xlsx"},
	}, func(a map[string]any) (any, error) {
		if err := may(auth.ActEditDraft); err != nil {
			return nil, err
		}
		format, ok := evidence.FormatNamed(fmt.Sprint(a["format"]))
		if !ok {
			return nil, &mcp.ArgumentError{Reason: "evidence_ingest needs arguments.format, one of " + formatList()}
		}
		var body []byte
		if s, _ := a["base64"].(string); s != "" {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return nil, &mcp.ArgumentError{Reason: "arguments.base64 is not base64"}
			}
			body = b
		} else if s, _ := a["content"].(string); s != "" {
			body = []byte(s)
		}
		if len(body) == 0 {
			return nil, &mcp.ArgumentError{Reason: "evidence_ingest needs the file, in arguments.content or arguments.base64"}
		}
		g, by, err := evidenceIngester(root, caller)
		if err != nil {
			return nil, err
		}
		source, _ := a["source"].(string)
		mapName, _ := a["map"].(string)
		in := evidence.Input{Format: format, Body: body, Source: source, By: caller.Kind}
		if err := g.Prepare(&in, mapName); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		if p, _ := a["preview"].(bool); p {
			b, err := evidence.Read(in)
			if err != nil {
				return nil, &mcp.Refusal{Reason: err.Error()}
			}
			return map[string]any{"preview": true, "batch": b}, nil
		}
		res, err := g.Ingest(by, "", in)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		return res, nil
	})
}

func formatList() string {
	var names []string
	for _, f := range evidence.Formats() {
		names = append(names, string(f.Format))
	}
	return strings.Join(names, ", ")
}
