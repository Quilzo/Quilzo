// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/export"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/siem"
	"github.com/quilzo/quilzo/internal/site"
)

func cmdExport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := fs.String("to", "export", "directory to write into")
	ref := fs.String("ref", site.RefLive, "which ref to export")
	baseURL := fs.String("base-url", "", "the site's absolute origin")
	name := fs.String("name", "", "the site's name")
	force := fs.Bool("force", false, "write into a directory that is not empty")
	licence := fs.String("licence", "",
		"SPDX URI the deposit is under (ro-crate requires one)")
	publisher := fs.String("publisher", "", "who is depositing (ro-crate)")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	format := export.Format("markdown")
	if len(pos) == 1 {
		format = export.Format(pos[0])
	}

	// The one export of a whole site (exportsite.go), which MCP's
	// export_site and the Transfer screen build too.
	caller := resolveCaller(root, flagToken)
	opts := exportOptions{Format: format, Ref: *ref, Name: *name, BaseURL: *baseURL,
		Licence: *licence, Publisher: *publisher}
	ex, err := exportSite(root, caller, opts)
	if err != nil {
		return err
	}
	for _, note := range ex.Notes {
		w.Human("  %s%s%s\n", yellow, note, reset)
	}
	files := ex.Files

	// Refuse to write into a directory that already has something in it. An
	// export that half-overwrites a previous one produces a directory that is
	// neither, and the person finds out when they try to load it.
	if entries, err := os.ReadDir(*dir); err == nil && len(entries) > 0 && !*force {
		return errBlocked{fmt.Errorf(
			"%s already contains %d entries; pass --force to write into it anyway",
			*dir, len(entries))}
	}

	for _, f := range files {
		path, err := containedPath(*dir, f.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, f.Body, 0o600); err != nil {
			return err
		}
	}

	recordExport(root, caller, opts, ex, *dir)

	if w.JSON(map[string]any{
		"format": format, "pages": ex.Pages, "records": ex.Records,
		"collections": ex.Collections, "files": len(files), "to": *dir,
	}) {
		return nil
	}
	// Records counted out loud, beside the pages. The count is what tells
	// somebody the catalogue came with them.
	w.Human("%s%d page(s)%s and %s%d record(s)%s in %d collection(s) as %s into %s%s%s\n",
		bold, ex.Pages, reset, bold, ex.Records, reset, ex.Collections,
		format, bold, *dir, reset)
	for _, f := range files {
		w.Human("  %s%s%s\n", dim, f.Path, reset)
	}
	w.Human("\n  %severything here is a plain file; README.md says how to load "+
		"it elsewhere%s\n", dim, reset)
	if format == export.ROCrate {
		w.Human("  %sthe crate lists a sha256 per file: it says these bytes "+
			"were published,\n  not that their content is correct%s\n",
			dim, reset)
	}
	return nil
}

func cmdSiem(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("siem", flag.ContinueOnError)
	outPath := fs.String("o", "", "write here instead of stdout")
	since := fs.Int64("since", 0, "first sequence number to include")
	until := fs.Int64("until", 0, "last sequence number to include")
	reveal := fs.Bool("reveal", false,
		"do not withhold identifiers (cannot undo pseudonymisation)")
	envelopePath := fs.String("envelope", "",
		"write the integrity envelope here, so the export stays verifiable")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	format := siem.Format("ocsf")
	if len(pos) == 1 {
		format = siem.Format(pos[0])
	}

	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}

	res, err := siem.Export(format, events, siem.Options{
		Reveal: *reveal, Since: *since, Until: *until,
	}, time.Now())
	if err != nil {
		return errBlocked{err}
	}

	// The export is itself an event. An export that quietly re-identified
	// people would be a privacy failure with a paper trail pointing the wrong
	// way, so asking for identifiers is recorded whether or not it worked.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "auditlog.export", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"format": string(format),
			"events": fmt.Sprintf("%d", res.Count),
			"range":  fmt.Sprintf("%d-%d", res.Chain.FirstSeq, res.Chain.LastSeq),
			// Named plainly, because "reveal=true" in an audit log is the line
			// somebody needs to find.
			"identifiers_requested": fmt.Sprintf("%t", *reveal),
			"pseudonymous":          fmt.Sprintf("%t", res.Chain.Pseudonymous),
		},
	})

	if *envelopePath != "" {
		body, err := json.MarshalIndent(res.Chain, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*envelopePath, append(body, '\n'), 0o600); err != nil {
			return err
		}
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(res.Body), 0o600); err != nil {
			return err
		}
	} else if w.Mode != out.JSON {
		fmt.Print(res.Body)
	}

	if w.Mode == out.JSON {
		w.JSON(map[string]any{
			"format": format, "events": res.Count,
			"envelope": res.Chain, "redacted": res.Redacted,
		})
		return nil
	}

	// Everything below goes to stderr, so piping the export into a SIEM does
	// not also pipe the summary into it.
	fmt.Fprintf(os.Stderr, "\n%s%d event(s)%s as %s, sequences %d-%d\n",
		bold, res.Count, reset, format, res.Chain.FirstSeq, res.Chain.LastSeq)
	if res.Redacted {
		fmt.Fprintf(os.Stderr, "  %sidentifiers are as the log stored them%s\n",
			dim, reset)
	}
	if *envelopePath == "" {
		fmt.Fprintf(os.Stderr,
			"  %sno envelope written: without one the receiving system cannot\n"+
				"  tell whether events were removed. Pass --envelope FILE.%s\n",
			yellow, reset)
	} else if format == siem.Format("jsonl") {
		fmt.Fprintf(os.Stderr, "  %senvelope in %s — verify with "+
			"`quilzo siem verify`%s\n", dim, *envelopePath, reset)
	} else {
		// An OCSF or CEF record carries its event's hash and not the event,
		// so it cannot be recomputed; saying "verify with" here sent people
		// to a check that reported their untouched export as altered.
		fmt.Fprintf(os.Stderr, "  %senvelope in %s — it lists every event's hash in order, as the export\n"+
			"  carries them (%s); a JSON Lines export (quilzo siem jsonl) carries each event\n"+
			"  whole, and is the one `quilzo siem verify` can check%s\n",
			dim, *envelopePath, hashWhere(format), reset)
	}
	return nil
}

// hashWhere is where an export format puts each event's hash.
func hashWhere(f siem.Format) string {
	if f == siem.Format("cef") {
		return "cs3, labelled eventHash"
	}
	return "metadata.uid"
}

// exportFormatOf names a SIEM format that is not JSON Lines of audit
// events, from its first line, or says nothing.
func exportFormatOf(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "CEF:") {
		return "CEF"
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal([]byte(line), &probe) == nil {
		if _, ocsf := probe["class_uid"]; ocsf {
			return "OCSF"
		}
	}
	return ""
}

// cmdSiemVerify checks an export against its envelope.
func cmdSiemVerify(root string, args []string) error {
	// leadingArgs, because Go's flag package stops at the first non-flag
	// argument — so `verify FILE --envelope E` would parse the filename and
	// then silently ignore the flag. This project has had that bug before.
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	envelopePath := fs.String("envelope", "", "the envelope written at export time")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *envelopePath == "" {
		return fmt.Errorf(
			"usage: quilzo siem verify EXPORT.jsonl --envelope envelope.json")
	}

	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	// The check recomputes each event from the event itself, which only a
	// JSON Lines export carries. An OCSF or CEF line read as an event has
	// no hash and no sequence, and was reported as "altered after export":
	// a false accusation about evidence nobody touched.
	if f := exportFormatOf(strings.SplitN(strings.TrimSpace(string(raw)), "\n", 2)[0]); f != "" {
		article := "a"
		if f == "OCSF" {
			article = "an"
		}
		return fmt.Errorf("%s is %s %s export, which carries each event's hash (%s) and not the event, "+
			"so it cannot be recomputed here. Compare those hashes, in order, with the envelope's; "+
			"for an export this can verify, use quilzo siem jsonl", pos[0], article, f,
			hashWhere(siem.Format(strings.ToLower(f))))
	}
	var events []audit.Event
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return fmt.Errorf("line %d is not a JSON Lines event: %w", i+1, err)
		}
		events = append(events, e)
	}

	var env siem.Envelope
	if err := loadJSON(*envelopePath, &env); err != nil {
		return err
	}

	if err := siem.VerifyEnvelope(events, env); err != nil {
		if w.JSON(map[string]any{"verified": false, "reason": err.Error()}) {
			return errBlocked{err}
		}
		w.Human("%sthis export does not verify%s\n", red, reset)
		w.Human("  %s\n", err)
		return errBlocked{err}
	}

	if w.JSON(map[string]any{
		"verified": true, "events": len(events),
		"first_seq": env.FirstSeq, "last_seq": env.LastSeq,
		"pseudonymous": env.Pseudonymous,
	}) {
		return nil
	}
	w.Human("%sverified%s  %d event(s), sequences %d-%d\n",
		green, reset, len(events), env.FirstSeq, env.LastSeq)
	w.Human("  %snothing was added, removed, reordered or altered since export%s\n",
		dim, reset)
	// Say what this does not establish. A verifier that overstates what it
	// checked is worse than none, because its output is believed.
	if env.AnchorPrev == "" {
		w.Human("  %sthis range starts at the beginning of the chain, so it is "+
			"the whole log%s\n", dim, reset)
	} else {
		w.Human("  %sthis does not establish that the range is the whole log; a\n"+
			"  partial export is a partial export. It links back to %s, which\n"+
			"  is not included here.%s\n", dim, short(env.AnchorPrev), reset)
	}
	return nil
}

// containedPath joins a name onto a directory and refuses to leave it.
//
// `quilzo ipfs write` has done this since it was written, and its comment
// predicted this exact defect: "Page names are validated on write, so this
// cannot currently escape — and 'cannot currently' is exactly the phrase that
// stops being true after somebody relaxes a rule somewhere else."
//
// It stopped being true. Store.PutRaw, the path a peer's objects arrive on,
// checked that bytes hash to the id asked for and parsed nothing — so a peer
// could offer a tree whose keys were "../../../../tmp/pwned", GetTree would
// unmarshal it without re-validating, and the exporter joined those keys onto
// the output directory and wrote them. Arbitrary location, attacker-chosen
// contents, parent directories created on the way.
//
// Both halves are fixed: the store validates a tree it is handed, and this
// checks the write regardless. Two independent checks rather than one, because
// the reason this happened is that a downstream consumer trusted an invariant
// it could have verified in three lines.
func containedPath(dir, name string) (string, error) {
	full := filepath.Join(dir, filepath.FromSlash(name))
	rel, err := filepath.Rel(dir, full)
	if err != nil || filepath.IsAbs(rel) ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q would be written outside %s", name, dir)
	}
	return full, nil
}
