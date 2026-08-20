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
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/export"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/seo"
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

	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, *ref)
	if err != nil {
		return err
	}

	head := s.GetRef(*ref)

	// The collections too. Leaving these out was a silent data loss in every
	// format: the demo shop exported a catalogue page and none of its twelve
	// products, and nothing said so because the count printed was of pages.
	colls := map[string][]export.Record{}
	records := 0
	tree := ""
	if head != "" {
		c, err := s.GetCommit(head)
		if err != nil {
			return err
		}
		tree = c.Tree
	}
	if tree != "" {
		names, err := collection.Names(s, tree)
		if err != nil {
			return err
		}
		for _, name := range names {
			// Paged to the end, not one page of it. A listing has a maximum
			// limit, so taking a single page would export the first thousand
			// products of a larger catalogue and report success — the same
			// shape of failure as exporting none of them.
			for offset := 0; ; {
				rows, total, err := collection.List(s, tree, name,
					collection.Query{
						Limit: collection.MaxLimit, Offset: offset, Sort: "id"})
				if err != nil {
					return err
				}
				for _, r := range rows {
					colls[name] = append(colls[name], export.Record{
						ID: r.ID, Fields: r.Fields,
						Created: r.Created, Updated: r.Updated,
					})
				}
				offset += len(rows)
				records += len(rows)
				if len(rows) == 0 || offset >= total {
					if offset != total {
						return errBlocked{fmt.Errorf(
							"%s holds %d records but only %d could be read; "+
								"exporting now would drop the rest silently",
							name, total, offset)}
					}
					break
				}
			}
		}
	}
	changed, err := seo.LastChanged(s, head, 5000)
	if err != nil {
		// A missing history costs the dates, not the export. Refusing to
		// export because one derived field could not be computed would be the
		// wrong trade for the one command people run when they are leaving.
		changed = nil
		w.Human("  %scould not read history, so change dates are omitted%s\n",
			yellow, reset)
	}

	var redirects []export.Redirect
	if rf, err := os.ReadFile("redirects.json"); err == nil {
		var file struct {
			Redirects []seo.Redirect `json:"redirects"`
		}
		if json.Unmarshal(rf, &file) == nil {
			for _, r := range file.Redirects {
				redirects = append(redirects, export.Redirect{
					From: r.From, To: r.To, Permanent: r.Permanent, Note: r.Note})
			}
		}
	}

	files, err := export.Export(format, export.Site{
		Pages: pages, Name: *name, BaseURL: *baseURL,
		Changed: changed, Redirects: redirects, Collections: colls,
		Licence: *licence, Publisher: *publisher, Commit: head,
	}, time.Now())
	if err != nil {
		return errBlocked{err}
	}

	// Refuse to write into a directory that already has something in it. An
	// export that half-overwrites a previous one produces a directory that is
	// neither, and the person finds out when they try to load it.
	if entries, err := os.ReadDir(*dir); err == nil && len(entries) > 0 && !*force {
		return errBlocked{fmt.Errorf(
			"%s already contains %d entries; pass --force to write into it anyway",
			*dir, len(entries))}
	}

	for _, f := range files {
		path := filepath.Join(*dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, f.Body, 0o600); err != nil {
			return err
		}
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "export", Resource: "/" + *ref, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"format": string(format), "pages": fmt.Sprintf("%d", len(pages)),
			"records": fmt.Sprintf("%d", records),
			"files":   fmt.Sprintf("%d", len(files)), "to": *dir,
		},
	})

	if w.JSON(map[string]any{
		"format": format, "pages": len(pages), "records": records,
		"collections": len(colls), "files": len(files), "to": *dir,
	}) {
		return nil
	}
	// Records counted out loud, beside the pages. The count is what tells
	// somebody the catalogue came with them.
	w.Human("%s%d page(s)%s and %s%d record(s)%s in %d collection(s) as %s into %s%s%s\n",
		bold, len(pages), reset, bold, records, reset, len(colls),
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
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
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
	} else {
		fmt.Fprintf(os.Stderr, "  %senvelope in %s — verify with "+
			"`quilzo siem verify`%s\n", dim, *envelopePath, reset)
	}
	return nil
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
