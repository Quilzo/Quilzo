package main

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The assistant writes to a draft and marks what it wrote.
//
// Those two things belong in one command because separating them is how the
// mark goes missing. Until now the assistant existed as a library nobody could
// call and the provenance system had to be driven by hand — which meant the one
// category of content Article 50 exists to catch was the category that got no
// mark unless somebody remembered.
//
// The rule enforced here: content the model touched is marked by the system, not
// by the model and not by the person running it. An assistant able to describe
// its own output as human-written is a laundering tool, and the marking would be
// worth nothing.

func cmdAssist(root string, args []string) error {
	fs := flag.NewFlagSet("assist", flag.ContinueOnError)
	author := fs.String("author", "", "the accountable person (required)")
	dryRun := fs.Bool("dry-run", false, "show the proposal without writing anything")
	tplDir := fs.String("templates", "templates", "where proposed templates would go")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(`usage: quilzo assist "what to change" --author <who>`)
	}
	instruction := pos[0]

	// Required, and not defaulted to a username. Article 50 puts the obligation
	// on a person or organisation; a record naming "cli" would satisfy the
	// struct and nobody at all.
	if strings.TrimSpace(*author) == "" {
		return fmt.Errorf(
			"--author is required: someone has to be accountable for what the " +
				"model writes, and that is never the tool")
	}

	model, err := assist.NewHTTPModel()
	if err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	// Captured before the model is asked, not after. The gap between reading
	// and writing is however long the model takes to think, which is the whole
	// window this is protecting.
	base := s.GetRef(site.RefDraft)
	current, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		current = map[string]any{}
	}

	w.Human("asking %s...\n", model.Name())
	proposal, err := assist.Ask(context.Background(), model, instruction, current)
	if err != nil {
		return err
	}

	// What the model actually proposes to change, so the operator sees the
	// blast radius before anything is written.
	names := make([]string, 0, len(proposal.Pages))
	for n := range proposal.Pages {
		names = append(names, n)
	}
	sort.Strings(names)

	changed := map[string]bool{}
	added := map[string]bool{}
	for _, n := range names {
		if _, existed := current[n]; existed {
			changed[n] = true
		} else {
			added[n] = true
		}
	}

	if w.Mode == out.JSON {
		type row struct {
			Page       string `json:"page"`
			Change     string `json:"change"`
			SourceType string `json:"digital_source_type"`
		}
		rows := make([]row, 0, len(names))
		for _, n := range names {
			rows = append(rows, row{
				Page: n, Change: changeKind(added[n]),
				SourceType: string(sourceTypeFor(added[n])),
			})
		}
		w.JSON(map[string]any{
			"instruction": instruction, "model": model.Name(),
			"dry_run": *dryRun, "pages": rows,
			"templates": len(proposal.Templates), "notes": proposal.Notes,
		})
	} else {
		w.Human("\n%sproposed%s\n", bold, reset)
		for _, n := range names {
			verb := "change"
			if added[n] {
				verb = "add"
			}
			w.Human("  %-8s %s\n", verb, n)
		}
		for n := range proposal.Templates {
			w.Human("  %-8s %s %s(template)%s\n", "write", n, dim, reset)
		}
		if proposal.Notes != "" {
			w.Human("\n  %s%s%s\n", dim, proposal.Notes, reset)
		}
	}

	if *dryRun {
		w.Human("\n  %snothing written%s\n", dim, reset)
		return nil
	}

	// Merge into the draft rather than replacing it. A proposal touching one
	// page must not delete the rest of the site.
	merged := map[string]any{}
	for k, v := range current {
		merged[k] = v
	}
	for k, v := range proposal.Pages {
		merged[k] = v
	}

	// The same gate as every other write path. A model producing content that
	// does not fit the declared shape is the likeliest source of it, and this
	// is the surface where nobody typed the values by hand and noticed.
	types, err := gateWrite(root, merged)
	if err != nil {
		return err
	}

	// The draft this proposal was computed against. An assistant that read the
	// draft, thought for twenty seconds and wrote back is the most likely
	// concurrent writer in the system, and the least likely to notice.
	cid, err := site.SaveDraftFrom(s, merged,
		fmt.Sprintf("assist: %s", truncate(instruction, 60)), *author, base)
	if err != nil {
		return conflictError(err, names)
	}
	if err := types.Save(); err != nil {
		return err
	}

	if len(proposal.Templates) > 0 {
		written, err := assist.WriteTemplates(*tplDir, proposal)
		if err != nil {
			return err
		}
		for _, f := range written {
			w.Human("  wrote %s\n", f)
		}
	}

	if err := markAssisted(root, s, cid, names, added, model.Name(), instruction, *author); err != nil {
		// The draft is written but unmarked, which is the state this command
		// exists to prevent. Say so loudly rather than reporting success.
		return fmt.Errorf(
			"the draft was saved but provenance could not be recorded (%w). "+
				"Do not publish until `quilzo provenance check` is clean", err)
	}

	record(root, audit.Record{
		Action: "assist", Resource: "/", Outcome: audit.Success,
		// The model is the actor, and it is recorded as one. Logging this as
		// the human who typed the command would lose the fact the log exists
		// to preserve.
		Principal: "assistant", Kind: audit.KindAI, Model: model.Name(),
		Detail: map[string]string{
			"pages":        fmt.Sprintf("%d", len(names)),
			"commit":       short(cid),
			"on_behalf_of": *author,
		},
	})

	w.Human("\ndraft %s\n", short(cid))
	w.Human("  %severy page the model touched is marked as AI-generated%s\n", dim, reset)
	w.Human("  %sreview it: quilzo diff · quilzo provenance check%s\n", dim, reset)
	return nil
}

// markAssisted records provenance for everything the model wrote.
//
// A page the model created is `trainedAlgorithmicMedia`. A page that already
// existed and was edited is `compositeWithTrainedAlgorithmicMedia`, because a
// person's work is still in there. Both require an Article 50 mark; the
// distinction is honest rather than decorative, and it is the difference
// between "the model wrote this" and "the model touched this".
func markAssisted(root string, s *store.Store, commitID string, pages []string,
	added map[string]bool, modelName, instruction, author string) error {

	c, err := s.GetCommit(commitID)
	if err != nil {
		return err
	}
	tree, err := s.GetTree(c.Tree)
	if err != nil {
		return err
	}

	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	for _, page := range pages {
		hash, ok := tree[page]
		if !ok {
			continue
		}
		rec := provenance.Record{
			ContentHash: hash,
			SourceType:  sourceTypeFor(added[page]),
			Model:       modelName,
			Instruction: instruction,
			Author:      author,
			// ReviewedBy stays empty deliberately. Running the command is not
			// reviewing the output, and the disclosure says "has not been
			// reviewed by a person" until somebody claims otherwise.
		}
		if err := idx.Set(page, rec); err != nil {
			return err
		}
	}
	return saveJSON(provPath(root), idx)
}

// sourceTypeFor picks the marking. There is no branch that returns humanEdits:
// the assistant cannot describe its own output as human-written, whatever it or
// its caller would prefer.
func sourceTypeFor(isNew bool) provenance.SourceType {
	if isNew {
		return provenance.TrainedAlgorithmicMedia
	}
	return provenance.CompositeWithTrainedAlgorithmicMedia
}

func changeKind(isNew bool) string {
	if isNew {
		return "added"
	}
	return "changed"
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
