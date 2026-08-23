package main

import (
	"time"

	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/audit"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

func provPath(root string) string { return filepath.Join(root, "provenance.json") }

func loadProvenance(root string) (*provenance.Index, error) {
	idx := provenance.NewIndex()
	return idx, loadJSON(provPath(root), idx)
}

// pageHashes returns the object id of each page's content at a ref.
//
// The hash is what a provenance record binds to, so this is the join between
// "what the site says" and "how it came to say it".
// pageHashes is every page in a commit, and its object id.
//
// Pages only: a records collection is a tree sharing the same root, and
// returning it made "data" a page to everything that reads this. `lang check`
// reported a missing French translation for a page that does not exist and
// could never be written, and `provenance check` listed it as content nobody
// had recorded — both of them permanently, on any site holding records.
//
// Filtered by what the object is rather than by name, the same way
// site.PagesAt does it: a list of reserved names has to be updated by whoever
// adds the next branch, and they will not know to.
func pageHashes(s *store.Store, ref string) (map[string]string, error) {
	cid := s.GetRef(ref)
	if cid == "" {
		cid = ref
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return nil, err
	}
	tree, err := s.GetTree(c.Tree)
	if err != nil {
		return nil, err
	}
	pages := make(map[string]string, len(tree))
	for name, oid := range tree {
		if s.IsTree(oid) {
			continue
		}
		pages[name] = oid
	}
	return pages, nil
}

func cmdProvenance(root string, args []string) error {
	if len(args) == 0 {
		return provStatus(root, nil)
	}
	switch args[0] {
	case "set":
		return provSet(root, args[1:])
	case "check", "status":
		return provStatus(root, args[1:])
	case "backfill":
		return provBackfill(root, args[1:])
	default:
		return fmt.Errorf(
			"unknown provenance command %q; try set, check or backfill", args[0])
	}
}

func provSet(root string, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	kind := fs.String("source", string(provenance.HumanEdits),
		"humanEdits | trainedAlgorithmicMedia | compositeWithTrainedAlgorithmicMedia | algorithmicMedia")
	model := fs.String("model", "", "which model, if one was involved")
	instruction := fs.String("instruction", "", "what it was asked to do")
	author := fs.String("author", "", "the accountable person (required)")
	reviewer := fs.String("reviewed-by", "", "who checked the output, if anyone")
	ref := fs.String("ref", site.RefDraft, "which ref the page is in")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo provenance set <page> --source <type> --author <who>")
	}
	page := pos[0]

	s, err := open(root)
	if err != nil {
		return err
	}
	hashes, err := pageHashes(s, *ref)
	if err != nil {
		return err
	}
	hash, ok := hashes[page]
	if !ok {
		return fmt.Errorf("no page %q in %s", page, *ref)
	}

	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	rec := provenance.Record{
		ContentHash: hash,
		SourceType:  provenance.SourceType(*kind),
		Model:       *model,
		Instruction: *instruction,
		Author:      *author,
		ReviewedBy:  *reviewer,
	}
	if err := idx.Set(page, rec); err != nil {
		return err
	}
	if err := saveJSON(provPath(root), idx); err != nil {
		return err
	}

	fmt.Printf("%s: %s\n", page, rec.SourceType.Describe())
	if d := rec.Disclosure(); d != "" {
		fmt.Printf("  %sreaders will see: %s%s\n", dim, d, reset)
	}
	fmt.Printf("  %sbound to sha256:%s%s\n", dim, short(hash), reset)
	return nil
}

func provStatus(root string, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	ref := fs.String("ref", site.RefDraft, "which ref to check")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	hashes, err := pageHashes(s, *ref)
	if err != nil {
		return err
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}

	statuses := provenance.Check(idx, hashes)
	gaps := provenance.Unmarked(statuses)

	// The machine contract. Deliberately not a transcription of the prose
	// below: it carries the fields a caller branches on, so the wording stays
	// free to improve without breaking anyone.
	if w.Mode == out.JSON {
		type row struct {
			Page       string `json:"page"`
			State      string `json:"state"` // ok | marked | stale | unrecorded
			SourceType string `json:"digital_source_type,omitempty"`
			NeedsMark  bool   `json:"requires_disclosure"`
			Disclosure string `json:"disclosure,omitempty"`
			Model      string `json:"model,omitempty"`
			Reviewed   bool   `json:"human_reviewed"`
		}
		rows := make([]row, 0, len(statuses))
		for _, st := range statuses {
			r := row{Page: st.Page, NeedsMark: st.NeedsMark, Disclosure: st.Disclosure}
			switch {
			case !st.Have:
				r.State = "unrecorded"
			case st.Stale:
				r.State = "stale"
			case st.NeedsMark:
				r.State = "marked"
			default:
				r.State = "ok"
			}
			if st.Have {
				r.SourceType = string(st.Record.SourceType)
				r.Model = st.Record.Model
				r.Reviewed = st.Record.ReviewedBy != ""
			}
			rows = append(rows, r)
		}
		w.JSON(map[string]any{
			"ref": *ref, "pages": rows,
			"without_provenance": len(gaps),
			"compliant":          len(gaps) == 0,
		})
		if len(gaps) > 0 {
			return errBlocked{fmt.Errorf("%d page(s) without provenance", len(gaps))}
		}
		return nil
	}

	fmt.Printf("%d page(s) in %s\n\n", len(statuses), *ref)
	for _, st := range statuses {
		switch {
		case !st.Have:
			fmt.Printf("  %sunrecorded%s  %-16s %sno provenance — this is a gap, "+
				"not a claim that a person wrote it%s\n", yellow, reset, st.Page, dim, reset)
		case st.Stale:
			fmt.Printf("  %sstale%s       %-16s %sthe record describes different "+
				"bytes; the page changed after it was written%s\n",
				red, reset, st.Page, dim, reset)
		case st.NeedsMark:
			fmt.Printf("  %smarked%s      %-16s %s%s%s\n",
				green, reset, st.Page, dim, st.Record.SourceType, reset)
			fmt.Printf("              %s%s%s\n", dim, st.Disclosure, reset)
		default:
			fmt.Printf("  %sok%s          %-16s %s%s%s\n",
				green, reset, st.Page, dim, st.Record.SourceType.Describe(), reset)
		}
	}

	if len(gaps) > 0 {
		fmt.Printf("\n  %s%d page(s) have no usable provenance.%s\n", yellow, len(gaps), reset)
		fmt.Printf("  %sEU AI Act Article 50 has applied since 2 August 2026: content a\n"+
			"  model generated must carry a machine-readable mark. Unrecorded is not\n"+
			"  the same as human-written, and only one of those is safe to publish\n"+
			"  unmarked.%s\n", dim, reset)
		return fmt.Errorf("%d page(s) without provenance", len(gaps))
	}
	return nil
}

// provBackfill marks content published before anybody was recording provenance.
//
// Article 50 covers content generated before August 2026 from 2 December 2026.
// The history is the only evidence left for that content, and it is thinner
// than it looks: a commit message prefix, which is real evidence and is also
// forgeable. So this proposes and explains rather than deciding quietly, and
// it never records human authorship for want of evidence.
func provBackfill(root string, args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ContinueOnError)
	ref := fs.String("ref", site.RefDraft, "which ref to mark")
	dryRun := fs.Bool("dry-run", false, "report what would happen, write nothing")
	limit := fs.Int("history", 5000, "how many commits back to read for evidence")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	current, err := pageHashes(s, *ref)
	if err != nil {
		return err
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}

	history, read, err := appearances(s, *ref, *limit)
	if err != nil {
		return err
	}

	plan := provenance.BuildPlan(current, history, idx, time.Now().Unix())

	if w.JSON(map[string]any{
		"ref": *ref, "pages": plan.Total(), "commits_read": read,
		"recorded": len(plan.Recorded), "inferred": len(plan.Inferred),
		"undecidable": len(plan.Undecidable), "dry_run": *dryRun,
		"plan": plan,
	}) {
		if *dryRun {
			return nil
		}
		_, aerr := plan.Apply(idx)
		if aerr != nil {
			return aerr
		}
		return saveJSON(provPath(root), idx)
	}

	// The count of what was examined, first. A pass that read no commits finds
	// nothing to infer and prints the same reassuring zero as one that read
	// everything.
	w.Human("%s%d page(s)%s at %s, against %s%d commit(s)%s of history\n",
		bold, plan.Total(), reset, *ref, bold, read, reset)

	if len(plan.Recorded) > 0 {
		w.Human("\n  %s%d already recorded%s\n", dim, len(plan.Recorded), reset)
	}

	if len(plan.Inferred) > 0 {
		w.Human("\n%s%d page(s) would be marked%s\n", bold, len(plan.Inferred), reset)
		for _, p := range plan.Inferred {
			w.Human("  %s%s%s  %s\n", bold, p.Page, reset, p.Record.SourceType)
			w.Human("    %s%s%s\n", dim, wrapIndent(p.Evidence, 68, 4), reset)
		}
		w.Human("\n  %sinferred, not observed. Each record says so and names "+
			"the commit it came\n  from, and none of them assesses the "+
			"Article 50 assistive-editing\n  exemption -- a typo fix is "+
			"exempt and this cannot tell one from the\n  other. Read them "+
			"before relying on the marks.%s\n", yellow, reset)
	}

	if len(plan.Undecidable) > 0 {
		w.Human("\n%s%d page(s) cannot be decided%s\n",
			bold, len(plan.Undecidable), reset)
		for _, p := range plan.Undecidable {
			w.Human("  %s%s%s\n", bold, p.Page, reset)
			w.Human("    %s%s%s\n", dim, wrapIndent(p.Why, 68, 4), reset)
		}
		w.Human("\n  %sthese are left with no record, which is what honestly "+
			"describes them.\n  Use `quilzo provenance set` where you know "+
			"the answer.%s\n", yellow, reset)
	}

	if *dryRun {
		w.Human("\n  %snothing written (--dry-run)%s\n", dim, reset)
		return nil
	}
	if len(plan.Inferred) == 0 {
		w.Human("\n  %snothing to write%s\n", dim, reset)
		return nil
	}

	n, err := plan.Apply(idx)
	if err != nil {
		return err
	}
	if err := saveJSON(provPath(root), idx); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "provenance.backfill", Resource: "/" + *ref,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified,
		Detail: map[string]string{
			"ref": *ref, "inferred": fmt.Sprintf("%d", n),
			"undecidable":  fmt.Sprintf("%d", len(plan.Undecidable)),
			"commits_read": fmt.Sprintf("%d", read),
		},
	})

	w.Human("\n  %swrote %d inferred record(s)%s\n", green, n, reset)
	w.Human("  %s`quilzo provenance check` now reports them as marked%s\n",
		dim, reset)
	return nil
}

// appearances walks the history and records where each page's content was
// introduced, with the message of the commit that introduced it.
//
// # A commit's tree is the whole site
//
// This is the trap, and the first version of this function fell straight into
// it. A commit names a tree, and that tree holds every page — not only the
// ones the commit changed. So iterating the tree of every commit says that
// every page "appears in" every commit, and one assistant-written commit
// anywhere in the history marks the entire site as AI-generated.
//
// Run against the demonstration, that is exactly what happened: fourteen
// pages marked trainedAlgorithmicMedia, all citing the same commit, including
// a page written by hand seconds earlier. Which is the failure the whole
// design is supposed to prevent — marking everything devalues the mark on the
// pages that need it.
//
// So a page is attributed to the commit where its content hash differs from
// the parent's, which is the commit that actually wrote those bytes. A commit
// that merely carried them forward changed nothing and is evidence about
// nothing.
func appearances(s *store.Store, ref string, limit int) (
	[]provenance.Appearance, int, error) {

	head := s.GetRef(ref)
	if head == "" {
		head = ref
	}
	hist, err := s.History(head, limit)
	if err != nil {
		return nil, 0, err
	}

	trees := map[string]map[string]string{}
	treeAt := func(commitID string) map[string]string {
		if t, ok := trees[commitID]; ok {
			return t
		}
		c, cerr := s.GetCommit(commitID)
		if cerr != nil {
			trees[commitID] = nil
			return nil
		}
		t, terr := s.GetTree(c.Tree)
		if terr != nil {
			t = nil
		}
		trees[commitID] = t
		return t
	}

	var out []provenance.Appearance
	for _, h := range hist {
		tree, terr := s.GetTree(h.Commit.Tree)
		if terr != nil {
			// One unreadable tree must not fail the whole walk. It shows up as
			// one fewer commit of evidence in the count printed to the
			// operator rather than as a silent gap.
			continue
		}

		// The union of the parents' trees. A page whose hash matches any
		// parent was not written here — on a merge, content coming from either
		// side was written on that side.
		inherited := map[string]bool{}
		for _, p := range h.Commit.Parents {
			for page, hash := range treeAt(p) {
				inherited[page+"\x00"+hash] = true
			}
		}

		for page, hash := range tree {
			if inherited[page+"\x00"+hash] {
				continue
			}
			out = append(out, provenance.Appearance{
				Page: page, ContentHash: hash, Commit: h.ID,
				Message: h.Commit.Message, Author: h.Commit.Author,
				At: h.Commit.At,
			})
		}
	}
	return out, len(hist), nil
}
