package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/lithoform/lithoform/internal/out"
	"github.com/lithoform/lithoform/internal/provenance"
	"github.com/lithoform/lithoform/internal/site"
	"github.com/lithoform/lithoform/internal/store"
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
func pageHashes(s *store.Store, ref string) (map[string]string, error) {
	cid := s.GetRef(ref)
	if cid == "" {
		cid = ref
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return nil, err
	}
	return s.GetTree(c.Tree)
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
	default:
		return fmt.Errorf("unknown provenance command %q; try set or check", args[0])
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
		return fmt.Errorf("usage: scrivet provenance set <page> --source <type> --author <who>")
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
