package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/brand"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The claims gate, as a command and as a gate.
//
// Two entry points to one set of rules: `quilzo brand check` so an author can
// ask before they commit, and the publish path so nobody has to remember to.
// The command is the courtesy; the gate is the control.

func brandPath(root string) string { return filepath.Join(root, "brand.json") }

// loadBrand reads and compiles the rules.
//
// An absent file means no rules, which is the honest state of an install that
// has not written any — and not an error, because most sites do not need this
// and a gate that demands configuration to be switched off is one people
// delete rather than configure.
//
// A file that exists and does not parse is an error. Treating a broken rules
// file as "no rules" would make corrupting it the way to publish anything,
// which is the fail-open shape this project has already shipped once.
func loadBrand(root string) (*brand.Rules, error) {
	r := &brand.Rules{}
	if err := loadJSON(brandPath(root), r); err != nil {
		return nil, fmt.Errorf(
			"brand.json could not be read, so no claim in this publication "+
				"was checked: %w", err)
	}
	if len(r.Terms) == 0 {
		return r, nil
	}
	if err := r.Compile(); err != nil {
		return nil, fmt.Errorf("brand.json: %w", err)
	}
	return r, nil
}

func cmdBrand(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return brandList(root)
	case "init":
		return brandInit(root)
	case "check":
		return brandCheck(root, args[1:])
	default:
		return fmt.Errorf("unknown brand command %q; try list, init or check",
			args[0])
	}
}

func brandList(root string) error {
	r, err := loadBrand(root)
	if err != nil {
		return err
	}
	if len(r.Terms) == 0 {
		fmt.Printf("  %sno claim rules. `quilzo brand init` writes a starter "+
			"set%s\n", dim, reset)
		return nil
	}
	for _, t := range r.Terms {
		fmt.Printf("%s%s%s\n", bold, t.Match, reset)
		fmt.Printf("  %s%s%s\n", dim, t.Why, reset)
		if t.Needs != "" {
			fmt.Printf("  sayable with %s%s%s\n", green, t.Needs, reset)
		} else {
			fmt.Printf("  %snothing makes this sayable%s\n", yellow, reset)
		}
		if len(t.Fields) > 0 {
			fmt.Printf("  %sonly in %s%s\n", dim, strings.Join(t.Fields, ", "), reset)
		}
	}
	return nil
}

func brandInit(root string) error {
	existing := &brand.Rules{}
	if err := loadJSON(brandPath(root), existing); err == nil &&
		len(existing.Terms) > 0 {
		return fmt.Errorf(
			"brand.json already has %d rule(s); edit it rather than "+
				"overwriting somebody's work", len(existing.Terms))
	}
	r := brand.Starter()
	if err := saveJSON(brandPath(root), r); err != nil {
		return err
	}
	// Writing a publish gate is a change to what this store will refuse, and
	// AU-3 wants who did that. Recorded with the count rather than the terms:
	// the file is readable and versioned, and a log entry that reproduces its
	// contents goes stale the moment somebody edits it.
	record(root, resolveCaller(root, "").auditRecord(
		"brand.init", "/", audit.Success, map[string]string{
			"rules": fmt.Sprint(len(r.Terms))}))
	fmt.Printf("wrote %d starter rule(s) to brand.json\n", len(r.Terms))
	fmt.Printf("  %severy one of them is a suggestion; edit the file%s\n",
		dim, reset)
	fmt.Printf("  %sthey run at publish, and `quilzo brand check` asks early%s\n",
		dim, reset)
	return nil
}

func brandCheck(root string, args []string) error {
	// The positional ref comes off the front before the flags are parsed.
	//
	// Go's flag package stops at the first non-flag argument, so
	// `brand check live --text "..."` would parse zero flags and hand back two
	// positionals — silently, with --text empty. That bug is written twice in
	// this tree already; see the note in rightscmd.go.
	ref := site.RefDraft
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		ref, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("brand check", flag.ContinueOnError)
	text := fs.String("text", "",
		"check this sentence instead of the store, for copy not yet written")
	if err := fs.Parse(args); err != nil {
		return err
	}

	r, err := loadBrand(root)
	if err != nil {
		return err
	}
	if len(r.Terms) == 0 {
		fmt.Printf("  %sno claim rules; nothing was checked%s\n", dim, reset)
		return nil
	}

	// A sentence somebody is still writing.
	//
	// The gate reads content out of the store, so checking a line of copy meant
	// saving it, running the check, editing, and running it again — which is the
	// loop the gate exists to shorten. The whole argument in internal/brand is
	// that a refusal an author cannot act on is one they route around.
	//
	// The store is not touched at all: no ref is resolved and nothing is read,
	// so this works on a draft nobody has committed and in a directory with no
	// store in it.
	if strings.TrimSpace(*text) != "" {
		findings := r.Check("this sentence", map[string]any{"text": *text})
		if len(findings) == 0 {
			fmt.Printf("%snothing in that sentence needs substantiating%s\n",
				green, reset)
			return nil
		}
		printBrand(findings)
		// Substantiation cannot succeed here, and saying so is the difference
		// between a useful answer and a discouraging one: a rule with Needs is
		// satisfied by a field elsewhere in the same record, and a bare
		// sentence has no record. The finding names the field, so the author
		// knows what to put beside the copy rather than what to delete from it.
		fmt.Printf("  %sa sentence on its own carries no evidence field, so "+
			"anything needing one reports here%s\n", dim, reset)
		fmt.Printf("  %swrite the copy with its evidence field and check the "+
			"draft to see it clear%s\n", dim, reset)
		return fmt.Errorf("%d claim(s) in that sentence need substantiation",
			len(findings))
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	findings, checked, err := brandFindings(s, r, ref)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		fmt.Printf("%s%d item(s) checked, nothing to answer for%s\n",
			green, checked, reset)
		return nil
	}
	printBrand(findings)
	return fmt.Errorf("%d claim(s) without substantiation", len(findings))
}

func printBrand(findings []brand.Finding) {
	for _, f := range findings {
		fmt.Printf("  %s%s%s\n", yellow, f.String(), reset)
	}
}

// brandFindings runs the rules over everything a commit publishes.
//
// Pages and records both. In a shop the product copy is a record, so gating
// only pages would gate the part nobody sells anything with — which is the
// failure mode where the feature exists, reports clean, and means nothing.
//
// # Two walks, and why the obvious simplification is wrong
//
// This looks like it should be one walk. PagesAt already reads the commit's
// tree, so surely the records are in there — and a test written against a
// helper that inserted a record as a flat tree entry agreed, reporting each
// product twice. The walk was collapsed into one on that evidence.
//
// The evidence was manufactured. A real record is written by collection.PutMany,
// which builds nested subtrees, so a real commit's tree has ONE entry called
// "data" and it is a tree. PagesAt skips trees by design — reading one as a
// page fails with "object is a tree, not a blob" — so records never appear
// there, and the collapsed version checked ten pages and zero of fifteen
// products while reporting success.
//
// Running the actual demonstration is what caught it: "10 item(s) checked"
// against a store holding twenty-five. The count is in the output for that
// reason, and the test below now writes records the way the store does.
func brandFindings(s *store.Store, r *brand.Rules, ref string) (
	[]brand.Finding, int, error) {

	commit := s.GetRef(ref)
	if commit == "" {
		commit = ref
	}
	content := map[string]map[string]any{}

	pages, err := site.PagesAt(s, ref)
	if err != nil {
		return nil, 0, err
	}
	for name, body := range pages {
		if m, ok := body.(map[string]any); ok {
			content[name] = m
		}
	}

	// The records, at the same commit rather than from the live index, so the
	// gate examines what is about to be published rather than what already is.
	c, cerr := s.GetCommit(commit)
	if cerr != nil {
		return nil, 0, cerr
	}
	if c.Tree != "" {
		cache := collection.NewCache()
		names, nerr := cache.Names(s, c.Tree)
		if nerr != nil {
			// Reported rather than skipped. A store whose collections cannot
			// be listed is one where every product would pass unexamined, and
			// silence there is the failure this gate exists to prevent.
			return nil, 0, fmt.Errorf(
				"the collections could not be listed, so no product was "+
					"checked: %w", nerr)
		}
		sort.Strings(names)
		for _, name := range names {
			idx, ierr := cache.For(s, c.Tree, name)
			if ierr != nil {
				return nil, 0, fmt.Errorf(
					"collection %s could not be read, so nothing in it was "+
						"checked: %w", name, ierr)
			}
			recs, _ := idx.Query(collection.Query{})
			for _, rec := range recs {
				// Named the way a person refers to it. A finding against a
				// shard path is one the author cannot go and fix.
				content[name+"/"+rec.ID] = rec.Fields
			}
		}
	}
	return r.CheckAll(content), len(content), nil
}
