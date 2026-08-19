package main

import (
	"fmt"
	"path/filepath"
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
	s, err := open(root)
	if err != nil {
		return err
	}
	ref := site.RefDraft
	if len(args) > 0 {
		ref = args[0]
	}
	r, err := loadBrand(root)
	if err != nil {
		return err
	}
	if len(r.Terms) == 0 {
		fmt.Printf("  %sno claim rules; nothing was checked%s\n", dim, reset)
		return nil
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
// # One walk, not two
//
// This read the pages and then walked the collections separately, which was
// wrong in a way only a live test showed: GetTree returns flattened leaf
// paths, so a record is already in PagesAt as a blob at
// data/products/ke/tt/kettle. Two walks meant every product reported each
// finding twice and the "n items checked" count was double what was checked.
//
// So there is one walk, and the collection path is decoded to name the record
// the way a person refers to it. A record that fails is reported as
// "products/kettle" rather than as its shard path, because the author has to
// find it.
func brandFindings(s *store.Store, r *brand.Rules, ref string) (
	[]brand.Finding, int, error) {

	entries, err := site.PagesAt(s, ref)
	if err != nil {
		return nil, 0, err
	}
	content := make(map[string]map[string]any, len(entries))
	for name, body := range entries {
		m, ok := body.(map[string]any)
		if !ok {
			// A page that is not an object carries no fields to check. Not an
			// error: a store may hold a blob that is a string or a number, and
			// a claim is language in a field.
			continue
		}
		if coll, id, isRecord := collection.IsCollectionPath(name); isRecord {
			name = coll + "/" + id
		}
		content[name] = m
	}
	return r.CheckAll(content), len(content), nil
}
