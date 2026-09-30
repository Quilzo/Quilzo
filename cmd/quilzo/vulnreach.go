// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/reach"
	"github.com/quilzo/quilzo/internal/vuln"
)

// Whether the vulnerable code is used, where that can be established.
//
// `vuln reach` reads one asset's source for the symbols each open advisory
// names, and records what it found against that advisory on that asset.
// Three things it is careful not to claim:
//
//   - It is per advisory. A library is not reachable or unreachable; one
//     function of it is, and the next advisory names a different one.
//   - It lowers a rank, and never closes a row. "This source does not name
//     the symbol" says nothing of the dependencies that might, so it is
//     grounds for a person to record not_affected, with their name on it.
//   - Most advisories name no symbol, and for those nothing is recorded:
//     unanalysed stays unanalysed, and the command says how many.
//
// A new bill for the asset discards its results: they were about code that
// has since changed.

func reachPath(root string) string {
	return filepath.Join(vulnDir(root), "reach.jsonl")
}

func loadReach(root string) ([]vuln.Reach, error) {
	var out []vuln.Reach
	err := loadJSONL(reachPath(root), func(b []byte) error {
		var r vuln.Reach
		if err := json.Unmarshal(b, &r); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

// dropReach removes what was established about one asset.
func dropReach(root, asset string) error {
	all, err := loadReach(root)
	if err != nil || len(all) == 0 {
		return err
	}
	kept := all[:0:0]
	for _, r := range all {
		if r.Where != asset {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(all) {
		return nil
	}
	return writeJSONL(reachPath(root), kept)
}

func vulnReach(root string, args []string) error {
	fs := flag.NewFlagSet("reach", flag.ContinueOnError)
	source := fs.String("source", "", "the asset's source tree")
	where := fs.String("where", "", "the asset, as issuer:value, the same "+
		"as its bill was imported under")
	tests := fs.Bool("tests", false, "count symbols used only in tests")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" {
		return fmt.Errorf("usage: quilzo vuln reach --source DIR --where " +
			"ISSUER:VALUE")
	}
	asset, err := parseAsset(*where)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	now := time.Now().UTC()
	v, err := loadVulnView(root, now)
	if err != nil {
		return err
	}
	onAsset := 0
	var results []reach.Result
	var kept []vuln.Reach
	for _, e := range v.Matched {
		if e.Component.Where != asset {
			continue
		}
		onAsset++
		var imports []reach.Affected
		for _, im := range e.Advisory.Imports {
			if vuln.Key(im.Ecosystem, im.Package) == e.Component.Key() {
				imports = append(imports, reach.Affected{Path: im.Path,
					Symbols: im.Symbols})
			}
		}
		if _, ok := reach.Supports(e.Component.Ecosystem); !ok {
			// An ecosystem whose advisories name no symbols. Nothing to
			// look for, and nothing is inferred.
			imports = nil
		}
		res, rerr := reach.Assess(e.Advisory.ID, e.Component.Key(), imports,
			reach.Source{Dir: *source, Tests: *tests})
		if rerr != nil {
			// Code that could not be read proves nothing about itself.
			return fmt.Errorf("%s: %w", e.Advisory.ID, rerr)
		}
		results = append(results, res)
		if !res.Verdict.Settled() {
			continue
		}
		kept = append(kept, vuln.Reach{Advisory: e.Advisory.ID,
			Component: e.Component.Key(), Where: asset.String(),
			Referenced: res.Verdict == reach.Referenced,
			Symbols:    len(res.Symbols), Found: res.Found, Files: res.Where,
			At: now})
	}
	if onAsset == 0 {
		return fmt.Errorf("nothing open is installed on %s. If that is "+
			"not what was expected, check the name against the one its "+
			"bill was imported under", asset)
	}
	all, err := loadReach(root)
	if err != nil {
		return err
	}
	merged := all[:0:0]
	for _, r := range all {
		if r.Where != asset.String() {
			merged = append(merged, r)
		}
	}
	merged = append(merged, kept...)
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Where != merged[j].Where {
			return merged[i].Where < merged[j].Where
		}
		return merged[i].Advisory < merged[j].Advisory
	})
	if err := writeJSONL(reachPath(root), merged); err != nil {
		return err
	}
	f := reach.Measure(results)
	record(root, audit.Record{Action: "vuln.reach", Resource: "/vuln",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{
			"asset": asset.String(), "assessed": fmt.Sprint(f.Total),
			"not_referenced":      fmt.Sprint(f.Cleared),
			"referenced":          fmt.Sprint(f.Kept),
			"nothing_to_look_for": fmt.Sprint(f.Silent)}})
	if w.JSON(map[string]any{"asset": asset.String(), "filter": f,
		"results": results}) {
		return nil
	}
	w.Human("%s%d exposure(s) on %s%s\n", bold, f.Total, asset, reset)
	for _, r := range reach.Worst(results) {
		if !r.Verdict.Settled() {
			continue
		}
		colour := green
		if r.Verdict == reach.Referenced {
			colour = red
		}
		w.Human("  %s%s%s  %s\n", colour, r.Verdict, reset, r.Says())
	}
	w.Human("\n  %s%d name a symbol this source uses, %d name symbols it "+
		"does not, and %d could not be checked: the advisory names no "+
		"symbol, or the ecosystem's advisories never do%s\n", dim, f.Kept,
		f.Cleared, f.Silent, reset)
	if f.Cleared > 0 {
		w.Human("  %snothing has left the queue. \"Not named here\" says "+
			"nothing of the dependencies; it is grounds for quilzo vuln "+
			"assess … not_affected, with a name on it%s\n", yellow, reset)
	}
	return nil
}
