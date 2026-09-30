// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/vuln"
)

// SSVC in the store: the decision table CERT/CC publishes, loaded from
// their file, and what this organisation says about its own machines.
//
// The table is not shipped. It is theirs, under their terms, and a newer
// one is a file rather than a release. Until one is loaded nothing here
// offers an SSVC decision, and says why.

func ssvcTreePath(root string) string {
	return filepath.Join(vulnDir(root), "ssvc-tree.csv")
}

func assetTagsPath(root string) string {
	return filepath.Join(vulnDir(root), "assets.json")
}

// loadTree reads the stored decision table. No table is nil and no error.
func loadSSVCTree(root string) (vuln.Tree, error) {
	b, err := os.ReadFile(ssvcTreePath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return vuln.ParseTree(b)
}

func loadAssetTags(root string) (vuln.Tags, error) {
	b, err := os.ReadFile(assetTagsPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t vuln.Tags
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("assets.json: %w", err)
	}
	return t, nil
}

// MaxAssetTags bounds how many tags are held.
const MaxAssetTags = 2000

// setAssetTag stores one tag, replacing an earlier one for the same match.
func setAssetTag(root string, caller *Caller, tag vuln.AssetTag) error {
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("how exposed a machine is, and what is lost " +
			"with it, is this organisation's judgement and a person's")
	}
	tag.Match = strings.TrimSpace(tag.Match)
	tag.By, tag.At = caller.Name, time.Now().UTC()
	tag.Because = strings.TrimSpace(tag.Because)
	if err := tag.Validate(); err != nil {
		return err
	}
	tags, err := loadAssetTags(root)
	if err != nil {
		return err
	}
	kept := tags[:0:0]
	for _, t := range tags {
		if t.Match != tag.Match {
			kept = append(kept, t)
		}
	}
	kept = append(kept, tag)
	if len(kept) > MaxAssetTags {
		return fmt.Errorf("that would be %d tags; use a prefix for a "+
			"group of machines", len(kept))
	}
	sort.Slice(kept, func(a, b int) bool { return kept[a].Match < kept[b].Match })
	if err := saveAssetTags(root, kept); err != nil {
		return err
	}
	return recordE(root, audit.Record{Action: "vuln.asset.tagged",
		Resource: "/vuln/assets", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"match": tag.Match,
			"exposure": tag.Exposure, "impact": tag.Impact}})
}

func saveAssetTags(root string, tags vuln.Tags) error {
	b, err := json.MarshalIndent(tags, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(vulnDir(root), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(assetTagsPath(root), b, 0o600)
}

func removeAssetTag(root string, caller *Caller, match string) error {
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a tag is removed by a person")
	}
	tags, err := loadAssetTags(root)
	if err != nil {
		return err
	}
	kept := tags[:0:0]
	for _, t := range tags {
		if t.Match != match {
			kept = append(kept, t)
		}
	}
	if len(kept) == len(tags) {
		return fmt.Errorf("there is no tag for %s", match)
	}
	if err := saveAssetTags(root, kept); err != nil {
		return err
	}
	return recordE(root, audit.Record{Action: "vuln.asset.untagged",
		Resource: "/vuln/assets", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"match": match}})
}

func vulnTree(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo vuln ssvc-tree FILE\n" +
			"  the deployer decision table CERT/CC publishes as a CSV, in " +
			"its SSVC repository under data/csv/ssvc")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	b, err := readBounded(args[0], 1<<20)
	if err != nil {
		return err
	}
	tree, err := vuln.ParseTree(b)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(vulnDir(root), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(ssvcTreePath(root), b, 0o600); err != nil {
		return err
	}
	record(root, audit.Record{Action: "vuln.ssvc.tree", Resource: "/vuln",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified,
		Detail:   map[string]string{"rows": fmt.Sprint(len(tree))}})
	if !w.JSON(map[string]any{"rows": len(tree)}) {
		w.Human("%sthe decision table is loaded%s: %d combinations\n", bold,
			reset, len(tree))
		w.Human("  %stag assets with quilzo vuln asset, or every decision "+
			"is a range%s\n", dim, reset)
	}
	return nil
}

func vulnAsset(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("asset", flag.ContinueOnError)
	exposure := fs.String("exposure", "", "small, controlled or open")
	impact := fs.String("impact", "", "low, medium, high or very high")
	because := fs.String("because", "", "why")
	remove := fs.Bool("remove", false, "take the tag away")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo vuln asset ISSUER:VALUE|PREFIX* " +
			"--exposure open --impact high --because \"…\"")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if *remove {
		if err := removeAssetTag(root, caller, pos[0]); err != nil {
			return err
		}
		if !w.JSON(map[string]any{"removed": pos[0]}) {
			w.Human("removed\n")
		}
		return nil
	}
	tag := vuln.AssetTag{Match: pos[0], Exposure: strings.ToLower(*exposure),
		Impact: strings.ToLower(*impact), Because: *because}
	if err := setAssetTag(root, caller, tag); err != nil {
		return err
	}
	if !w.JSON(tag) {
		w.Human("%s%s%s is %s and its loss is %s\n", bold, tag.Match, reset,
			tag.Exposure, tag.Impact)
	}
	return nil
}

func vulnAssets(root string) error {
	tags, err := loadAssetTags(root)
	if err != nil {
		return err
	}
	v, err := loadVulnView(root, time.Now().UTC())
	if err != nil {
		return err
	}
	untagged := map[string]bool{}
	for _, c := range v.Inventory {
		if _, ok := tags.For(c.Where.String()); !ok {
			untagged[c.Where.String()] = true
		}
	}
	if w.JSON(map[string]any{"tags": tags, "untagged": len(untagged)}) {
		return nil
	}
	for _, t := range tags {
		w.Human("%s%-28s%s %-10s %-9s %s%s (%s)%s\n", bold, t.Match, reset,
			t.Exposure, t.Impact, dim, t.Because, t.By, reset)
	}
	if len(untagged) > 0 {
		w.Human("\n  %s%d asset(s) in the inventory have no tag, so their "+
			"decisions are ranges%s\n", yellow, len(untagged), reset)
	}
	return nil
}
