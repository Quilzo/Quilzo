// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/detect"
)

// The starter pack, installed as files.
//
// `detect pack` lists what ships. `detect pack install` copies the rules
// into the rules directory, where they are this organisation's: reviewed,
// tuned, put on trial or switched off like any other. A file that is
// already there is left alone, so an install after an upgrade adds what is
// new and changes nothing anybody has edited.

func detectPack(root string, args []string) error {
	files, err := detect.Pack()
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "list" {
		type row struct {
			ID, Title string
			Sources   []string
			Quiet     bool
		}
		var rows []row
		for _, f := range files {
			if !strings.HasSuffix(f.Name, ".json") {
				continue
			}
			var r detect.Rule
			if err := json.Unmarshal(f.Body, &r); err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
			rows = append(rows, row{r.ID, r.Title, r.Sources, r.Quiet})
		}
		if w.JSON(map[string]any{"rules": rows}) {
			return nil
		}
		for _, r := range rows {
			note := ""
			if r.Quiet {
				note = dim + "  counted by a correlation" + reset
			}
			w.Human("  %s%-36s%s %s%s\n", bold, r.ID, reset, r.Title, note)
		}
		w.Human("\n  %s%d rule(s), and correlations across platforms. "+
			"quilzo detect pack install copies them into the rules "+
			"directory, where they are yours to tune%s\n", dim, len(rows), reset)
		return nil
	}
	if args[0] != "install" {
		return fmt.Errorf("usage: quilzo detect pack [list | install " +
			"[--rules DIR]]")
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	rulesAt := fs.String("rules", "", "where the rules live")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	dir := *rulesAt
	if dir == "" {
		// In the store unless somebody keeps them elsewhere: a rules
		// directory that depends on where the command was run from is one
		// the server does not find.
		dir = filepath.Join(root, "detections")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	added, kept := 0, 0
	for _, f := range files {
		dest := filepath.Join(dir, f.Name)
		if _, err := os.Stat(dest); err == nil {
			kept++
			continue
		}
		if err := atomicfile.Write(dest, f.Body, 0o600); err != nil {
			return err
		}
		added++
	}
	record(root, audit.Record{Action: "detect.pack", Resource: "/detections",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{
			"added": fmt.Sprint(added), "kept": fmt.Sprint(kept)}})
	if w.JSON(map[string]any{"added": added, "kept": kept, "dir": dir}) {
		return nil
	}
	w.Human("%s%d file(s) added%s to %s; %d already there and left alone\n",
		bold, added, reset, dir, kept)
	w.Human("  %sthey run on the next quilzo detect run. A rule for a "+
		"platform you do not collect matches nothing and costs nothing%s\n",
		dim, reset)
	return nil
}
