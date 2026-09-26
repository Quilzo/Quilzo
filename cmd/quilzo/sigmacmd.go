// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/sigma"
)

// Bring your own rules, in the format they are already in.
//
// Every security product invents a detection language and the cost lands on
// the customer: rules written for one tool are worthless in the next, which
// is most of why replacing a SIEM takes a year. Sigma is the vendor-neutral
// answer, with a public repository of a few thousand community rules and
// converters into Splunk's SPL, Sentinel's KQL, Elastic and Chronicle's
// YARA-L.
//
// `sigma import` reads a directory of them and says exactly what came
// across, what did not, and — the part no product offering Sigma import
// says out loud — how many of the rules that did come across have never
// been shown to fire.

func cmdSigma(args []string) error {
	if len(args) == 0 {
		args = []string{"import"}
	}
	switch args[0] {
	case "import":
		return sigmaImport(args[1:])
	default:
		return fmt.Errorf("unknown sigma command %q; try import", args[0])
	}
}

func sigmaImport(args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	mapFile := fs.String("pipeline", "",
		"a JSON file mapping Sigma field names onto this program's event "+
			"fields")
	source := fs.String("source", "",
		"the connector these rules read, overriding their logsource")
	show := fs.Int("show", 8, "how many skipped rules to name")
	if err := fs.Parse(flags); err != nil {
		return err
	}

	files := map[string][]byte{}
	if len(pos) == 0 {
		// Nothing to read: show what the importer does against a rule
		// written here, so the command is useful without a corpus.
		files["example.yml"] = []byte(exampleRule)
		w.Human("%sno path given, so this reads one built-in rule%s\n\n",
			dim, reset)
	}
	for _, p := range pos {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			files[p] = b
			continue
		}
		err = filepath.WalkDir(p, func(path string, d os.DirEntry,
			err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yml", ".yaml":
			default:
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = b
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("no .yml or .yaml files under there")
	}

	pipe := sigma.Pipeline{Source: *source}
	if *mapFile != "" {
		var f struct {
			Fields map[string]string `json:"fields"`
			Source string            `json:"source"`
		}
		if err := loadJSON(*mapFile, &f); err != nil {
			return err
		}
		pipe.Fields = f.Fields
		if pipe.Source == "" {
			pipe.Source = f.Source
		}
	}

	rep := sigma.Import(files, pipe)
	if w.JSON(map[string]any{
		"read": rep.Read, "compiled": len(rep.Rules),
		"unproven": rep.Unproven(), "skipped": rep.Skipped,
		"loud": rep.Loud, "gaps": rep.Gaps(),
	}) {
		return nil
	}

	w.Human("%s%d of %d rule(s) compiled%s\n\n", bold, len(rep.Rules),
		rep.Read, reset)

	if ours := rep.Ours(); len(ours) > 0 {
		w.Human("  %sthis implementation does not do:%s\n", yellow, reset)
		for _, g := range rep.Gaps() {
			w.Human("    %s\n", g)
		}
		for i, s := range ours {
			if i >= *show {
				w.Human("    %s… and %d more%s\n", dim, len(ours)-*show,
					reset)
				break
			}
			w.Human("    %s%s%s\n", dim, s.Title, reset)
		}
		w.Human("\n")
	}
	if theirs := rep.Theirs(); len(theirs) > 0 {
		w.Human("  %sthese rules are malformed:%s\n", yellow, reset)
		for i, s := range theirs {
			if i >= *show {
				w.Human("    %s… and %d more%s\n", dim, len(theirs)-*show,
					reset)
				break
			}
			w.Human("    %s\n      %s%s%s\n", s.Title, dim,
				wrapAt(s.Why, 62, "      "), reset)
		}
		w.Human("\n")
	}

	if n := rep.Unproven(); n > 0 {
		w.Human("  %s%d of the %d that compiled have no fixture%s\n",
			yellow, n, len(rep.Rules), reset)
		w.Human("    %sSigma has nowhere to record an event a rule is\n"+
			"    asserted to match, so every rule in a community library\n"+
			"    arrives never having been demonstrated to do anything.\n"+
			"    Between 13 and 18 percent of deployed rules in this\n"+
			"    industry never fire under any input, and nothing about a\n"+
			"    rule's text reveals which ones. They will not load until\n"+
			"    somebody writes an event they should catch and one they\n"+
			"    should not%s\n\n", dim, reset)
	}
	if len(rep.Loud) > 0 {
		w.Human("  %s%d claim high or critical and say their false "+
			"positives are unknown%s\n", yellow, len(rep.Loud), reset)
		for i, t := range rep.Loud {
			if i >= *show {
				w.Human("    %s… and %d more%s\n", dim, len(rep.Loud)-*show,
					reset)
				break
			}
			w.Human("    %s%s%s\n", dim, t, reset)
		}
		w.Human("    %sthat pairing is a rule somebody wrote confidently\n"+
			"    without having run it anywhere%s\n", dim, reset)
	}
	return nil
}

// exampleRule is a rule in the shape the public corpus writes them, so the
// command demonstrates itself without a checkout of somebody else's
// repository.
const exampleRule = `
title: Suspicious Encoded PowerShell Command Line
id: 5b6b9b4b-1111-4c0f-9c3a-3f1a2b3c4d5e
status: test
description: Detects a base64 encoded command passed to PowerShell
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\powershell.exe'
        - OriginalFileName: 'PowerShell.EXE'
    selection_cli:
        CommandLine|contains|windash: '-enc'
    filter_main_known:
        ParentImage|startswith: 'C:\Program Files\Trusted\'
    condition: all of selection_* and not filter_main_known
falsepositives:
    - Unknown
level: high
tags:
    - attack.execution
    - attack.t1059.001
`
