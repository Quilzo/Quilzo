// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/sca"
)

// Which dependencies are affected, and which of those anybody can fix.
//
// Every scanner reports that a vulnerable package is present. Almost none
// report whether the team reading it can do anything, and those are
// different questions — only the second is work. A direct dependency with a
// released fix is an afternoon. The same advisory four levels down is a
// conversation with whoever maintains the thing above it.
//
// `sca scan` reads a CycloneDX bill and a set of OSV advisories and sorts
// by what can be started today.

func cmdSCA(args []string) error {
	if len(args) == 0 {
		args = []string{"scan"}
	}
	switch args[0] {
	case "scan":
		return scaScan(args[1:])
	default:
		return fmt.Errorf("unknown sca command %q; try scan", args[0])
	}
}

func scaScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	bomPath := fs.String("bom", "", "a CycloneDX bill of materials")
	osvPath := fs.String("osv", "", "OSV advisories, one record or an array")
	where := fs.String("where", "prod", "which deployment this bill is of")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var bomRaw, osvRaw []byte
	if *bomPath == "" && *osvPath == "" {
		bomRaw, osvRaw = []byte(exampleBOM), []byte(exampleOSV)
		w.Human("%sno files given, so this reads a built-in example%s\n\n",
			dim, reset)
	} else {
		if *bomPath == "" || *osvPath == "" {
			return fmt.Errorf("give both --bom and --osv, or neither")
		}
		b, err := os.ReadFile(*bomPath)
		if err != nil {
			return err
		}
		o, err := os.ReadFile(*osvPath)
		if err != nil {
			return err
		}
		bomRaw, osvRaw = b, o
	}

	bom, err := sca.ReadBOM(bomRaw)
	if err != nil {
		return err
	}
	records, err := sca.ReadOSV(osvRaw)
	if err != nil {
		return err
	}
	rep := sca.Scan(bom, records, *where, time.Now().UTC())

	if w.JSON(map[string]any{"report": rep}) {
		return nil
	}

	w.Human("%s%d component(s), %d advisory match(es)%s\n\n", bold,
		rep.Components, len(rep.Hits), reset)

	if act := rep.Actionable(); len(act) > 0 {
		w.Human("%sstart today%s\n", bold, reset)
		for _, h := range act {
			c := h.Exposure.Component
			w.Human("  %s%-14s%s %s %s→ %s%s\n", green, h.Exposure.Advisory.ID,
				reset, c.Name+"@"+c.Version, dim, h.Fixed, reset)
		}
		w.Human("\n")
	}

	blocked := rep.Blocked()
	if len(blocked) > 0 {
		w.Human("%swaiting on somebody else%s\n", bold, reset)
		for name, hits := range blocked {
			w.Human("  %s%s%s\n", yellow, name, reset)
			for _, h := range hits {
				c := h.Exposure.Component
				w.Human("    %s%s in %s@%s, %d level(s) down%s\n", dim,
					h.Exposure.Advisory.ID, c.Name, c.Version, h.Depth,
					reset)
				w.Human("      %s%s%s\n", dim,
					strings.Join(h.Path, " → "), reset)
				if h.Fixed != "" {
					w.Human("      %sfixed in %s, which %s has not "+
						"taken%s\n", dim, h.Fixed, name, reset)
				}
			}
		}
		w.Human("  %sone package that has not moved can be holding up a "+
			"dozen\n  advisories. Seeing them as one conversation rather "+
			"than a dozen\n  tickets is the difference between chasing an "+
			"upstream and\n  chasing a queue%s\n\n", dim, reset)
	}

	var stuck []string
	for _, h := range rep.Hits {
		if h.Work == sca.Nothing {
			c := h.Exposure.Component
			stuck = append(stuck, fmt.Sprintf("%s in %s@%s",
				h.Exposure.Advisory.ID, c.Name, c.Version))
		}
	}
	if len(stuck) > 0 {
		w.Human("%sno fix exists%s\n", bold, reset)
		for _, s := range stuck {
			w.Human("  %s%s%s\n", dim, s, reset)
		}
		w.Human("  %s%s%s\n\n", dim,
			wrapAt(sca.Nothing.Why(), 64, "  "), reset)
	}

	if rep.Graphless {
		w.Human("  %s%s%s\n", yellow,
			wrapAt(sca.Unknown.Why(), 64, "  "), reset)
	}
	w.Human("  %s%s%s\n", dim, wrapAt(rep.Why(), 66, "  "), reset)
	return nil
}

const exampleBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "type": "application",
                             "name": "api", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "srv", "name": "server", "version": "3.0.0",
     "purl": "pkg:golang/github.com/acme/server@v3.0.0"},
    {"bom-ref": "mw", "name": "middleware", "version": "2.0.0",
     "purl": "pkg:golang/github.com/acme/middleware@v2.0.0"},
    {"bom-ref": "arc", "name": "archive", "version": "1.2.0",
     "purl": "pkg:golang/github.com/acme/archive@v1.2.0"},
    {"bom-ref": "tmpl", "name": "template", "version": "0.4.0",
     "purl": "pkg:golang/github.com/acme/template@v0.4.0"},
    {"bom-ref": "parser", "name": "parser", "version": "0.9.0",
     "purl": "pkg:golang/github.com/acme/parser@v0.9.0"}
  ],
  "dependencies": [
    {"ref": "root", "dependsOn": ["srv", "parser"]},
    {"ref": "srv", "dependsOn": ["mw", "tmpl"]},
    {"ref": "mw", "dependsOn": ["arc"]}
  ]
}`

const exampleOSV = `[
 {"id":"GHSA-arch","summary":"Path traversal in the archive reader",
  "severity":[{"type":"CVSS_V3",
    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected":[{"package":{"ecosystem":"Go",
    "name":"github.com/acme/archive"},
    "ranges":[{"type":"SEMVER",
      "events":[{"introduced":"1.0.0"},{"fixed":"1.4.2"}]}]}]},
 {"id":"GHSA-tmpl","summary":"Template injection",
  "severity":[{"type":"CVSS_V3",
    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
  "affected":[{"package":{"ecosystem":"Go",
    "name":"github.com/acme/template"},
    "ranges":[{"type":"SEMVER",
      "events":[{"introduced":"0"},{"fixed":"0.5.0"}]}]}]},
 {"id":"GHSA-pars","summary":"Stack exhaustion on deep input",
  "severity":[{"type":"CVSS_V3",
    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
  "affected":[{"package":{"ecosystem":"Go",
    "name":"github.com/acme/parser"},
    "ranges":[{"type":"SEMVER",
      "events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]},
 {"id":"GHSA-srv","summary":"Request smuggling, no fix released",
  "severity":[{"type":"CVSS_V3",
    "score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
  "affected":[{"package":{"ecosystem":"Go",
    "name":"github.com/acme/server"},
    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}
]`
