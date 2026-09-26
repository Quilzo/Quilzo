// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/sarif"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The interchange format every code scanner already speaks.
//
// SARIF 2.1.0 won: Semgrep, CodeQL, ZAP, OSV-Scanner, Trivy and most of the
// rest emit it, and GitHub code scanning consumes it. One reader covers
// static analysis, dynamic analysis and dependency scanning; one writer
// puts results back where developers already look.
//
// `sarif read` imports a file and says what the tool left out — which is
// the useful part, because the field most tools omit is the one that
// decides whether an alert survives somebody reformatting the file.

func cmdSarif(args []string) error {
	if len(args) == 0 {
		args = []string{"read"}
	}
	switch args[0] {
	case "read":
		return sarifRead(args[1:])
	default:
		return fmt.Errorf("unknown sarif command %q; try read", args[0])
	}
}

func sarifRead(args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	repo := fs.String("repository", "",
		"which checkout these paths are relative to")
	show := fs.Int("show", 5, "how many alerts to print")
	out := fs.String("out", "",
		"write the alerts back out as SARIF to this path")
	if err := fs.Parse(flags); err != nil {
		return err
	}

	var raw []byte
	switch {
	case len(pos) == 1:
		b, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		raw = b
	case len(pos) > 1:
		return fmt.Errorf("one file at a time")
	default:
		raw = []byte(exampleSarif)
		w.Human("%sno path given, so this reads a built-in example in the "+
			"shape a scanner emits%s\n\n", dim, reset)
	}

	l, err := sarif.Read(raw)
	if err != nil {
		return err
	}
	rep := sarif.Convert(l, *repo)

	if w.JSON(map[string]any{
		"report": rep, "alerts": rep.Alerts, "limits": l.Check(),
	}) {
		return nil
	}

	w.Human("%s%d result(s) from %s%s\n", bold, rep.Read,
		strings.Join(rep.Tools, ", "), reset)
	if len(rep.Failed) > 0 {
		w.Human("  %s%d run(s) reported that the tool did not finish, so "+
			"this\n  file is not a clean scan and a low count means "+
			"nothing%s\n", yellow, len(rep.Failed), reset)
	}
	w.Human("\n")

	for i, a := range rep.Alerts {
		if i >= *show {
			w.Human("  %s… and %d more%s\n", dim, len(rep.Alerts)-*show,
				reset)
			break
		}
		w.Human("  %s%-9s%s %s:%d\n", severityColour(a.Severity),
			severityWord(a.Severity), reset, a.Path, a.Line)
		w.Human("    %s%s · %s%s\n", dim, a.Rule, a.Message, reset)
	}
	w.Human("\n")

	if len(rep.Gaps) == 0 {
		w.Human("  %sthis file carries everything a consumer needs%s\n",
			green, reset)
	}
	for _, g := range rep.Gaps {
		w.Human("  %s%d result(s) have %s%s\n", yellow, g.Count, g.What,
			reset)
		w.Human("    %s%s%s\n\n", dim, wrapAt(g.Costs, 64, "    "), reset)
	}
	if rep.Suppressed > 0 {
		w.Human("  %s%d were already dismissed by whoever ran the tool%s\n\n",
			dim, rep.Suppressed, reset)
	}
	for _, c := range l.Check() {
		w.Human("  %s%s%s\n", yellow, wrapAt(c, 64, "    "), reset)
	}

	if *out == "" {
		return nil
	}
	// Written back out with a fingerprint on every result, because
	// omitting it is the churn above and there is no reason to pass it on.
	written, err := sarif.Write("quilzo", "1.0.0", rep.Alerts,
		sarif.Provenance{})
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(written, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	w.Human("\n  %swrote %d result(s) to %s, every one with a "+
		"primaryLocationLineHash%s\n", dim, len(rep.Alerts), *out, reset)
	return nil
}

// exampleSarif is the shape a real scanner emits, including the field most
// of them leave out.
const exampleSarif = `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "semgrep", "version": "1.90.0", "rules": [
      {"id": "go.lang.security.audit.dangerous-exec",
       "shortDescription": {"text": "Command built from user input"},
       "defaultConfiguration": {"level": "error"},
       "properties": {"tags": ["security", "CWE-78"],
                      "security-severity": "8.6"}},
      {"id": "generic.secrets.aws-key",
       "shortDescription": {"text": "AWS key in source"},
       "properties": {"tags": ["secret"], "security-severity": "9.4"}},
      {"id": "go.lang.correctness.unused",
       "shortDescription": {"text": "Unused assignment"},
       "defaultConfiguration": {"level": "warning"}}
    ]}},
    "results": [
      {"ruleId": "go.lang.security.audit.dangerous-exec", "ruleIndex": 0,
       "level": "error",
       "message": {"text": "exec.Command built from a request field"},
       "locations": [{"physicalLocation": {
         "artifactLocation": {"uri": "internal/api/run.go"},
         "region": {"startLine": 42,
                    "snippet": {"text": "exec.Command(sh, in)"}}},
         "logicalLocations": [{"fullyQualifiedName": "api.Run"}]}],
       "partialFingerprints": {"primaryLocationLineHash": "8f2a11c4"}},
      {"ruleId": "generic.secrets.aws-key", "ruleIndex": 1,
       "level": "warning", "message": {"text": "AWS key in a deploy script"},
       "locations": [{"physicalLocation": {
         "artifactLocation": {"uri": "deploy/env.sh"},
         "region": {"startLine": 7}}}]},
      {"ruleId": "go.lang.correctness.unused", "ruleIndex": 2,
       "level": "warning", "message": {"text": "value never read"},
       "locations": [{"physicalLocation": {
         "artifactLocation": {"uri": "internal/api/run.go"},
         "region": {"startLine": 88}}}],
       "suppressions": [{"kind": "inSource", "status": "accepted",
                         "justification": "kept for the next refactor"}]},
      {"ruleId": "generic.secrets.aws-key", "ruleIndex": 1,
       "level": "error", "message": {"text": "key with no location"}}
    ]
  }]
}`

// severityColour picks a colour for a severity, so a queue can be skimmed.
func severityColour(s telemetry.Severity) string {
	switch {
	case s >= telemetry.SeverityHigh:
		return yellow
	case s >= telemetry.SeverityMedium:
		return bold
	default:
		return dim
	}
}

// severityWord spells a severity out.
//
// Local rather than a String method on telemetry.Severity: that type is
// OCSF's severity_id and prints as its number in a dozen places that
// expect one, and giving it a String would quietly change all of them.
func severityWord(s telemetry.Severity) string {
	switch s {
	case telemetry.SeverityCritical:
		return "critical"
	case telemetry.SeverityHigh:
		return "high"
	case telemetry.SeverityMedium:
		return "medium"
	case telemetry.SeverityLow:
		return "low"
	case telemetry.SeverityInfo:
		return "info"
	}
	return "unknown"
}
