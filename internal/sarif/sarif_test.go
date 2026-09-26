// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sarif

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/appsec"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// semgrepish is the shape Semgrep emits: rules in the driver, a
// security-severity property, and a fingerprint.
const semgrepish = `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "version": "1.90.0",
          "rules": [
            {
              "id": "go.lang.security.audit.dangerous-exec",
              "name": "dangerous-exec",
              "shortDescription": {"text": "Command built from user input"},
              "defaultConfiguration": {"level": "error"},
              "properties": {
                "tags": ["security", "CWE-78"],
                "precision": "high",
                "security-severity": "8.6"
              }
            },
            {
              "id": "generic.secrets.aws-key",
              "shortDescription": {"text": "AWS key in source"},
              "properties": {"tags": ["secret"], "security-severity": "9.4"}
            }
          ]
        }
      },
      "versionControlProvenance": [
        {"repositoryUri": "https://github.com/acme/api",
         "revisionId": "deadbeef", "branch": "main"}
      ],
      "results": [
        {
          "ruleId": "go.lang.security.audit.dangerous-exec",
          "ruleIndex": 0,
          "level": "error",
          "message": {"text": "exec.Command built from a request field"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "internal/api/run.go"},
                "region": {"startLine": 42, "snippet": {"text": "exec.Command(sh, in)"}}
              },
              "logicalLocations": [{"fullyQualifiedName": "api.Run"}]
            }
          ],
          "partialFingerprints": {"primaryLocationLineHash": "abc123"}
        },
        {
          "ruleId": "generic.secrets.aws-key",
          "ruleIndex": 1,
          "level": "warning",
          "message": {"text": "AWS key"},
          "locations": [
            {"physicalLocation": {
              "artifactLocation": {"uri": "deploy/env.sh"},
              "region": {"startLine": 7}}}
          ]
        }
      ]
    }
  ]
}`

func TestReadsWhatAScannerActuallyEmits(t *testing.T) {
	l, err := Read([]byte(semgrepish))
	if err != nil {
		t.Fatal(err)
	}
	if l.Count() != 2 {
		t.Fatalf("%d result(s)", l.Count())
	}
	if got := l.Tools(); len(got) != 1 || got[0] != "semgrep 1.90.0" {
		t.Fatalf("tools = %v", got)
	}
	run := l.Runs[0]
	r, ok := run.Rule(run.Results[0])
	if !ok || r.Name != "dangerous-exec" {
		t.Fatalf("rule = %+v, found = %v", r, ok)
	}
	p, line, ok := run.Results[0].Where()
	if !ok || p != "internal/api/run.go" || line != 42 {
		t.Fatalf("where = %q:%d", p, line)
	}
}

func TestRefusesWhatIsNotSARIF(t *testing.T) {
	for _, c := range []struct{ name, src, says string }{
		{"not json", "{", "not JSON"},
		{"no version", `{"runs":[]}`, "no version"},
		{"another version",
			`{"version":"2.0.0","runs":[{"tool":{"driver":{"name":"x"}}}]}`,
			"SARIF 2.0.0"},
		{"no runs", `{"version":"2.1.0","runs":[]}`, "no runs"},
	} {
		_, err := Read([]byte(c.src))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestTheMissingFingerprintIsReported is the churn nobody attributes
// correctly.
func TestTheMissingFingerprintIsReported(t *testing.T) {
	l, err := Read([]byte(semgrepish))
	if err != nil {
		t.Fatal(err)
	}
	if l.Runs[0].Results[0].Churns() {
		t.Fatal("a result with a line hash was said to churn")
	}
	if !l.Runs[0].Results[1].Churns() {
		t.Fatal("a result with no fingerprint at all was not")
	}

	rep := Convert(l, "acme/api")
	if rep.Churn != 1 {
		t.Fatalf("churn = %d", rep.Churn)
	}
	var gap *Gap
	for i := range rep.Gaps {
		if strings.Contains(rep.Gaps[i].What, "primaryLocationLineHash") {
			gap = &rep.Gaps[i]
		}
	}
	if gap == nil {
		t.Fatal("no gap reported for the missing fingerprint")
	}
	for _, want := range []string{"editing it closes the alert",
		"scanner is noisy", "semgrep"} {
		if !strings.Contains(gap.Costs, want) {
			t.Fatalf("the cost does not mention %q: %s", want, gap.Costs)
		}
	}
	if !strings.Contains(rep.Why(), "every time their line is edited") {
		t.Fatalf("why = %q", rep.Why())
	}
}

// TestSecuritySeverityBeatsLevel — a level is not a severity.
func TestSecuritySeverityBeatsLevel(t *testing.T) {
	l, err := Read([]byte(semgrepish))
	if err != nil {
		t.Fatal(err)
	}
	rep := Convert(l, "acme/api")
	if len(rep.Alerts) != 2 {
		t.Fatalf("%d alert(s)", len(rep.Alerts))
	}
	// 8.6 is high even though the level says error, and 9.4 is critical
	// even though the level says warning — which is the whole point.
	if rep.Alerts[0].Severity != telemetry.SeverityHigh {
		t.Fatalf("8.6 became %v", rep.Alerts[0].Severity)
	}
	if rep.Alerts[1].Severity != telemetry.SeverityCritical {
		t.Fatalf("9.4 became %v; the level said warning", rep.Alerts[1].Severity)
	}
	if rep.Levelled != 0 {
		t.Fatalf("%d fell back to the level", rep.Levelled)
	}

	// A tool that gives only a level is counted.
	bare := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
		"results":[{"ruleId":"r","level":"error","message":{"text":"m"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},
		"region":{"startLine":1}}}]}]}]}`
	bl, err := Read([]byte(bare))
	if err != nil {
		t.Fatal(err)
	}
	br := Convert(bl, "acme/api")
	if br.Levelled != 1 {
		t.Fatalf("levelled = %d", br.Levelled)
	}
	if br.Alerts[0].Severity != telemetry.SeverityHigh {
		t.Fatalf("error became %v", br.Alerts[0].Severity)
	}
	found := false
	for _, g := range br.Gaps {
		if strings.Contains(g.What, "security-severity") {
			found = true
			if !strings.Contains(g.Costs, "wrong axis") {
				t.Fatalf("cost = %s", g.Costs)
			}
		}
	}
	if !found {
		t.Fatal("no gap for the missing severity")
	}
}

// TestScoreBoundariesAreThePublishedOnes.
func TestScoreBoundariesAreThePublishedOnes(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want telemetry.Severity
	}{
		{9.0, telemetry.SeverityCritical},
		{8.9, telemetry.SeverityHigh},
		{7.0, telemetry.SeverityHigh},
		{6.9, telemetry.SeverityMedium},
		{4.0, telemetry.SeverityMedium},
		{3.9, telemetry.SeverityLow},
		{0.1, telemetry.SeverityLow},
	} {
		if got := score(c.in); got != c.want {
			t.Errorf("%.1f became %v, want %v", c.in, got, c.want)
		}
	}
	// A number as well as a string, because tools do both.
	var asNumber Properties
	if err := json.Unmarshal([]byte(`{"security-severity":7.5}`),
		&asNumber); err != nil {
		t.Fatal(err)
	}
	if f, ok := asNumber.Score(); !ok || f != 7.5 {
		t.Fatalf("number form = %v, %v", f, ok)
	}
	var asString Properties
	if err := json.Unmarshal([]byte(`{"security-severity":"7.5"}`),
		&asString); err != nil {
		t.Fatal(err)
	}
	if f, ok := asString.Score(); !ok || f != 7.5 {
		t.Fatalf("string form = %v, %v", f, ok)
	}
}

func TestKindsComeFromTags(t *testing.T) {
	l, err := Read([]byte(semgrepish))
	if err != nil {
		t.Fatal(err)
	}
	rep := Convert(l, "acme/api")
	if rep.Alerts[0].Kind != appsec.Weakness {
		t.Fatalf("kind = %v", rep.Alerts[0].Kind)
	}
	if rep.Alerts[1].Kind != appsec.Secret {
		t.Fatalf("a rule tagged secret became %v", rep.Alerts[1].Kind)
	}
}

// TestAResultWithNowhereToGoIsNotAnAlert.
func TestAResultWithNowhereToGoIsNotAnAlert(t *testing.T) {
	src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
		"results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}`
	l, err := Read([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	rep := Convert(l, "acme/api")
	if rep.Read != 1 {
		t.Fatalf("read = %d", rep.Read)
	}
	if len(rep.Alerts) != 0 {
		t.Fatal("a result with no location became an alert")
	}
	if rep.Placeless != 1 {
		t.Fatalf("placeless = %d", rep.Placeless)
	}
	found := false
	for _, g := range rep.Gaps {
		if strings.Contains(g.What, "no file location") {
			found = true
			if !strings.Contains(g.Costs, "rather than work") {
				t.Fatalf("cost = %s", g.Costs)
			}
		}
	}
	if !found {
		t.Fatal("no gap for the missing location")
	}
}

func TestAFailedRunIsReported(t *testing.T) {
	src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"zap"}},
		"invocations":[{"executionSuccessful":false}],"results":[]}]}`
	l, err := Read([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	rep := Convert(l, "acme/api")
	if len(rep.Failed) != 1 || rep.Failed[0] != "zap" {
		t.Fatalf("failed = %v", rep.Failed)
	}
	if !strings.Contains(rep.Why(), "did not finish") {
		t.Fatalf("why = %q", rep.Why())
	}
}

func TestSuppressionsAreCounted(t *testing.T) {
	src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
		"results":[{"ruleId":"r","message":{"text":"m"},
		"suppressions":[{"kind":"inSource","status":"accepted",
		"justification":"reviewed, the input is constant"}],
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},
		"region":{"startLine":1}}}]}]}]}`
	l, err := Read([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	why, yes := l.Runs[0].Results[0].Suppressed()
	if !yes || !strings.Contains(why, "input is constant") {
		t.Fatalf("suppressed = %v, %q", yes, why)
	}
	if Convert(l, "acme/api").Suppressed != 1 {
		t.Fatal("the suppression was not counted")
	}
}

// TestTheGapBetweenAcceptedAndDisplayed.
func TestTheGapBetweenAcceptedAndDisplayed(t *testing.T) {
	run := Run{Tool: Tool{Driver: Component{Name: "noisy"}}}
	for i := range MaxShown + 1200 {
		run.Results = append(run.Results, Result{
			RuleID: "r", Message: Text{Text: "m"},
			Locations: []Location{{Physical: &Physical{
				Artifact: Artifact{URI: fmt.Sprintf("f%d.go", i)},
				Region:   &Region{StartLine: 1}}}},
		})
	}
	l := Log{Version: Version, Runs: []Run{run}}
	rep := Convert(l, "acme/api")
	if rep.Hidden != 1200 {
		t.Fatalf("hidden = %d", rep.Hidden)
	}
	checks := l.Check()
	if len(checks) == 0 {
		t.Fatal("Check said nothing about a run past the display cap")
	}
	if !strings.Contains(strings.Join(checks, " "), "invisible") {
		t.Fatalf("checks = %v", checks)
	}
	if !strings.Contains(rep.Why(), "uploaded and not shown") {
		t.Fatalf("why = %q", rep.Why())
	}
}

// TestWriteAlwaysEmitsAFingerprint is the other half: never pass the churn
// on to whoever receives this.
func TestWriteAlwaysEmitsAFingerprint(t *testing.T) {
	alerts := []appsec.Alert{
		{Tool: "quilzo", Rule: "hardcoded-key", Kind: appsec.Secret,
			Message: "a key in source", Severity: telemetry.SeverityCritical,
			Path: "deploy/env.sh", Line: 7, Snippet: "KEY=abc",
			Symbol: "deploy"},
		{Tool: "quilzo", Rule: "hardcoded-key", Kind: appsec.Secret,
			Message: "another", Severity: telemetry.SeverityHigh,
			Path: "deploy/other.sh", Line: 3, Given: "carried-through"},
	}
	l, err := Write("quilzo", "1.0.0", alerts,
		Provenance{RepositoryURI: "https://github.com/acme/api",
			RevisionID: "deadbeef", Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if l.Version != Version || l.Schema != Schema {
		t.Fatalf("version %q schema %q", l.Version, l.Schema)
	}
	run := l.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("%d result(s)", len(run.Results))
	}
	// One rule, referenced twice by index.
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("%d rule(s)", len(run.Tool.Driver.Rules))
	}
	for i, res := range run.Results {
		if res.Churns() {
			t.Fatalf("result %d was written without a fingerprint", i)
		}
		if res.RuleIndex == nil || *res.RuleIndex != 0 {
			t.Fatalf("result %d has index %v", i, res.RuleIndex)
		}
		if _, ok := res.Properties.Score(); !ok {
			t.Fatalf("result %d carries no security severity", i)
		}
	}
	// A tool's own fingerprint is carried through rather than recomputed.
	if got := run.Results[1].
		PartialFingerprints["primaryLocationLineHash"]; got != "carried-through" {
		t.Fatalf("fingerprint = %q", got)
	}
	if run.Provenance[0].RevisionID != "deadbeef" {
		t.Fatal("the commit did not survive")
	}
	if _, err := Write("", "1.0.0", alerts, Provenance{}); err == nil {
		t.Fatal("a run with no tool name was written")
	}
}

// TestRoundTrip: what this writes, this reads, and the severities survive.
func TestRoundTrip(t *testing.T) {
	in := []appsec.Alert{
		{Tool: "quilzo", Rule: "a", Kind: appsec.Weakness, Message: "m",
			Severity: telemetry.SeverityCritical, Path: "x.go", Line: 1},
		{Tool: "quilzo", Rule: "b", Kind: appsec.Dependency, Message: "m",
			Severity: telemetry.SeverityMedium, Path: "go.mod", Line: 2},
		{Tool: "quilzo", Rule: "c", Kind: appsec.Secret, Message: "m",
			Severity: telemetry.SeverityLow, Path: "y.sh", Line: 3},
	}
	l, err := Write("quilzo", "1.0.0", in, Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Read(b)
	if err != nil {
		t.Fatalf("what we wrote does not parse: %v", err)
	}
	rep := Convert(back, "acme/api")
	if len(rep.Alerts) != len(in) {
		t.Fatalf("%d alert(s) back from %d", len(rep.Alerts), len(in))
	}
	if rep.Churn != 0 || rep.Levelled != 0 || rep.Placeless != 0 {
		t.Fatalf("our own output has gaps: %+v", rep.Gaps)
	}
	for i, a := range rep.Alerts {
		if a.Severity != in[i].Severity {
			t.Errorf("%s: severity %v became %v", in[i].Rule,
				in[i].Severity, a.Severity)
		}
		if a.Path != in[i].Path || a.Line != in[i].Line {
			t.Errorf("%s: %s:%d became %s:%d", in[i].Rule, in[i].Path,
				in[i].Line, a.Path, a.Line)
		}
		if a.Kind != in[i].Kind {
			t.Errorf("%s: kind %v became %v", in[i].Rule, in[i].Kind, a.Kind)
		}
	}
}

// TestLineHashSurvivesReformattingAround it.
func TestLineHashSurvivesReformatting(t *testing.T) {
	a := LineHash("a/b.go", "exec.Command(sh, in)")
	b := LineHash("a/b.go", "  exec.Command(sh,   in)  ")
	if a != b {
		t.Fatal("whitespace changed the fingerprint, which is the churn " +
			"this exists to avoid")
	}
	if a == LineHash("a/c.go", "exec.Command(sh, in)") {
		t.Fatal("the same line in two files has one fingerprint")
	}
	if a == LineHash("a/b.go", "exec.Command(sh, other)") {
		t.Fatal("a different line has the same fingerprint")
	}
}
