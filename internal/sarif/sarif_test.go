// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
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

// The fixture is the one the reader's source repository tests with, byte
// for byte: the same digest is held there, so a change to either copy's
// fixture is a change to both readers' tests, and is seen.
func TestFixtureDigestShared(t *testing.T) {
	sum := sha256.Sum256([]byte(semgrepish))
	if got := hex.EncodeToString(sum[:]); got != "e976bf8f6764e07880cb61f00d1a832751870df65b064f601b3e1e1ec8c16518" {
		t.Fatalf("the shared SARIF fixture changed: its digest is %s", got)
	}
}

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

	gap, ok := gapNamed(l.Gaps(), "primaryLocationLineHash")
	if !ok {
		t.Fatal("no gap reported for the missing fingerprint")
	}
	if gap.Count != 1 || gap.From != "semgrep" {
		t.Fatalf("the gap counts %d, from %q", gap.Count, gap.From)
	}
	for _, want := range []string{"editing it closes the alert", "scanner is noisy"} {
		if !strings.Contains(gap.Costs, want) {
			t.Fatalf("the cost does not mention %q: %s", want, gap.Costs)
		}
	}
}

// gapNamed is the gap whose What says what, if there is one.
func gapNamed(gaps []Gap, what string) (Gap, bool) {
	for _, g := range gaps {
		if strings.Contains(g.What, what) {
			return g, true
		}
	}
	return Gap{}, false
}

// TestSecuritySeverityBeatsLevel: a level is not a severity.
func TestSecuritySeverityBeatsLevel(t *testing.T) {
	l, err := Read([]byte(semgrepish))
	if err != nil {
		t.Fatal(err)
	}
	run := l.Runs[0]
	// 8.6 is high even though the level says error, and 9.4 is critical
	// even though the level says warning, which is the whole point.
	if s, scored := run.SeverityOf(run.Results[0]); s != SeverityHigh || !scored {
		t.Fatalf("8.6 became %v (scored %v)", s, scored)
	}
	if s, scored := run.SeverityOf(run.Results[1]); s != SeverityCritical || !scored {
		t.Fatalf("9.4 became %v (scored %v); the level said warning", s, scored)
	}
	if _, ok := gapNamed(l.Gaps(), "security-severity"); ok {
		t.Fatal("a log whose every result has a security severity fell back to the level")
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
	if s, scored := bl.Runs[0].SeverityOf(bl.Runs[0].Results[0]); s != SeverityHigh || scored {
		t.Fatalf("error became %v (scored %v)", s, scored)
	}
	gap, ok := gapNamed(bl.Gaps(), "security-severity")
	if !ok {
		t.Fatal("no gap for the missing severity")
	}
	if gap.Count != 1 || !strings.Contains(gap.Costs, "wrong axis") {
		t.Fatalf("the gap counts %d and costs %s", gap.Count, gap.Costs)
	}

	// A rule's default level stands in where the result gives none.
	ruled := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[{"id":"r",
		"defaultConfiguration":{"level":"warning"}}]}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`
	rl, err := Read([]byte(ruled))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := rl.Runs[0].SeverityOf(rl.Runs[0].Results[0]); s != SeverityMedium {
		t.Fatalf("a rule's warning became %v", s)
	}
}

// TestScoreBoundariesAreThePublishedOnes.
func TestScoreBoundariesAreThePublishedOnes(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want Severity
	}{
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
	} {
		if got := score(c.in); got != c.want {
			t.Errorf("%.1f became %v, want %v", c.in, got, c.want)
		}
	}
	// A number as well as a string, because tools do both.
	var asNumber Properties
	if err := json.Unmarshal([]byte(`{"security-severity":7.5}`), &asNumber); err != nil {
		t.Fatal(err)
	}
	if f, ok := asNumber.Score(); !ok || f != 7.5 {
		t.Fatalf("number form = %v, %v", f, ok)
	}
	var asString Properties
	if err := json.Unmarshal([]byte(`{"security-severity":"7.5"}`), &asString); err != nil {
		t.Fatal(err)
	}
	if f, ok := asString.Score(); !ok || f != 7.5 {
		t.Fatalf("string form = %v, %v", f, ok)
	}
	if len(Severities) != 4 || Severities[0] != SeverityLow || Severities[3] != SeverityCritical {
		t.Fatalf("the severities, lowest first, are %v", Severities)
	}
}

func TestKindsComeFromTags(t *testing.T) {
	l, err := Read([]byte(semgrepish))
	if err != nil {
		t.Fatal(err)
	}
	run := l.Runs[0]
	if k := run.KindOf(run.Results[0]); k != KindWeakness {
		t.Fatalf("kind = %v", k)
	}
	if k := run.KindOf(run.Results[1]); k != KindSecret {
		t.Fatalf("a rule tagged secret became %v", k)
	}
	for tags, want := range map[string]Kind{
		`["dependency"]`: KindDependency, `["supply-chain"]`: KindDependency,
		`["iac","terraform"]`: KindConfiguration, `["misconfiguration"]`: KindConfiguration,
	} {
		src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[{"id":"r","properties":{"tags":` +
			tags + `}}]}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`
		tl, err := Read([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if k := tl.Runs[0].KindOf(tl.Runs[0].Results[0]); k != want {
			t.Errorf("a rule tagged %s became %v, not %v", tags, k, want)
		}
	}
}

// TestAResultWithNowhereToGoIsAGap: a finding nobody can open is a number
// rather than work, and the log is said to hold it.
func TestAResultWithNowhereToGoIsAGap(t *testing.T) {
	src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
		"results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}`
	l, err := Read([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if l.Count() != 1 {
		t.Fatalf("read = %d", l.Count())
	}
	if _, _, ok := l.Runs[0].Results[0].Where(); ok {
		t.Fatal("a result with no location was given one")
	}
	gap, ok := gapNamed(l.Gaps(), "no file location")
	if !ok {
		t.Fatal("no gap for the missing location")
	}
	if gap.Count != 1 || !strings.Contains(gap.Costs, "rather than work") {
		t.Fatalf("the gap counts %d and costs %s", gap.Count, gap.Costs)
	}
}

func TestAFailedRunIsReported(t *testing.T) {
	src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"zap"}},
		"invocations":[{"executionSuccessful":false}],"results":[]}]}`
	l, err := Read([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !l.Runs[0].Failed() {
		t.Fatal("a run whose tool did not finish is not reported")
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
	checks := l.Check()
	if len(checks) == 0 {
		t.Fatal("Check said nothing about a run past the display cap")
	}
	if !strings.Contains(strings.Join(checks, " "), "invisible") {
		t.Fatalf("checks = %v", checks)
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

// A log made to hurt its reader is refused before it is decoded: too
// deep, a key given twice, cut short, or larger than any scanner writes.
func TestHostileLogsRefused(t *testing.T) {
	for what, src := range map[string]string{
		"nested past the limit": `{"version":"2.1.0","runs":[` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + `]}`,
		"a key given twice":     `{"version":"2.1.0","version":"2.0.0","runs":[{"tool":{"driver":{"name":"x"}}}]}`,
		"cut short":             `{"version":"2.1.0","runs":[`,
	} {
		if _, err := Read([]byte(src)); err == nil {
			t.Errorf("a log %s is read", what)
		}
	}
	if _, err := Read(make([]byte, MaxBytes+1)); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("a log larger than the limit: %v", err)
	}
}
