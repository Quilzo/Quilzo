// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sigma

import (
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// A rule in the shape SigmaHQ actually publishes them.
const realish = `
title: Suspicious Encoded PowerShell Command Line
id: 5b6b9b4b-1111-4c0f-9c3a-3f1a2b3c4d5e
status: test
description: Detects a base64 encoded command passed to PowerShell
references:
    - https://example.invalid/writeup
author: somebody
date: 2026-01-09
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
    - Administrative scripts that encode their arguments
level: high
tags:
    - attack.execution
    - attack.t1059.001
`

// ev builds an event whose source the rule reads and whose fields are the
// ones the rule names. Arbitrary source fields live in Raw.
func ev(source string, f map[string]string) telemetry.Event {
	return telemetry.Event{Source: source, Raw: f}
}

func read(t *testing.T, src string) Rule {
	t.Helper()
	rs, err := Read([]byte(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("%d rule(s)", len(rs))
	}
	return rs[0]
}

func TestReadsARuleInTheShapeTheyAreWritten(t *testing.T) {
	r := read(t, realish)
	if r.Title != "Suspicious Encoded PowerShell Command Line" {
		t.Fatalf("title = %q", r.Title)
	}
	if r.LogSource.Name() != "windows/process_creation" {
		t.Fatalf("logsource = %q", r.LogSource.Name())
	}
	if len(r.References) != 1 ||
		!strings.HasPrefix(r.References[0], "https://") {
		t.Fatalf("references = %v", r.References)
	}
	if r.Condition != "all of selection_* and not filter_main_known" {
		t.Fatalf("condition = %q", r.Condition)
	}
	if len(r.FalsePositives) != 1 {
		t.Fatalf("falsepositives = %v", r.FalsePositives)
	}
	if len(r.Detection) != 3 {
		t.Fatalf("%d selection(s)", len(r.Detection))
	}
}

// TestItCompilesAndThenActuallyMatches: parsing is not the claim, running
// is. The compiled rule is driven against events.
func TestItCompilesAndThenActuallyMatches(t *testing.T) {
	c, err := read(t, realish).Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// A compiled Sigma rule carries no fixtures, because the format has
	// no place for them. internal/detect refuses a rule nothing has shown
	// can fire, and that refusal is the honest news about importing a
	// community library.
	if err := c.Validate(); err == nil {
		t.Fatal("an imported rule with no fixture validated")
	} else if !strings.Contains(err.Error(), "fixture") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if c.Severity != telemetry.SeverityHigh {
		t.Fatalf("severity = %v", c.Severity)
	}
	if !strings.Contains(c.Blind, "Administrative scripts") {
		t.Fatalf("the false positives did not reach Blind: %q", c.Blind)
	}
	if len(c.Technique) != 1 || c.Technique[0] != "T1059.001" {
		t.Fatalf("technique = %v", c.Technique)
	}

	for _, tc := range []struct {
		name  string
		ev    map[string]string
		match bool
	}{
		{"powershell with an encoded command", map[string]string{
			"Image":       `C:\Windows\System32\WindowsPowerShell\powershell.exe`,
			"CommandLine": `powershell.exe -enc SQBFAFgA`,
			"ParentImage": `C:\Windows\explorer.exe`,
		}, true},
		{"the windash variant", map[string]string{
			"Image":       `C:\powershell.exe`,
			"CommandLine": `powershell /enc SQBFAFgA`,
			"ParentImage": `C:\Windows\explorer.exe`,
		}, true},
		{"matched by original file name instead", map[string]string{
			"Image":            `C:\Windows\renamed.exe`,
			"OriginalFileName": "PowerShell.EXE",
			"CommandLine":      `renamed.exe -enc SQBFAFgA`,
			"ParentImage":      `C:\Windows\explorer.exe`,
		}, true},
		{"the excluded parent", map[string]string{
			"Image":       `C:\powershell.exe`,
			"CommandLine": `powershell -enc SQBFAFgA`,
			"ParentImage": `C:\Program Files\Trusted\runner.exe`,
		}, false},
		{"powershell with no encoded command", map[string]string{
			"Image":       `C:\powershell.exe`,
			"CommandLine": `powershell -File c:\ok.ps1`,
			"ParentImage": `C:\Windows\explorer.exe`,
		}, false},
		{"something else entirely", map[string]string{
			"Image":       `C:\Windows\cmd.exe`,
			"CommandLine": `cmd /c dir`,
			"ParentImage": `C:\Windows\explorer.exe`,
		}, false},
	} {
		got := c.Matches(ev("windows/process_creation", tc.ev))
		if got != tc.match {
			t.Errorf("%s: matched = %v, want %v", tc.name, got, tc.match)
		}
	}
}

func TestModifiersCompileToTheRightOperators(t *testing.T) {
	src := `
title: modifiers
logsource:
    product: test
detection:
    sel:
        A|contains: 'x'
        B|startswith: 'y'
        C|endswith: 'z'
        D|re: '^a.*b$'
        E|cidr: '10.0.0.0/8'
        F|gt: '100'
        G: null
    condition: sel
level: low
`
	c, err := read(t, src).Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	want := map[string]detect.Op{
		"raw.A": detect.Contains, "raw.B": detect.Prefix,
		"raw.C": detect.Suffix, "raw.D": detect.Matches,
		"raw.E": detect.Inside, "raw.F": detect.Above,
	}
	found := map[string]detect.Op{}
	var walk func(detect.Predicate)
	walk = func(p detect.Predicate) {
		if p.Match != nil {
			found[p.Match.Field] = p.Match.Op
		}
		for _, q := range append(append([]detect.Predicate{}, p.All...),
			p.Any...) {
			walk(q)
		}
		if p.Not != nil {
			walk(*p.Not)
		}
	}
	walk(c.When)
	for f, op := range want {
		if found[f] != op {
			t.Errorf("%s compiled to %q, want %q", f, found[f], op)
		}
	}
	if found["raw.G"] != detect.Exists {
		t.Errorf("null compiled to %q, want a negated exists",
			found["raw.G"])
	}

	// And the CIDR test actually works, which string matching would not.
	f := map[string]string{
		"A": "axb", "B": "ybc", "C": "abz", "D": "aQQb",
		"E": "10.3.4.5", "F": "101",
	}
	if !c.Matches(ev("test", f)) {
		t.Fatal("the compiled rule did not match an event it describes")
	}
	f["E"] = "11.3.4.5"
	if c.Matches(ev("test", f)) {
		t.Fatal("an address outside the block matched")
	}
}

func TestBase64OffsetFindsTheStringWhereverItStarts(t *testing.T) {
	src := `
title: encoded
logsource:
    product: test
detection:
    sel:
        CommandLine|base64offset|contains: 'whoami'
    condition: sel
level: low
`
	c, err := read(t, src).Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// The same string encoded at each of the three offsets. A naive
	// base64 modifier matches one of these.
	for pad, blob := range map[int]string{
		0: "d2hvYW1p", 1: "B3aG9hbWk", 2: "13aG9hbWk",
	} {
		if !c.Matches(ev("test", map[string]string{
			"CommandLine": "powershell -enc " + blob,
		})) {
			t.Errorf("offset %d (%s) did not match", pad, blob)
		}
	}
	if c.Matches(ev("test", map[string]string{
		"CommandLine": "powershell -enc bm90aGluZw",
	})) {
		t.Error("an unrelated blob matched")
	}
}

// TestAListOfMapsIsAlternativesAndAMapIsConjunction — the asymmetry most
// often misread.
func TestAListOfMapsIsAlternativesAndAMapIsConjunction(t *testing.T) {
	either := read(t, `
title: either
logsource:
    product: test
detection:
    sel:
        - A: '1'
        - B: '2'
    condition: sel
level: low
`)
	both := read(t, `
title: both
logsource:
    product: test
detection:
    sel:
        A: '1'
        B: '2'
    condition: sel
level: low
`)
	ce, err := either.Compile()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := both.Compile()
	if err != nil {
		t.Fatal(err)
	}
	one := ev("test", map[string]string{"A": "1"})
	if !ce.Matches(one) {
		t.Error("a list of maps should be alternatives")
	}
	if cb.Matches(one) {
		t.Error("a map should require every key")
	}
	if !cb.Matches(ev("test", map[string]string{"A": "1", "B": "2"})) {
		t.Error("both present did not match")
	}
}

func TestConditionLanguage(t *testing.T) {
	base := `
title: conditions
logsource:
    product: test
detection:
    sel_a:
        A: '1'
    sel_b:
        B: '2'
    filt:
        C: '3'
    condition: %s
level: low
`
	for _, tc := range []struct {
		cond  string
		ev    map[string]string
		match bool
	}{
		{"sel_a and sel_b", map[string]string{"A": "1", "B": "2"}, true},
		{"sel_a and sel_b", map[string]string{"A": "1"}, false},
		{"sel_a or sel_b", map[string]string{"B": "2"}, true},
		{"sel_a and not filt", map[string]string{"A": "1"}, true},
		{"sel_a and not filt",
			map[string]string{"A": "1", "C": "3"}, false},
		{"1 of sel_*", map[string]string{"B": "2"}, true},
		{"all of sel_*", map[string]string{"B": "2"}, false},
		{"all of sel_*", map[string]string{"A": "1", "B": "2"}, true},
		{"any of them", map[string]string{"C": "3"}, true},
		{"(sel_a or sel_b) and not filt",
			map[string]string{"A": "1", "C": "3"}, false},
		{"(sel_a or sel_b) and not filt",
			map[string]string{"A": "1"}, true},
	} {
		r := read(t, strings.Replace(base, "%s", tc.cond, 1))
		c, err := r.Compile()
		if err != nil {
			t.Errorf("%q: %v", tc.cond, err)
			continue
		}
		if got := c.Matches(ev("test", tc.ev)); got != tc.match {
			t.Errorf("%q against %v: matched = %v, want %v", tc.cond, tc.ev,
				got, tc.match)
		}
	}
}

// TestItNeverHalfCompiles is the safety property.
func TestItNeverHalfCompiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		what string
	}{
		{"an aggregation", `
title: agg
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel | count() > 5
level: low
`, "aggregation"},
		{"a keyword list", `
title: kw
logsource:
    product: test
detection:
    keywords:
        - 'something'
    condition: keywords
level: low
`, "keyword"},
		{"an unknown modifier", `
title: mod
logsource:
    product: test
detection:
    sel:
        A|fieldref: 'B'
    condition: sel
level: low
`, "fieldref"},
		{"plain base64", `
title: b64
logsource:
    product: test
detection:
    sel:
        A|base64|contains: 'x'
    condition: sel
level: low
`, "base64"},
	} {
		r := read(t, tc.src)
		_, err := r.Compile()
		if err == nil {
			t.Errorf("%s: compiled", tc.name)
			continue
		}
		var u *Unsupported
		if !errors.As(err, &u) {
			t.Errorf("%s: %v is not reported as unsupported", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.what) {
			t.Errorf("%s: the refusal does not name it: %v", tc.name, err)
		}
		if u.Why == "" {
			t.Errorf("%s: refused with no reason", tc.name)
		}
	}
}

func TestAConditionNamingSomethingUndefinedIsRefused(t *testing.T) {
	_, err := read(t, `
title: missing
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel and nosuch
level: low
`).Compile()
	if err == nil {
		t.Fatal("a condition naming an undefined selection compiled")
	}
	if !strings.Contains(err.Error(), "nosuch") ||
		!strings.Contains(err.Error(), "sel") {
		t.Fatalf("the refusal does not help: %v", err)
	}
	_, err = read(t, `
title: empty quantifier
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: all of nothing_*
level: low
`).Compile()
	if err == nil {
		t.Fatal("a quantifier over nothing compiled")
	}
}

// TestALoudRuleIsReported: high level, unknown false positives.
func TestALoudRuleIsReported(t *testing.T) {
	loud := read(t, `
title: loud
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel
falsepositives:
    - Unknown
level: critical
`)
	if !loud.Loud() {
		t.Fatal("a critical rule with unknown false positives is not loud?")
	}
	quiet := read(t, `
title: quiet
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel
falsepositives:
    - Backup software that reads the same path
level: critical
`)
	if quiet.Loud() {
		t.Fatal("a rule that states its false positives is not loud")
	}
	low := read(t, `
title: low
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel
level: low
`)
	if low.Loud() {
		t.Fatal("a low rule cannot be loud")
	}
}

// TestAPipelineRemapsFieldsWithoutEditingRules is how a deployment adapts
// three thousand portable rules to its own event shape.
func TestAPipelineRemapsFieldsWithoutEditingRules(t *testing.T) {
	src := `
title: mapped
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'whoami'
        User: 'SYSTEM'
    condition: sel
level: low
`
	r := read(t, src)
	pipe := Pipeline{
		Fields: map[string]string{
			"CommandLine": "raw.process.command_line",
			"User":        "actor.value",
		},
		Source: "edr/process",
	}
	c, err := r.CompileWith(pipe)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sources) != 1 || c.Sources[0] != "edr/process" {
		t.Fatalf("sources = %v", c.Sources)
	}
	e := telemetry.Event{
		Source: "edr/process",
		Actor:  telemetry.ID{Issuer: "ad", Value: "SYSTEM"},
		Raw:    map[string]string{"process.command_line": "cmd /c whoami"},
	}
	if !c.Matches(e) {
		t.Fatal("the remapped rule did not match the deployment's event")
	}
	// The same rule with no pipeline looks for raw.CommandLine, which this
	// deployment does not have.
	plain, err := r.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if plain.Matches(e) {
		t.Fatal("the unmapped rule matched, which would mean the mapping " +
			"does nothing")
	}
}

// TestImportReportsBothKindsOfSkipAndTheUnprovenCount.
func TestImportReportsBothKindsOfSkipAndTheUnprovenCount(t *testing.T) {
	files := map[string][]byte{
		"good.yml": []byte(`
title: good
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel
falsepositives:
    - A backup agent doing the same thing
level: high
`),
		"ours.yml": []byte(`
title: needs an aggregation
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel | count() > 5
level: low
`),
		"theirs.yml": []byte(`
title: names a selection that is not there
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel and missing
level: low
`),
		"loud.yml": []byte(`
title: confident and untested
logsource:
    product: test
detection:
    sel:
        A: '1'
    condition: sel
falsepositives:
    - Unknown
level: critical
`),
	}
	rep := Import(files, Pipeline{})
	if rep.Read != 4 {
		t.Fatalf("read = %d", rep.Read)
	}
	if len(rep.Rules) != 2 {
		t.Fatalf("%d compiled", len(rep.Rules))
	}
	if len(rep.Ours()) != 1 || !strings.Contains(rep.Ours()[0].What,
		"aggregation") {
		t.Fatalf("ours = %+v", rep.Ours())
	}
	if len(rep.Theirs()) != 1 {
		t.Fatalf("theirs = %+v", rep.Theirs())
	}
	if len(rep.Loud) != 1 || rep.Loud[0] != "confident and untested" {
		t.Fatalf("loud = %v", rep.Loud)
	}
	// Every imported rule is unproven, which is the honest headline.
	if rep.Unproven() != len(rep.Rules) {
		t.Fatalf("unproven = %d of %d", rep.Unproven(), len(rep.Rules))
	}
	why := rep.Why()
	for _, want := range []string{"2 of 4 compiled", "not implemented here",
		"malformed", "no fixture", "unknown false positives"} {
		if !strings.Contains(why, want) {
			t.Fatalf("the summary does not mention %q: %s", want, why)
		}
	}
	if g := rep.Gaps(); len(g) != 1 || !strings.Contains(g[0], "(1)") {
		t.Fatalf("gaps = %v", g)
	}
}

func TestTheYAMLReaderRefusesWhatItCannotRead(t *testing.T) {
	for _, c := range []struct {
		name string
		src  string
		says string
	}{
		{"a tab indent", "title: x\n\tid: y\n", "tab"},
		{"an anchor", "title: x\nid: &a y\n", "anchors"},
		{"a flow mapping", "title: x\nlogsource: {product: test}\n",
			"flow mapping"},
		{"a line that is not a mapping", "title: x\nnonsense\n", "key: value"},
	} {
		if _, err := Parse([]byte(c.src)); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// And the things it must read.
	docs, err := Parse([]byte(`
# a comment
title: 'has a # hash in it'
plain: has a # hash in it
refs:
    - 'a: b'
    - "c\td"
    - [1, 2]
nested:
    deep:
        key: value
---
title: second document
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("%d document(s)", len(docs))
	}
	if docs[0]["title"] != "has a # hash in it" {
		t.Fatalf("a quoted hash did not survive: %q", docs[0]["title"])
	}
	// Unquoted, a space before a hash starts a comment. That is what YAML
	// says, and a reader that was friendlier here would disagree with
	// every other reader about what the rule means.
	if docs[0]["plain"] != "has a" {
		t.Fatalf("an unquoted hash was not treated as a comment: %q",
			docs[0]["plain"])
	}
	refs := docs[0]["refs"].([]any)
	if refs[0] != "a: b" || refs[1] != "c\td" {
		t.Fatalf("refs = %v", refs)
	}
	if len(refs[2].([]any)) != 2 {
		t.Fatalf("flow sequence = %v", refs[2])
	}
	deep := docs[0]["nested"].(map[string]any)["deep"].(map[string]any)
	if deep["key"] != "value" {
		t.Fatalf("nested = %v", deep)
	}
}

// TestEverythingIsAString: no type inference, so the Norway problem cannot
// happen here.
func TestEverythingIsAString(t *testing.T) {
	docs, err := Parse([]byte("country: no\nversion: 010\nyes: y\n"))
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"country": "no", "version": "010", "yes": "y",
	} {
		if got := docs[0][k]; got != want {
			t.Errorf("%s = %#v, want the string %q", k, got, want)
		}
	}
}
