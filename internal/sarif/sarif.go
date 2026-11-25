// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package sarif reads the interchange format every code scanner already
// speaks.
//
// SARIF 2.1.0 is an OASIS standard and, unusually for this industry, it
// won: Semgrep, CodeQL, ZAP, OSV-Scanner, Trivy, gosec and most of the rest
// emit it, and GitHub code scanning consumes it. One reader therefore
// covers static analysis, dynamic analysis and dependency scanning.
//
// # The churn nobody attributes correctly
//
// GitHub tracks an alert across commits using partialFingerprints, and uses
// exactly one key from it: primaryLocationLineHash. When a tool omits it,
// the uploader falls back to hashing the line — so editing the line closes
// the alert and opens a new one. Whitespace counts. A team that reformats a
// file gets a wave of new alerts and a matching wave of fixed ones, nobody
// connects the two, and the conclusion drawn is that the scanner is noisy.
//
// It is not the scanner. It is a field the scanner did not fill in. So this
// reads the fingerprint where a tool provided one, reports which results
// arrived without one (Gaps).
//
// # A level is not a severity
//
// SARIF's level is error, warning, note or none, and it describes how the
// tool is configured rather than how much the finding matters. There is no
// risk concept in the standard at all, which is why GitHub bolts one on as
// a property called security-severity, a number from 0.0 to 10.0. Tools
// conflate the two constantly and the result is a queue sorted by whichever
// meaning the last scanner had in mind.
//
// Both are read here and kept apart. Where a tool gives a security severity
// it is used, mapped on GitHub's own published boundaries; where it does
// not, the level is used, and SeverityOf and Gaps say which happened
// (severity.go).
//
// # The limits, which are not what they look like
//
// GitHub accepts twenty-five thousand results in a run and displays the top
// five thousand. The other twenty thousand are uploaded, stored, counted
// against nothing, and invisible. A scanner emitting forty thousand
// findings therefore produces a page that looks complete and is missing
// most of what was found, and nothing in the interface says so. Check
// reports it, because a team that cannot see its own queue does not know
// what it has not fixed.
//
// # Read as hostile
//
// This reader came from a security team's own tools, with its tests, and
// is held here to what every file brought in as evidence is held to: a log
// larger than MaxBytes, or nested deeper than MaxDepth, is refused before
// it is decoded, and so is one that gives a key twice in an object, where
// two readers would read two different logs. What it does with the log is
// read it; it never fetches a URI the log names.
package sarif

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Version is the only version of the format this reads.
//
// 2.1.0 is what every tool emits and what GitHub accepts. A reader that
// claimed to handle 2.0 as well would be claiming to have tested against
// files nobody produces.
const Version = "2.1.0"

// Schema is the published schema location, which a log names to say what
// it validates against.
const Schema = "https://json.schemastore.org/sarif-2.1.0.json"

// The limits a platform applies, from GitHub's published table.
//
// Named rather than inlined because the interesting one is not a limit at
// all: MaxResults is what will be accepted and MaxShown is what will be
// displayed, and the gap between them is silent.
const (
	// MaxRuns is runs per file.
	MaxRuns = 20
	// MaxResults is results accepted in one run.
	MaxResults = 25_000
	// MaxShown is how many of those are displayed, ordered by severity.
	MaxShown = 5_000
	// MaxRules is rules per run.
	MaxRules = 25_000
	// MaxLocations is locations per result; a hundred are displayed.
	MaxLocations = 1_000
	// MaxTags is tags per rule; ten are displayed.
	MaxTags = 20
)

// Text is SARIF's multiformat message string.
type Text struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// Log is a SARIF file.
type Log struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one execution of one tool.
type Run struct {
	Tool        Tool         `json:"tool"`
	Results     []Result     `json:"results,omitempty"`
	Invocations []Invocation `json:"invocations,omitempty"`
	Automation  *Automation  `json:"automationDetails,omitempty"`
	Provenance  []Provenance `json:"versionControlProvenance,omitempty"`
}

// Tool is what produced a run.
type Tool struct {
	Driver     Component   `json:"driver"`
	Extensions []Component `json:"extensions,omitempty"`
}

// Component is a driver or an extension, and the rules it carries.
type Component struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	InformationURI  string `json:"informationUri,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

// Rule is SARIF's reportingDescriptor.
type Rule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name,omitempty"`
	ShortDescription *Text      `json:"shortDescription,omitempty"`
	FullDescription  *Text      `json:"fullDescription,omitempty"`
	Help             *Text      `json:"help,omitempty"`
	HelpURI          string     `json:"helpUri,omitempty"`
	Configuration    *Config    `json:"defaultConfiguration,omitempty"`
	Properties       Properties `json:"properties,omitempty"`
}

// Config carries a rule's default level.
type Config struct {
	Level   string `json:"level,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// Properties is the bag every tool uses differently.
//
// Decoded loosely because that is what it is: security-severity arrives as
// a string from most tools and a number from some, precision as a word, and
// tags as anything. A strict decode here would reject real files from real
// scanners, which is the one thing an interchange reader must not do.
type Properties struct {
	Tags             []string `json:"tags,omitempty"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity any      `json:"security-severity,omitempty"`
	ProblemSeverity  string   `json:"problem.severity,omitempty"`
	CWE              []string `json:"cwe,omitempty"`
}

// Score reads the security severity, whichever way the tool wrote it.
func (p Properties) Score() (float64, bool) {
	switch v := p.SecuritySeverity.(type) {
	case float64:
		return v, v > 0
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil && f > 0
	}
	return 0, false
}

// Result is one finding.
type Result struct {
	RuleID    string     `json:"ruleId,omitempty"`
	RuleIndex *int       `json:"ruleIndex,omitempty"`
	Level     string     `json:"level,omitempty"`
	Kind      string     `json:"kind,omitempty"`
	Message   Text       `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	// PartialFingerprints is how an alert is tracked across commits. The
	// only key any platform reads is primaryLocationLineHash.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	BaselineState       string            `json:"baselineState,omitempty"`
	Suppressions        []Suppression     `json:"suppressions,omitempty"`
	Rank                *float64          `json:"rank,omitempty"`
	Properties          Properties        `json:"properties,omitempty"`
}

// Location is where a result is.
type Location struct {
	Physical *Physical `json:"physicalLocation,omitempty"`
	Logical  []Logical `json:"logicalLocations,omitempty"`
}

// Physical is a file and a region in it.
type Physical struct {
	Artifact Artifact `json:"artifactLocation"`
	Region   *Region  `json:"region,omitempty"`
}

// Artifact names a file.
type Artifact struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     *int   `json:"index,omitempty"`
}

// Region is a span within a file.
type Region struct {
	StartLine   int   `json:"startLine,omitempty"`
	StartColumn int   `json:"startColumn,omitempty"`
	EndLine     int   `json:"endLine,omitempty"`
	EndColumn   int   `json:"endColumn,omitempty"`
	Snippet     *Text `json:"snippet,omitempty"`
}

// Logical is a named container: a function, a class, a namespace.
type Logical struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// Suppression is a result somebody has already decided about.
type Suppression struct {
	Kind          string `json:"kind,omitempty"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// Invocation says whether the tool ran successfully.
type Invocation struct {
	ExecutionSuccessful *bool  `json:"executionSuccessful,omitempty"`
	CommandLine         string `json:"commandLine,omitempty"`
	StartTime           string `json:"startTimeUtc,omitempty"`
	EndTime             string `json:"endTimeUtc,omitempty"`
	ExitCode            *int   `json:"exitCode,omitempty"`
}

// Automation identifies a run so repeated uploads replace each other.
type Automation struct {
	ID string `json:"id,omitempty"`
}

// Provenance is the commit a run was against.
type Provenance struct {
	RepositoryURI string `json:"repositoryUri,omitempty"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

// MaxBytes is the largest log read, and MaxDepth the deepest it may nest.
// A real log of twenty-five thousand results is tens of megabytes and
// nests about twelve deep; anything past these is not a scanner's output.
const (
	MaxBytes = 64 << 20
	MaxDepth = 64
)

// Read parses a SARIF file.
//
// Tolerant on purpose about everything except the version. Real files from
// real scanners carry fields this does not model and omit fields the schema
// marks required, and a reader that refused them would be a reader nobody
// could use on their own output. What it is not tolerant of is a file made
// to hurt its reader: too large, too deep, or saying two things under one
// key (hostile).
func Read(in []byte) (Log, error) {
	if len(in) > MaxBytes {
		return Log{}, fmt.Errorf("this log is %d bytes, and the most read is %d", len(in), MaxBytes)
	}
	if err := hostile(in); err != nil {
		return Log{}, err
	}
	var l Log
	if err := json.Unmarshal(in, &l); err != nil {
		return Log{}, fmt.Errorf("this is not JSON: %w", err)
	}
	if strings.TrimSpace(l.Version) == "" {
		return Log{}, fmt.Errorf(
			"this has no version, so it is not a SARIF log. Every tool " +
				"that emits the format writes one")
	}
	if l.Version != Version {
		return Log{}, fmt.Errorf(
			"this is SARIF %s and this reads %s. Claiming to handle a "+
				"version nothing emits would be claiming to have tested "+
				"against files nobody produces", l.Version, Version)
	}
	if len(l.Runs) == 0 {
		return Log{}, fmt.Errorf("this log contains no runs")
	}
	return l, nil
}

// Rule finds the descriptor a result refers to.
//
// By index first, because that is what the standard says and what a large
// file uses; by id as a fallback, because plenty of tools emit only that.
// Extensions are searched too: a tool that ships its rules in an extension
// is not an edge case, it is how CodeQL packs work.
func (r Run) Rule(res Result) (Rule, bool) {
	all := append([]Rule(nil), r.Tool.Driver.Rules...)
	for _, e := range r.Tool.Extensions {
		all = append(all, e.Rules...)
	}
	if res.RuleIndex != nil {
		i := *res.RuleIndex
		if i >= 0 && i < len(r.Tool.Driver.Rules) {
			return r.Tool.Driver.Rules[i], true
		}
	}
	if res.RuleID != "" {
		for _, rl := range all {
			if rl.ID == res.RuleID {
				return rl, true
			}
		}
	}
	return Rule{}, false
}

// Churns reports whether a result will open a new alert every time its line
// is edited.
//
// The single most useful thing a reader can say about a SARIF file, and no
// tool says it. Without a primaryLocationLineHash the platform hashes the
// line text, so reformatting a file closes every alert in it and opens a
// matching set of new ones — and the team concludes the scanner is noisy.
func (res Result) Churns() bool {
	if res.PartialFingerprints["primaryLocationLineHash"] != "" {
		return false
	}
	return len(res.Fingerprints) == 0
}

// Where is a result's primary file and line.
func (res Result) Where() (path string, line int, ok bool) {
	for _, l := range res.Locations {
		if l.Physical == nil || l.Physical.Artifact.URI == "" {
			continue
		}
		p := strings.TrimPrefix(l.Physical.Artifact.URI, "file://")
		if l.Physical.Region != nil {
			return p, l.Physical.Region.StartLine, true
		}
		return p, 0, true
	}
	return "", 0, false
}

// Suppressed reports whether somebody has already dismissed this.
func (res Result) Suppressed() (string, bool) {
	for _, s := range res.Suppressions {
		if s.Status == "" || strings.EqualFold(s.Status, "accepted") {
			why := s.Justification
			if why == "" {
				why = "no justification given"
			}
			return why, true
		}
	}
	return "", false
}

// LineHash computes the fingerprint a platform expects.
//
// Over the trimmed text of the line and the path, which is what makes it
// survive reformatting above and below it. This is what a tool should have
// emitted.
func LineHash(path, lineText string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(path)))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(strings.Fields(lineText), " ")))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Count is how many results a log holds.
func (l Log) Count() int {
	n := 0
	for _, r := range l.Runs {
		n += len(r.Results)
	}
	return n
}

// Tools names everything that contributed to a log.
func (l Log) Tools() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range l.Runs {
		n := r.Tool.Driver.Name
		if n == "" {
			n = "an unnamed tool"
		}
		if r.Tool.Driver.Version != "" {
			n += " " + r.Tool.Driver.Version
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Check reports what a log will do to whoever receives it.
func (l Log) Check() []string {
	var out []string
	if len(l.Runs) > MaxRuns {
		out = append(out, fmt.Sprintf(
			"%d runs; a platform takes %d", len(l.Runs), MaxRuns))
	}
	for _, r := range l.Runs {
		name := firstOf(r.Tool.Driver.Name, "an unnamed tool")
		if n := len(r.Results); n > MaxResults {
			out = append(out, fmt.Sprintf(
				"%s has %d results and %d will be accepted", name, n,
				MaxResults))
		} else if n > MaxShown {
			out = append(out, fmt.Sprintf(
				"%s has %d results and %d will be displayed; the other %d "+
					"are uploaded and invisible", name, n, MaxShown,
				n-MaxShown))
		}
		if n := len(r.Tool.Driver.Rules); n > MaxRules {
			out = append(out, fmt.Sprintf("%s declares %d rules and %d "+
				"will be accepted", name, n, MaxRules))
		}
		for _, res := range r.Results {
			if len(res.Locations) > MaxLocations {
				out = append(out, fmt.Sprintf(
					"a result in %s has %d locations and %d will be "+
						"accepted", name, len(res.Locations), MaxLocations))
				break
			}
		}
	}
	return out
}

// Failed reports whether the run's tool said it did not finish, which
// makes an empty run no news at all rather than good news.
func (r Run) Failed() bool {
	for _, inv := range r.Invocations {
		if inv.ExecutionSuccessful != nil && !*inv.ExecutionSuccessful {
			return true
		}
	}
	return false
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// foldKey is a key as encoding/json matches it to a field: each letter
// folded to the least of the letters Unicode folds it with, so that
// "Results", "RESULTS" and "reſults" are one key.
func foldKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				r = next
				break
			}
			r = next
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hostile walks a log once before it is decoded, and refuses one nested
// deeper than MaxDepth or giving a key twice in an object. Twice means as
// the decoder matches keys to fields, which ignores case: "Results" after
// "results" is the same field to it and the last one is kept, while every
// reader that goes by the format's own spelling reads the first.
func hostile(in []byte) error {
	d := json.NewDecoder(bytes.NewReader(in))
	type frame struct {
		object, key bool
		keys        map[string]bool
	}
	var stack []frame
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) > 0 {
				return errors.New("this is not JSON: it ends before it is complete")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("this is not JSON: %w", err)
		}
		top := len(stack) - 1
		if k, ok := tok.(string); ok && top >= 0 && stack[top].object && stack[top].key {
			if stack[top].keys[foldKey(k)] {
				return fmt.Errorf("this log gives the key %q twice in one object, and two readers would read two logs", firstOf(k, "(blank)"))
			}
			stack[top].keys[foldKey(k)], stack[top].key = true, false
			continue
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if len(stack) >= MaxDepth {
					return fmt.Errorf("this log nests deeper than %d, which no scanner's does", MaxDepth)
				}
				stack = append(stack, frame{object: delim == '{', key: delim == '{', keys: map[string]bool{}})
				continue
			default:
				stack = stack[:len(stack)-1]
			}
		}
		if top := len(stack) - 1; top >= 0 && stack[top].object {
			stack[top].key = true
		}
	}
}
