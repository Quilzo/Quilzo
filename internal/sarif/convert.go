// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sarif

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/appsec"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Severity boundaries, as the platform publishes them.
//
// Named because the numbers are somebody else's and a reader should be able
// to check them against the source rather than against a comparison chain.
const (
	CriticalAt = 9.0
	HighAt     = 7.0
	MediumAt   = 4.0
)

// score maps a security-severity number onto a severity.
func score(f float64) telemetry.Severity {
	switch {
	case f >= CriticalAt:
		return telemetry.SeverityCritical
	case f >= HighAt:
		return telemetry.SeverityHigh
	case f >= MediumAt:
		return telemetry.SeverityMedium
	default:
		return telemetry.SeverityLow
	}
}

// fromLevel maps SARIF's level onto a severity, which it is not.
//
// error, warning, note and none describe how the tool is configured, not
// how much the finding matters. This mapping exists because something has
// to be done when a tool gave nothing better, and the conversion records
// that it was used so a queue sorted on it can be recognised as one.
func fromLevel(level string) telemetry.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return telemetry.SeverityHigh
	case "warning":
		return telemetry.SeverityMedium
	case "note", "none", "":
		return telemetry.SeverityLow
	}
	return telemetry.SeverityLow
}

// kinds maps rule tags onto what sort of finding this is.
//
// Tags are the only place SARIF carries this and every tool spells them
// differently, so the match is on substrings and the default is a weakness
// — which is what a static analyser mostly finds and the least surprising
// thing to guess wrong.
func kindOf(r Rule, res Result, tool string) appsec.Kind {
	hay := strings.ToLower(strings.Join(append(append([]string{},
		r.Properties.Tags...), res.Properties.Tags...), " ") +
		" " + strings.ToLower(r.ID+" "+res.RuleID+" "+tool))
	switch {
	case strings.Contains(hay, "secret"), strings.Contains(hay, "credential"),
		strings.Contains(hay, "token"), strings.Contains(hay, "key-leak"):
		return appsec.Secret
	case strings.Contains(hay, "dependency"), strings.Contains(hay, "sca"),
		strings.Contains(hay, "supply-chain"), strings.Contains(hay, "osv"),
		strings.Contains(hay, "vulnerable-package"):
		return appsec.Dependency
	case strings.Contains(hay, "misconfig"),
		strings.Contains(hay, "configuration"),
		strings.Contains(hay, "iac"), strings.Contains(hay, "terraform"):
		return appsec.Configuration
	}
	return appsec.Weakness
}

// Gap is something a tool left out, and what it costs.
type Gap struct {
	What  string `json:"what"`
	Count int    `json:"count"`
	Costs string `json:"costs"`
}

// Report is what a SARIF file was, and what it did not say.
type Report struct {
	Alerts []appsec.Alert `json:"-"`
	Tools  []string       `json:"tools"`
	Read   int            `json:"read"`
	// Churn is how many results arrived with no fingerprint.
	Churn int `json:"churn"`
	// Levelled is how many had no security severity, so the level had to
	// stand in for one.
	Levelled int `json:"levelled"`
	// Placeless is how many had no file location at all.
	Placeless int `json:"placeless"`
	// Suppressed is how many the tool says somebody already dismissed.
	Suppressed int   `json:"suppressed"`
	Gaps       []Gap `json:"gaps,omitempty"`
	// Hidden is how many results would be accepted and not displayed.
	Hidden int `json:"hidden,omitempty"`
	// Failed names runs whose tool reported that it did not finish.
	Failed []string `json:"failed,omitempty"`
}

// Why summarises a report in a sentence.
func (r Report) Why() string {
	var says []string
	says = append(says, fmt.Sprintf("%d result(s) from %s", r.Read,
		strings.Join(r.Tools, ", ")))
	if r.Churn > 0 {
		says = append(says, fmt.Sprintf("%d will open a new alert every "+
			"time their line is edited", r.Churn))
	}
	if r.Levelled > 0 {
		says = append(says, fmt.Sprintf("%d carry no severity, only a "+
			"level", r.Levelled))
	}
	if r.Hidden > 0 {
		says = append(says, fmt.Sprintf("%d would be uploaded and not "+
			"shown", r.Hidden))
	}
	if len(r.Failed) > 0 {
		says = append(says, fmt.Sprintf("%d run(s) did not finish",
			len(r.Failed)))
	}
	return strings.Join(says, "; ")
}

// Convert turns a SARIF log into alerts for internal/appsec.
//
// repository is the checkout these paths are relative to, carried through
// so a deployment scanning several can tell them apart.
func Convert(l Log, repository string) Report {
	rep := Report{Tools: l.Tools()}
	var churnTools, levelTools, placeTools map[string]int
	churnTools, levelTools, placeTools = map[string]int{}, map[string]int{},
		map[string]int{}

	for _, run := range l.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = "unknown"
		}
		for _, inv := range run.Invocations {
			if inv.ExecutionSuccessful != nil && !*inv.ExecutionSuccessful {
				rep.Failed = append(rep.Failed, tool)
			}
		}
		if over := len(run.Results) - MaxShown; over > 0 {
			rep.Hidden += over
		}
		for _, res := range run.Results {
			rep.Read++
			rule, _ := run.Rule(res)

			a := appsec.Alert{
				Tool: tool, Repository: repository,
				Rule:    firstOf(res.RuleID, rule.ID, rule.Name),
				Kind:    kindOf(rule, res, tool),
				Message: firstOf(res.Message.Text, text(rule.ShortDescription)),
			}
			if s, ok := res.Properties.Score(); ok {
				a.Severity = score(s)
			} else if s, ok := rule.Properties.Score(); ok {
				a.Severity = score(s)
			} else {
				lvl := res.Level
				if lvl == "" && rule.Configuration != nil {
					lvl = rule.Configuration.Level
				}
				a.Severity = fromLevel(lvl)
				rep.Levelled++
				levelTools[tool]++
			}

			if p, line, ok := res.Where(); ok {
				a.Path, a.Line = p, line
			} else {
				rep.Placeless++
				placeTools[tool]++
			}
			a.Symbol = symbol(res)
			a.Snippet = snippet(res)

			// The tool's own fingerprint, preferred over anything computed
			// here: it knows more about what it matched than this does.
			if fp := res.PartialFingerprints["primaryLocationLineHash"]; fp != "" {
				a.Given = fp
			} else if fp := firstValue(res.Fingerprints); fp != "" {
				a.Given = fp
			} else {
				rep.Churn++
				churnTools[tool]++
			}
			if _, yes := res.Suppressed(); yes {
				rep.Suppressed++
			}
			if a.Path == "" {
				// appsec refuses an alert with nowhere to go, and it is
				// right to: a finding nobody can open is a number.
				continue
			}
			rep.Alerts = append(rep.Alerts, a)
		}
	}

	if rep.Churn > 0 {
		rep.Gaps = append(rep.Gaps, Gap{
			What:  "no partialFingerprints.primaryLocationLineHash",
			Count: rep.Churn,
			Costs: "the platform falls back to hashing the line, so " +
				"editing it closes the alert and opens a new one. A " +
				"reformat produces a wave of new findings and a matching " +
				"wave of fixed ones, and the conclusion drawn is that the " +
				"scanner is noisy — from " + worst(churnTools),
		})
	}
	if rep.Levelled > 0 {
		rep.Gaps = append(rep.Gaps, Gap{
			What:  "no security-severity",
			Count: rep.Levelled,
			Costs: "SARIF's level says how the tool is configured, not " +
				"how much a finding matters, so these were ranked on the " +
				"wrong axis — from " + worst(levelTools),
		})
	}
	if rep.Placeless > 0 {
		rep.Gaps = append(rep.Gaps, Gap{
			What:  "no file location",
			Count: rep.Placeless,
			Costs: "nobody can open them, so they are a number rather " +
				"than work — from " + worst(placeTools),
		})
	}
	if rep.Hidden > 0 {
		rep.Gaps = append(rep.Gaps, Gap{
			What:  "more results than a platform displays",
			Count: rep.Hidden,
			Costs: fmt.Sprintf(
				"a run may carry %d results and %d are shown, ordered by "+
					"severity. The rest are uploaded, stored and invisible, "+
					"and the page looks complete", MaxResults, MaxShown),
		})
	}
	sort.SliceStable(rep.Gaps, func(i, j int) bool {
		return rep.Gaps[i].Count > rep.Gaps[j].Count
	})
	return rep
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func text(t *Text) string {
	if t == nil {
		return ""
	}
	return t.Text
}

func firstValue(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if m[k] != "" {
			return m[k]
		}
	}
	return ""
}

func symbol(res Result) string {
	for _, l := range res.Locations {
		for _, lg := range l.Logical {
			if n := firstOf(lg.FullyQualifiedName, lg.Name); n != "" {
				return n
			}
		}
	}
	return ""
}

func snippet(res Result) string {
	for _, l := range res.Locations {
		if l.Physical != nil && l.Physical.Region != nil &&
			l.Physical.Region.Snippet != nil {
			return l.Physical.Region.Snippet.Text
		}
	}
	return ""
}

// worst names the tool responsible for most of a gap.
func worst(by map[string]int) string {
	best, at := "", 0
	names := make([]string, 0, len(by))
	for n := range by {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if by[n] > at {
			best, at = n, by[n]
		}
	}
	if best == "" {
		return "no tool in particular"
	}
	if len(by) == 1 {
		return best
	}
	return fmt.Sprintf("%s mostly (%d of them)", best, at)
}

// Write produces a SARIF log from alerts.
//
// Always with a primaryLocationLineHash, because omitting it is the churn
// above and there is no reason to pass it on. Always with a
// security-severity, because a consumer that has only a level will sort on
// it.
func Write(tool, version string, alerts []appsec.Alert,
	p Provenance) (Log, error) {
	if strings.TrimSpace(tool) == "" {
		return Log{}, fmt.Errorf(
			"a run names the tool that produced it; a result whose origin " +
				"is blank cannot be traced back to a scanner or a version")
	}
	run := Run{Tool: Tool{Driver: Component{Name: tool, Version: version}}}
	if p.RepositoryURI != "" || p.RevisionID != "" {
		run.Provenance = []Provenance{p}
	}
	seen := map[string]int{}
	for _, a := range alerts {
		if err := a.Validate(); err != nil {
			return Log{}, err
		}
		idx, ok := seen[a.Rule]
		if !ok {
			idx = len(run.Tool.Driver.Rules)
			seen[a.Rule] = idx
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, Rule{
				ID:               a.Rule,
				Name:             a.Rule,
				ShortDescription: &Text{Text: firstOf(a.Message, a.Rule)},
				Configuration:    &Config{Level: toLevel(a.Severity)},
				Properties: Properties{
					Tags:             []string{"security", string(a.Kind)},
					SecuritySeverity: fmt.Sprintf("%.1f", toScore(a.Severity)),
				},
			})
		}
		i := idx
		res := Result{
			RuleID: a.Rule, RuleIndex: &i,
			Level:   toLevel(a.Severity),
			Message: Text{Text: firstOf(a.Message, a.Rule)},
			Locations: []Location{{Physical: &Physical{
				Artifact: Artifact{URI: a.Path},
			}}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": firstOf(a.Given,
					LineHash(a.Path, a.Snippet)),
			},
			Properties: Properties{
				SecuritySeverity: fmt.Sprintf("%.1f", toScore(a.Severity)),
			},
		}
		if a.Line > 0 {
			res.Locations[0].Physical.Region = &Region{StartLine: a.Line}
			if a.Snippet != "" {
				res.Locations[0].Physical.Region.Snippet =
					&Text{Text: a.Snippet}
			}
		}
		if a.Symbol != "" {
			res.Locations[0].Logical = []Logical{{Name: a.Symbol}}
		}
		run.Results = append(run.Results, res)
	}
	return Log{Schema: Schema, Version: Version, Runs: []Run{run}}, nil
}

func toLevel(s telemetry.Severity) string {
	switch {
	case s >= telemetry.SeverityHigh:
		return "error"
	case s >= telemetry.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// toScore maps a severity back onto the platform's numeric scale.
//
// The midpoint of each band rather than its edge, because a value on a
// boundary rounds unpredictably against a comparison somebody else wrote.
func toScore(s telemetry.Severity) float64 {
	switch s {
	case telemetry.SeverityCritical:
		return 9.5
	case telemetry.SeverityHigh:
		return 8.0
	case telemetry.SeverityMedium:
		return 5.5
	default:
		return 2.0
	}
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
