// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"sort"

	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sarif"
)

// A SARIF log from a code scanner, read by internal/sarif.
//
// What a code scan shows of a control is how many findings it left open,
// and by which rule, in which repository: so a run becomes counts, as facts
// about the repository it scanned (the run's version control provenance,
// or, with none, the tool's own name). code.findings is the results nobody
// suppressed; code.rule.RULE the same for one rule; code.findings.suppressed
// the ones a person already decided about in the source. A run whose tool
// said it did not finish is a fact too, code.run.failed, because an empty
// run that failed is not a clean one.

func init() { readers[FormatSARIF] = readSARIF }

func readSARIF(rd *reader) error {
	if err := checkJSON(rd.in.Body, false); err != nil {
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	l, err := sarif.Read(rd.in.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	for _, c := range l.Check() {
		rd.note("%s", label(c))
	}
	// Counts are per repository across the log's runs: two scanners of one
	// repository in one file are two runs, and one count of what is open.
	type counts struct {
		place            string
		open, suppressed int
		byRule           map[string]int
		failed           bool
	}
	byRepo := map[register.ID]*counts{}
	var repos []register.ID
	for i, run := range l.Runs {
		place := fmt.Sprintf("/runs/%d", i)
		tool := firstText(run.Tool.Driver.Name, "an unnamed tool")
		ref, name := tool, "code scanned by "+tool
		if len(run.Provenance) > 0 && run.Provenance[0].RepositoryURI != "" {
			ref, name = run.Provenance[0].RepositoryURI, run.Provenance[0].RepositoryURI
		} else {
			rd.note("the run at %s names no repository, so its facts are about the tool %s", place, label(tool))
		}
		repo, err := rd.asset("repository", ref, name, place)
		if err != nil {
			return err
		}
		c := byRepo[repo]
		if c == nil {
			c = &counts{place: place, byRule: map[string]int{}}
			byRepo[repo] = c
			repos = append(repos, repo)
		}
		churn := 0
		for _, res := range run.Results {
			if _, yes := res.Suppressed(); yes {
				c.suppressed++
				continue
			}
			c.open++
			rule := res.RuleID
			if rule == "" {
				if r, ok := run.Rule(res); ok {
					rule = r.ID
				}
			}
			c.byRule[firstText(rule, "unnamed")]++
			if res.Churns() {
				churn++
			}
		}
		c.failed = c.failed || run.Failed()
		if churn > 0 {
			rd.note("%d result(s) of %s have no fingerprint, and a platform opens a new alert each time their line is edited",
				churn, label(tool))
		}
	}
	for _, repo := range repos {
		c := byRepo[repo]
		place := c.place + "/results"
		if err := rd.observe(repo, "code.findings", register.NumberValue(float64(c.open)), place, ""); err != nil {
			return err
		}
		if err := rd.observe(repo, "code.findings.suppressed", register.NumberValue(float64(c.suppressed)), place, ""); err != nil {
			return err
		}
		rules := make([]string, 0, len(c.byRule))
		for r := range c.byRule {
			rules = append(rules, r)
		}
		sort.Strings(rules)
		for _, r := range rules {
			if err := rd.observe(repo, factName("code.rule", r), register.NumberValue(float64(c.byRule[r])), place, ""); err != nil {
				return err
			}
		}
		if c.failed {
			if err := rd.observe(repo, "code.run.failed", register.BoolValue(true), c.place+"/invocations", ""); err != nil {
				return err
			}
		}
	}
	return nil
}
