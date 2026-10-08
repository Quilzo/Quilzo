// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package experiment runs A/B tests on the published site with no script and
// no cookie, and says honestly when a result is a result.
//
// # How a variant is served
//
// A variant is another published page. "pricing-b" is served at /pricing to
// the share of visitors the experiment gives it, so anything an editor can
// change on a page — words, sections, layout — can be tested, and a test is
// built with the editor rather than with a second editing system.
//
// Who sees which is decided by the same daily visitor hash analytics counts
// with (see internal/analytics): a visitor sees one variant all day, and
// nothing about them is stored to make that so. The cost is that a visitor
// may see the other variant tomorrow. Most conversions happen in the visit
// that exposed them, and a test that needed a cookie to be stable would need
// a consent banner to be legal, which is a different product.
//
// # When a difference is a difference
//
// Every A/B tool shows a leaderboard from the first visitor, and every team
// that watches it declares a winner too early: checking repeatedly and
// stopping at the first significant moment makes a false winner several
// times more likely than the 5% the test claims. So this reports a verdict
// only once every arm has MinSample visitors, uses a two-sided two-proportion
// test at 95%, and says "no difference yet" in the meantime rather than
// showing which arm is "winning".
package experiment

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Variant is one version of the page.
type Variant struct {
	Name string `json:"name"`
	// Page is the published page served for this variant. The first
	// variant's page is normally the experiment's own page: the control.
	Page string `json:"page"`
	// Weight is its share of visitors, relative to the others.
	Weight int `json:"weight"`
}

// Experiment is one test on one page.
type Experiment struct {
	Name     string    `json:"name"`
	Page     string    `json:"page"`
	Variants []Variant `json:"variants"`
	// Goal is what counts as a conversion: "form:NAME", "chatbot:NAME", or
	// "page:/path" for reaching a page.
	Goal    string `json:"goal"`
	Running bool   `json:"running"`
}

var (
	reName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	rePage = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,200}$`)
	reGoal = regexp.MustCompile(`^(form:[a-z0-9_-]+|chatbot:[a-z0-9-]+|page:/[a-z0-9/_-]*)$`)
)

// Validate refuses an experiment that could not be run or read.
func (e Experiment) Validate() error {
	if !reName.MatchString(e.Name) {
		return fmt.Errorf("%q is not a usable experiment name", e.Name)
	}
	if !rePage.MatchString(e.Page) {
		return fmt.Errorf("%q is not a page name", e.Page)
	}
	if len(e.Variants) < 2 || len(e.Variants) > 4 {
		return fmt.Errorf("%s has %d variants; between 2 and 4", e.Name, len(e.Variants))
	}
	seen, pages := map[string]bool{}, map[string]bool{}
	for _, v := range e.Variants {
		if !reName.MatchString(v.Name) || seen[v.Name] {
			return fmt.Errorf("variant %q is unnamed or named twice", v.Name)
		}
		seen[v.Name] = true
		if !rePage.MatchString(v.Page) || pages[v.Page] {
			return fmt.Errorf("variant %s's page %q is not a page, or is used twice", v.Name, v.Page)
		}
		pages[v.Page] = true
		if v.Weight < 1 || v.Weight > 100 {
			return fmt.Errorf("variant %s has weight %d; between 1 and 100", v.Name, v.Weight)
		}
	}
	if !reGoal.MatchString(e.Goal) {
		return fmt.Errorf("%q is not a goal: use form:NAME, chatbot:NAME or page:/path", e.Goal)
	}
	return nil
}

// Weights lists the variants' weights in order.
func (e Experiment) Weights() []int {
	out := make([]int, len(e.Variants))
	for i, v := range e.Variants {
		out[i] = v.Weight
	}
	return out
}

// Keys are the analytics goal names an experiment's counts live under. A
// visitor shown a variant is "seen" once a day, and one who then reaches the
// goal is "won" once a day — both through analytics' per-visitor-per-day
// uniqueness, so nothing new is stored.
func SeenKey(exp, variant string) string { return "exp/" + exp + "/" + variant + "/seen" }

// WonKey is a conversion attributed to a variant.
func WonKey(exp, variant string) string { return "exp/" + exp + "/" + variant + "/won" }

// MinSample is how many visitor-days every arm needs before a verdict.
const MinSample = 200

// Arm is one variant's results.
type Arm struct {
	Variant string
	Page    string
	Seen    int
	Won     int
	Rate    float64
	// Lift and P compare this arm with the first (the control). P is the
	// two-sided p-value of a two-proportion z-test.
	Lift float64
	P    float64
}

// Report is an experiment's results so far.
type Report struct {
	Experiment Experiment
	Arms       []Arm
	// Ready is every arm having MinSample visitor-days.
	Ready bool
	// Verdict says what may be concluded, in words.
	Verdict string
}

// Measure reads an experiment's counts out of daily analytics.
func Measure(e Experiment, days []analytics.Day) Report {
	rep := Report{Experiment: e, Ready: true}
	for _, v := range e.Variants {
		a := Arm{Variant: v.Name, Page: v.Page}
		for _, d := range days {
			a.Seen += d.Goals[SeenKey(e.Name, v.Name)]
			a.Won += d.Goals[WonKey(e.Name, v.Name)]
		}
		if a.Seen > 0 {
			a.Rate = float64(a.Won) / float64(a.Seen)
		}
		if a.Seen < MinSample {
			rep.Ready = false
		}
		rep.Arms = append(rep.Arms, a)
	}
	control := rep.Arms[0]
	for i := 1; i < len(rep.Arms); i++ {
		a := &rep.Arms[i]
		if control.Rate > 0 {
			a.Lift = (a.Rate - control.Rate) / control.Rate
		}
		a.P = twoProportionP(control.Won, control.Seen, a.Won, a.Seen)
	}
	rep.Verdict = verdict(rep)
	return rep
}

// twoProportionP is the two-sided p-value for a difference in two rates,
// by the pooled normal approximation. 1 when there is nothing to compare.
func twoProportionP(w1, n1, w2, n2 int) float64 {
	if n1 == 0 || n2 == 0 {
		return 1
	}
	p1, p2 := float64(w1)/float64(n1), float64(w2)/float64(n2)
	pool := float64(w1+w2) / float64(n1+n2)
	se := math.Sqrt(pool * (1 - pool) * (1/float64(n1) + 1/float64(n2)))
	if se == 0 {
		return 1
	}
	z := math.Abs(p1-p2) / se
	return math.Erfc(z / math.Sqrt2)
}

func verdict(r Report) string {
	if !r.Ready {
		least := r.Arms[0].Seen
		for _, a := range r.Arms {
			if a.Seen < least {
				least = a.Seen
			}
		}
		return fmt.Sprintf("Too early to say: every variant needs %d visitor-days "+
			"and the smallest has %d. Looking before then is how false winners "+
			"are declared.", MinSample, least)
	}
	var winners []string
	for _, a := range r.Arms[1:] {
		if a.P < 0.05 {
			dir := "better"
			if a.Lift < 0 {
				dir = "worse"
			}
			winners = append(winners, fmt.Sprintf("%s converts %s than %s "+
				"(%+.0f%%, p = %.3f)", a.Variant, dir, r.Arms[0].Variant, a.Lift*100, a.P))
		}
	}
	if len(winners) == 0 {
		return "No difference detected at 95% confidence. Either there is none, " +
			"or it is smaller than this many visitors can show."
	}
	return strings.Join(winners, "; ") + "."
}

// -- storage ------------------------------------------------------------------

// Set is every experiment a site declares.
type Set struct {
	Experiments []Experiment `json:"experiments"`
}

// Get finds one by name.
func (s *Set) Get(name string) (Experiment, bool) {
	for _, e := range s.Experiments {
		if e.Name == name {
			return e, true
		}
	}
	return Experiment{}, false
}

// RunningOn is the running experiment on a page, if any.
func (s *Set) RunningOn(page string) (Experiment, bool) {
	for _, e := range s.Experiments {
		if e.Running && e.Page == page {
			return e, true
		}
	}
	return Experiment{}, false
}

// Put adds or replaces one. Two running experiments on one page are refused:
// a visitor would be in both, and neither result would mean anything.
func (s *Set) Put(e Experiment) error {
	if err := e.Validate(); err != nil {
		return err
	}
	for _, o := range s.Experiments {
		if o.Name != e.Name && o.Running && e.Running && o.Page == e.Page {
			return fmt.Errorf("%s is already running on %s; stop it first", o.Name, e.Page)
		}
	}
	for i := range s.Experiments {
		if s.Experiments[i].Name == e.Name {
			s.Experiments[i] = e
			return nil
		}
	}
	s.Experiments = append(s.Experiments, e)
	sort.Slice(s.Experiments, func(i, j int) bool { return s.Experiments[i].Name < s.Experiments[j].Name })
	return nil
}

// Remove deletes one.
func (s *Set) Remove(name string) bool {
	for i := range s.Experiments {
		if s.Experiments[i].Name == name {
			s.Experiments = append(s.Experiments[:i], s.Experiments[i+1:]...)
			return true
		}
	}
	return false
}

// Load reads a set; missing is empty.
func Load(path string) (*Set, error) {
	s := &Set{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s is not a set of experiments: %w", path, err)
	}
	for _, e := range s.Experiments {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return s, nil
}

// Save writes a set.
func Save(path string, s *Set) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}
