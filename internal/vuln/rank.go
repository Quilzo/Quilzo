// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The order, and the one number that makes a probability useful.
//
// # Expected exploitations
//
// EPSS is a probability and almost nobody treats it as one. A queue showing
// "EPSS 0.08" next to four hundred rows tells a reader nothing, because the
// interesting quantity is not any single row: it is the sum. Four hundred
// vulnerabilities averaging 0.008 carry an expected 3.2 exploitations in the
// next thirty days, and if 2.9 of that sits in the top twelve rows then the
// top twelve rows are this month's work and the rest is not.
//
// That is addition. It is the most useful thing that can be done with EPSS
// and no product does it, because a number that says "the other 388 do not
// matter this month" is a number nobody wants to publish.
//
// Expected is deliberately not a threshold and not a target. It answers "how
// much of the risk in this queue is in the part I am about to work on", which
// is the question somebody with a Tuesday afternoon is actually asking.

// Exposure is one vulnerability in one installed thing.
type Exposure struct {
	Advisory  Advisory   `json:"advisory"`
	Component Component  `json:"component"`
	Verdict   Verdict    `json:"verdict"`
	Why       string     `json:"why"`
	Assessed  Assessment `json:"assessed,omitzero"`
	// Silenced is whether an assessment takes this out of the queue now.
	Silenced bool `json:"silenced,omitempty"`
}

// Fixable reports whether there is a version to move to.
func (e Exposure) Fixable() (string, bool) {
	if v, ok := e.Advisory.FixedIn[e.Component.Key()]; ok && v != "" {
		return v, true
	}
	for _, r := range e.Advisory.Affects {
		if Key(r.Ecosystem, r.Package) == e.Component.Key() && r.Fixed != "" {
			return r.Fixed, true
		}
	}
	return "", false
}

// Weight orders the queue. Higher is sooner.
//
// Every term is here rather than in a configuration file, because a weight
// somebody can change without reading this is a weight nobody can explain
// afterwards. The order of magnitude between the terms is the argument:
//
//	attested exploitation   1000 per source   a fact
//	probability             0-800             a prediction, from EPSS
//	reachability             0-120            what this deployment knows
//	age since we knew        0-60             a decision not to act
//	severity                 0-10             a tiebreak, and only that
//
// Severity is last on the evidence. Holding coverage of actually-exploited
// vulnerabilities constant at 82%, an EPSS-driven strategy gets there by
// remediating about 14,000 CVEs and a CVSS-seven-and-above strategy by
// remediating about 110,000. Sorting by severity is eight times the work for
// the same result, and it is what every scanner does by default.
func (e Exposure) Weight(now time.Time) float64 {
	if e.Silenced || e.Verdict == Outside || e.Verdict == Patched {
		return 0
	}
	var w float64

	// A fact beats every prediction. Each independent source that says so
	// counts, because two agencies agreeing is more than one asserting.
	if yes, who := e.Advisory.Attested(); yes {
		w += 1000 * float64(len(who))
	}

	// The probability, scaled. Stale figures are discounted rather than
	// ignored: EPSS moves daily and a month-old number is about last month,
	// but it is still the best available estimate.
	epss := e.Advisory.EPSS
	if !e.Advisory.Fresh(now) {
		epss *= 0.5
	}
	w += 800 * epss

	// What this deployment knows about its own code, which no feed knows.
	switch {
	case e.Component.Reachable != nil && *e.Component.Reachable:
		w += 120
	case e.Component.Reachable != nil:
		w += 0
	default:
		// Unknown reachability sits between the two. Treating it as
		// unreachable would silently sink everything nobody has analysed,
		// which is most things.
		w += 40
	}
	if e.Component.Direct {
		w += 20
	}
	if e.Verdict == Undecided {
		// The comparator could not tell. Ranked as present, and visible.
		w += 30
	}

	// Age from when we knew, capped at sixty days. Past that it is not
	// getting worse, it is getting older, and letting it climb for ever
	// would eventually float ancient low-probability rows above a fresh
	// attested one.
	days := now.Sub(e.Advisory.Known).Hours() / 24
	if days > 60 {
		days = 60
	}
	if days > 0 {
		w += days
	}

	// A lapsed investigation returns at full weight and says so, rather than
	// quietly reappearing at the bottom.
	if e.Assessed.Lapsed(now) {
		w += 50
	}

	// Severity, last. It breaks ties between things that are otherwise
	// equal, which is the job it can actually do.
	w += e.Advisory.CVSS
	return w
}

// Why explains an exposure's position in one line.
func (e Exposure) Explain(now time.Time) string {
	if e.Silenced {
		return fmt.Sprintf("%s: %s, %s", e.Advisory.ID, e.Assessed.Status,
			e.Assessed.Because)
	}
	var parts []string
	if yes, who := e.Advisory.Attested(); yes {
		parts = append(parts, fmt.Sprintf("%s says it is being exploited",
			strings.Join(who, " and ")))
	}
	if e.Advisory.EPSS > 0 {
		when := "measured today"
		if !e.Advisory.Fresh(now) {
			when = "from a figure over a week old"
		}
		parts = append(parts, fmt.Sprintf(
			"%.1f%% chance of exploitation in thirty days, %s",
			e.Advisory.EPSS*100, when))
	}
	if e.Verdict == Undecided {
		parts = append(parts, e.Why)
	}
	if e.Component.Reachable != nil && *e.Component.Reachable {
		parts = append(parts, "the vulnerable code is reachable here")
	}
	if fix, ok := e.Fixable(); ok {
		parts = append(parts, "fixed in "+fix)
	} else {
		// Changes what the work is rather than how urgent it is: there is
		// nothing to upgrade to, so the options are mitigate or accept.
		parts = append(parts, "no fix has been published, so the work is a "+
			"mitigation or a recorded acceptance rather than an upgrade")
	}
	if e.Assessed.Lapsed(now) {
		parts = append(parts, fmt.Sprintf(
			"an investigation by %s lapsed on %s", e.Assessed.By,
			e.Assessed.Until.Format("2006-01-02")))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("CVSS %.1f, and nothing else is known about it",
			e.Advisory.CVSS)
	}
	return strings.Join(parts, "; ")
}

// Rank orders exposures, most urgent first.
func Rank(in []Exposure, now time.Time) []Exposure {
	out := append([]Exposure(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		wi, wj := out[i].Weight(now), out[j].Weight(now)
		if wi != wj {
			return wi > wj
		}
		if out[i].Advisory.ID != out[j].Advisory.ID {
			return out[i].Advisory.ID < out[j].Advisory.ID
		}
		return out[i].Component.Where.String() <
			out[j].Component.Where.String()
	})
	return out
}

// Expected is how many of these are likely to be exploited in thirty days.
//
// The sum of the probabilities, which is what an expected value is. Not a
// score, not a percentage, and not comparable to anybody else's number: it is
// this queue's own arithmetic, and its use is the comparison between a slice
// of the queue and the whole of it.
func Expected(in []Exposure, now time.Time) float64 {
	var total float64
	seen := map[string]bool{}
	for _, e := range in {
		if e.Silenced || e.Weight(now) == 0 {
			continue
		}
		// Once per advisory. The same CVE on forty hosts is one prediction
		// about one vulnerability, and adding it forty times would turn a
		// fleet size into a risk figure.
		if seen[e.Advisory.ID] {
			continue
		}
		seen[e.Advisory.ID] = true
		total += e.Advisory.EPSS
	}
	return total
}

// Concentration says how much of a queue's expected exploitation sits in its
// first n rows.
//
// The sentence somebody with a Tuesday afternoon needs: "the top twelve carry
// nine tenths of it". Returns the expected value of the head, the whole, and
// the share.
func Concentration(ranked []Exposure, n int, now time.Time) (head, all,
	share float64) {

	if n > len(ranked) {
		n = len(ranked)
	}
	head = Expected(ranked[:n], now)
	all = Expected(ranked, now)
	if all == 0 {
		return head, all, 0
	}
	return head, all, head / all
}

// Match pairs advisories against an inventory, applying assessments.
func Match(advisories []Advisory, inventory []Component,
	assessments []Assessment, now time.Time) []Exposure {

	byKey := map[string]Assessment{}
	for _, a := range assessments {
		// The newest assessment for a thing wins. Two statements about one
		// vulnerability are a person changing their mind, not a conflict.
		if existing, ok := byKey[a.Key()]; ok && existing.At.After(a.At) {
			continue
		}
		byKey[a.Key()] = a
	}

	var out []Exposure
	for _, adv := range advisories {
		for _, c := range inventory {
			verdict, why := adv.Applies(c)
			if verdict == Outside || verdict == Patched {
				continue
			}
			e := Exposure{Advisory: adv, Component: c, Verdict: verdict,
				Why: why}
			// A statement about every installation first, then one about
			// this particular asset, which overrides it.
			for _, key := range []string{
				adv.ID + "\x00" + c.Key(),
				adv.ID + "\x00" + c.Key() + "\x00" + c.Where.String(),
			} {
				if a, ok := byKey[key]; ok {
					e.Assessed = a
				}
			}
			e.Silenced = e.Assessed.Status != "" &&
				e.Assessed.Silences(now)
			out = append(out, e)
		}
	}
	return Rank(out, now)
}

// Findings turns exposures into the register everything else works from.
func Findings(in []Exposure, now time.Time) []finding.Finding {
	var out []finding.Finding
	for _, e := range in {
		if e.Silenced || e.Weight(now) == 0 {
			continue
		}
		fix, fixable := e.Fixable()
		title := fmt.Sprintf("%s in %s %s on %s", e.Advisory.ID,
			e.Component.Name, e.Component.Version, e.Component.Where.Value)
		if fixable {
			title = fmt.Sprintf("%s in %s %s: upgrade to %s", e.Advisory.ID,
				e.Component.Name, e.Component.Version, fix)
		}
		f := finding.Finding{
			Kind: finding.FromVulnerability, Title: title,
			Source: "vuln", Entity: e.Component.Where,
			Severity: severityOf(e, now), State: finding.Open, Seen: 1,
			First: e.Advisory.Known, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "vuln", What: e.Explain(now),
				Ref: e.Advisory.ID,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}
	return finding.Rank(out, now)
}

// severityOf maps an exposure onto the register's severity band.
//
// Not the CVSS band. A vulnerability somebody has attested is being exploited
// is critical whatever its base score says, and a high-scoring one with a
// vanishing probability and no reachability is not the thing to look at
// first — which is the entire argument of this package, applied where it
// meets a queue that other kinds of finding also live in.
func severityOf(e Exposure, now time.Time) telemetry.Severity {
	if yes, _ := e.Advisory.Attested(); yes {
		return telemetry.SeverityCritical
	}
	epss := e.Advisory.EPSS
	if !e.Advisory.Fresh(now) {
		epss *= 0.5
	}
	switch {
	case epss >= 0.1:
		return telemetry.SeverityHigh
	case epss >= 0.01:
		return telemetry.SeverityMedium
	case e.Advisory.CVSS >= 9:
		// A severity with nothing else behind it. Still worth being above
		// the floor, and deliberately not critical.
		return telemetry.SeverityMedium
	default:
		return telemetry.SeverityLow
	}
}

// Group is one vulnerability and every place it was found.
//
// The queue groups by advisory rather than listing one row per host, because
// the work is per-advisory and the exposure is per-host. Upgrading lodash on
// forty laptops is one job; a queue that spends forty rows on it pushes the
// next vulnerability off the page, which is how a scanner's output ends up
// being read down to row twenty and no further.
//
// It also makes the arithmetic and the display agree: Expected counts a CVE
// once however many hosts carry it, and a list that showed it forty times
// while counting it once would be two different claims on one screen.
type Group struct {
	Advisory Advisory `json:"advisory"`
	// On is where it was found, in rank order.
	On []Exposure `json:"on"`
}

// Assets is how many places this was found.
func (g Group) Assets() int { return len(g.On) }

// Where names the first few assets, and says how many more there are.
func (g Group) Where(limit int) string {
	var names []string
	for i, e := range g.On {
		if i >= limit {
			return fmt.Sprintf("%s and %d more", strings.Join(names, ", "),
				len(g.On)-limit)
		}
		names = append(names, e.Component.Where.String())
	}
	return strings.Join(names, ", ")
}

// Worst is the highest-ranked exposure in the group, which is the one whose
// explanation the queue prints.
func (g Group) Worst() Exposure { return g.On[0] }

// Groups folds a ranked list of exposures into one entry per advisory,
// keeping the order the ranking produced.
func Groups(ranked []Exposure) []Group {
	var out []Group
	at := map[string]int{}
	for _, e := range ranked {
		if i, seen := at[e.Advisory.ID]; seen {
			out[i].On = append(out[i].On, e)
			continue
		}
		at[e.Advisory.ID] = len(out)
		out = append(out, Group{Advisory: e.Advisory, On: []Exposure{e}})
	}
	return out
}

// Flatten is the inverse, for a caller that wants exposures back.
func Flatten(groups []Group) []Exposure {
	var out []Exposure
	for _, g := range groups {
		out = append(out, g.On...)
	}
	return out
}
