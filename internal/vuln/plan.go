// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The queue answers "which vulnerability first". This answers the question
// the person doing the work actually has, which is "what do I change".
//
// Six advisories against one library are one upgrade, and the version that
// matters is the lowest one that clears all six: lower leaves one open and
// the job is done twice, higher is a bigger change than anybody asked for
// and the reason upgrades get deferred. A scanner prints six rows with six
// "fixed in" versions and leaves the arithmetic to whoever is reading.

// Left is an advisory an upgrade does not clear, and why.
type Left struct {
	ID  string `json:"id"`
	Why string `json:"why"`
}

// Upgrade is one package, and the smallest move that clears what can be
// cleared.
type Upgrade struct {
	// Package is ecosystem:name.
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// Versions is what is installed, lowest first where they compare.
	Versions []string `json:"versions"`
	// To is the lowest version that clears everything in Clears. Empty when
	// nothing here has a fix.
	To string `json:"to,omitempty"`
	// Clears is the advisories moving to To closes.
	Clears []string `json:"clears,omitempty"`
	// Leaves is what stays open afterwards.
	Leaves []Left `json:"leaves,omitempty"`
	// Into is what is known to be wrong with To itself. An upgrade into a
	// version with its own unfixed advisory is still usually right; it is
	// not right to find that out afterwards.
	Into []string `json:"into,omitempty"`
	// Assets is how many places the package is installed and exposed.
	Assets int `json:"assets"`
	// Expected is the expected exploitations the upgrade removes: the sum
	// of the probabilities of what it clears, each counted once.
	Expected float64 `json:"expected"`
	// Exploited is whether anything it clears is attested as exploited.
	Exploited bool `json:"exploited,omitempty"`
}

// fixFor is the version that closes one advisory for one installed thing.
//
// The range that actually covers the installed version, not the first range
// that mentions the package: an advisory fixed in 1.2.5 on the 1.x line and
// 2.0.3 on the 2.x line has two answers, and telling somebody on 2.0.1 to
// move to 1.2.5 is telling them to downgrade into it.
func fixFor(a Advisory, c Component) (string, bool) {
	for _, r := range a.Affects {
		if Key(r.Ecosystem, r.Package) != c.Key() || r.Fixed == "" {
			continue
		}
		if v, _ := r.covers(c.Version); v == Vulnerable {
			return r.Fixed, true
		}
	}
	return Exposure{Advisory: a, Component: c}.Fixable()
}

// Upgrades turns the live queue into the changes that would empty it.
//
// known is every advisory, not only the open ones, because the version an
// upgrade lands on has to be checked against all of them: the point of
// computing a target is lost if the target is itself on the list.
func Upgrades(live []Exposure, known []Advisory, now time.Time) []Upgrade {
	type pile struct {
		up       Upgrade
		versions map[string]bool
		assets   map[string]bool
		adv      map[string]Exposure
		order    []string
	}
	piles := map[string]*pile{}
	var keys []string
	for _, e := range live {
		if e.Silenced || e.Weight(now) == 0 {
			continue
		}
		k := e.Component.Key()
		p := piles[k]
		if p == nil {
			p = &pile{up: Upgrade{Package: k,
				Ecosystem: strings.ToLower(strings.TrimSpace(e.Component.Ecosystem)),
				Name:      e.Component.Name},
				versions: map[string]bool{}, assets: map[string]bool{},
				adv: map[string]Exposure{}}
			piles[k] = p
			keys = append(keys, k)
		}
		p.versions[e.Component.Version] = true
		p.assets[e.Component.Where.String()] = true
		// One exposure per advisory is kept: the one on the highest
		// installed version, because its fix is the one every other
		// installation is also below.
		if old, seen := p.adv[e.Advisory.ID]; !seen {
			p.adv[e.Advisory.ID] = e
			p.order = append(p.order, e.Advisory.ID)
		} else if c, ok := Compare(e.Component.Version,
			old.Component.Version); ok && c > 0 {
			p.adv[e.Advisory.ID] = e
		}
	}

	var out []Upgrade
	for _, k := range keys {
		p := piles[k]
		up := p.up
		for v := range p.versions {
			up.Versions = append(up.Versions, v)
		}
		sort.Slice(up.Versions, func(i, j int) bool {
			if c, ok := Compare(up.Versions[i], up.Versions[j]); ok {
				return c < 0
			}
			return up.Versions[i] < up.Versions[j]
		})
		up.Assets = len(p.assets)
		sort.Strings(p.order)

		// The target: the highest of the fixes, since anything lower leaves
		// the advisory that needed the highest one open.
		left := map[string]string{}
		for _, id := range p.order {
			e := p.adv[id]
			fix, ok := fixFor(e.Advisory, e.Component)
			if !ok {
				left[id] = "no fix has been published"
				continue
			}
			if up.To == "" {
				up.To = fix
				continue
			}
			c, comparable := Compare(fix, up.To)
			if !comparable {
				left[id] = fmt.Sprintf("its fix, %s, cannot be ordered "+
					"against %s", fix, up.To)
				continue
			}
			if c > 0 {
				up.To = fix
			}
		}

		if up.To != "" {
			// Then walk the target forward past anything known to be wrong
			// with it. Bounded: a feed whose ranges chase each other is a
			// broken feed, and the answer to it is to stop.
			for i := 0; i < 16; i++ {
				moved := false
				at := Component{Ecosystem: up.Ecosystem, Name: up.Name,
					Version: up.To}
				for _, a := range known {
					if v, _ := a.Applies(at); v != Vulnerable {
						continue
					}
					next, ok := fixFor(a, at)
					if !ok {
						continue
					}
					if c, comparable := Compare(next, up.To); comparable &&
						c > 0 {
						up.To, moved = next, true
					}
				}
				if !moved {
					break
				}
			}
			at := Component{Ecosystem: up.Ecosystem, Name: up.Name,
				Version: up.To}
			for _, a := range known {
				if _, open := p.adv[a.ID]; open {
					continue
				}
				if v, _ := a.Applies(at); v == Vulnerable {
					up.Into = append(up.Into, a.ID)
				}
			}
			sort.Strings(up.Into)
			for _, id := range p.order {
				if _, already := left[id]; already {
					continue
				}
				e := p.adv[id]
				switch v, why := e.Advisory.Applies(at); v {
				case Patched, Outside:
					up.Clears = append(up.Clears, id)
					up.Expected += e.Advisory.EPSS
					if yes, _ := e.Advisory.Attested(); yes {
						up.Exploited = true
					}
				default:
					left[id] = why
				}
			}
			if len(up.Clears) == 0 {
				up.To = ""
			}
		}
		for _, id := range p.order {
			if why, ok := left[id]; ok {
				up.Leaves = append(up.Leaves, Left{ID: id, Why: why})
			}
		}
		out = append(out, up)
	}
	// What is being exploited, then what removes the most expected
	// exploitation, then what closes the most rows. Things with nowhere to
	// go come last: they are decisions, not upgrades.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.To != "") != (b.To != "") {
			return a.To != ""
		}
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if a.Expected != b.Expected {
			return a.Expected > b.Expected
		}
		if len(a.Clears) != len(b.Clears) {
			return len(a.Clears) > len(b.Clears)
		}
		return a.Package < b.Package
	})
	return out
}

// Tally is the queue as a handful of numbers, for a trend.
//
// Aggregates only. A history of which host carried what is an inventory of
// every machine's weaknesses by date, and nothing about a trend line needs
// one.
type Tally struct {
	At time.Time `json:"at"`
	// Vulnerabilities is distinct open advisories; Exposures is rows.
	Vulnerabilities int `json:"vulnerabilities"`
	Exposures       int `json:"exposures"`
	// Exploited is open advisories somebody attests are being exploited.
	Exploited int     `json:"exploited"`
	Expected  float64 `json:"expected"`
	// Decided away, by how.
	NotAffected   int `json:"not_affected"`
	Fixed         int `json:"fixed"`
	Accepted      int `json:"accepted"`
	Investigating int `json:"investigating"`
	// Lapsed is decisions that ran out and are back in the queue.
	Lapsed int `json:"lapsed"`
}

// Summarise counts a matched queue.
func Summarise(matched []Exposure, now time.Time) Tally {
	t := Tally{At: now}
	open, exploited := map[string]bool{}, map[string]bool{}
	var live []Exposure
	for _, e := range matched {
		if e.Silenced {
			switch {
			case e.Assessed.Status == NotAffected:
				t.NotAffected++
			case e.Assessed.Status == Fixed:
				t.Fixed++
			case e.Assessed.Accepted():
				t.Accepted++
			case e.Assessed.Status == UnderInvestigation:
				t.Investigating++
			}
			continue
		}
		if e.Weight(now) == 0 {
			continue
		}
		live = append(live, e)
		t.Exposures++
		open[e.Advisory.ID] = true
		if yes, _ := e.Advisory.Attested(); yes {
			exploited[e.Advisory.ID] = true
		}
		if e.Assessed.Lapsed(now) {
			t.Lapsed++
		}
	}
	t.Vulnerabilities, t.Exploited = len(open), len(exploited)
	t.Expected = Expected(live, now)
	return t
}

// Document is an OpenVEX document: what this organisation says about the
// vulnerabilities in what it runs, in the form a customer's scanner reads.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  time.Time   `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is one line of a Document.
type Statement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Timestamp     time.Time `json:"timestamp"`
	Products      []Product `json:"products"`
	Status        Status    `json:"status"`
	Justification string    `json:"justification,omitempty"`
	Impact        string    `json:"impact_statement,omitempty"`
	Action        string    `json:"action_statement,omitempty"`
}

// Product identifies what a statement is about.
type Product struct {
	ID string `json:"@id"`
}

// OpenVEXContext is the version of the format written.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// Draft writes the current assessments as an OpenVEX document.
//
// A draft, because a VEX document is a public statement and this is its
// text, not its publication: somebody reads it, and signs it, and that is
// where the organisation's name goes on it. Names of the people who made
// each assessment are left out — the document speaks for the author — and
// so is the evidence, which is internal; the impact statement is what was
// written to be read outside.
//
// The newest assessment for each thing is the one stated. A lapsed
// investigation is stated as under investigation no longer: it is left out,
// since the true status is "nobody has decided", which VEX cannot say and
// which a consumer correctly reads from silence.
func Draft(assessments []Assessment, author, id string,
	now time.Time) (Document, error) {

	d := Document{Context: OpenVEXContext, ID: id, Author: author,
		Timestamp: now.UTC(), Version: 1, Statements: []Statement{}}
	if strings.TrimSpace(author) == "" {
		return d, fmt.Errorf("a VEX document needs an author: it is a " +
			"statement, and a statement is somebody's")
	}
	if strings.TrimSpace(id) == "" {
		return d, fmt.Errorf("a VEX document needs an identifier, so a " +
			"later version can say which one it replaces")
	}
	newest := map[string]Assessment{}
	var keys []string
	for _, a := range assessments {
		old, seen := newest[a.Key()]
		if !seen {
			keys = append(keys, a.Key())
		}
		if !seen || !old.At.After(a.At) {
			newest[a.Key()] = a
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := newest[k]
		if a.Lapsed(now) {
			continue
		}
		st := Statement{Timestamp: a.At.UTC(), Status: a.Status,
			Products:      []Product{{ID: purl(a.Component)}},
			Justification: string(a.Justification), Impact: a.Impact}
		st.Vulnerability.Name = a.Advisory
		if a.Status == Affected {
			// Required by the format, and rightly: "affected" with no next
			// step is a warning with nothing to do about it.
			st.Action = "Upgrade to a fixed version when one is available."
			if a.Accepted() {
				st.Action = fmt.Sprintf("Remediation is scheduled; this "+
					"statement will be revised by %s.",
					a.Until.UTC().Format("2006-01-02"))
			}
		}
		d.Statements = append(d.Statements, st)
	}
	return d, nil
}

// purl writes ecosystem:name as a package URL without a version: the
// statement is about the package wherever it is installed.
func purl(component string) string {
	eco, name, ok := strings.Cut(component, ":")
	if !ok {
		return "pkg:generic/" + component
	}
	// OSV's ecosystem names and the package URL types are two lists kept by
	// two groups; these are where they differ.
	switch eco {
	case "go":
		eco = "golang"
	case "crates.io":
		eco = "cargo"
	case "rubygems":
		eco = "gem"
	case "packagist":
		eco = "composer"
	case "maven":
		name = strings.ReplaceAll(name, ":", "/")
	}
	return "pkg:" + eco + "/" + name
}
