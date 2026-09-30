// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SSVC: what to do about a vulnerability, as a decision and not a score.
//
// CERT/CC's deployer tree takes four things — is it being exploited, how
// exposed is the system, could an attack be automated, what is lost if it
// works — and answers with one of four words: defer, scheduled,
// out-of-cycle, immediate.
//
// Two of the four are about the vulnerability and two are about the
// machine it is on. No feed knows the second two. So this keeps them as
// tags an organisation puts on its own assets, and where one is missing
// it does not guess: it works the tree for every value the missing input
// could take and reports the range. "Scheduled to immediate, depending on
// how exposed this is" is a true statement. "Scheduled", computed from an
// exposure nobody recorded, is not.
//
// The tree itself is not in this program. It is CERT/CC's table, published
// under their terms, and it is loaded from the file they publish. That
// also means a newer version of the tree is a file, not a release.

// The decision points, in the tree's own words.
var (
	Exploitations = []string{"none", "public poc", "active"}
	Exposures     = []string{"small", "controlled", "open"}
	Automatables  = []string{"no", "yes"}
	Impacts       = []string{"low", "medium", "high", "very high"}
	// Outcomes are in order of urgency.
	Outcomes = []string{"defer", "scheduled", "out-of-cycle", "immediate"}
)

func among(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func urgency(outcome string) int {
	for n, o := range Outcomes {
		if o == outcome {
			return n
		}
	}
	return -1
}

// Tree is the deployer decision table: exploitation, exposure,
// automatable, human impact, to an outcome.
type Tree map[[4]string]string

// ParseTree reads the table as CERT/CC publishes it: a CSV whose header
// names the four decision points and the outcome. Every combination must
// be present exactly once; a tree with a hole in it answers some
// vulnerability with nothing.
func ParseTree(in []byte) (Tree, error) {
	if len(in) > 1<<20 {
		return nil, fmt.Errorf("a decision table of %d bytes", len(in))
	}
	r := csv.NewReader(bytes.NewReader(in))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("this is not a CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("this table has no rows")
	}
	col := map[string]int{}
	for n, h := range rows[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		switch {
		case strings.HasPrefix(h, "exploitation"):
			col["exploitation"] = n
		case strings.Contains(h, "exposure"):
			col["exposure"] = n
		case strings.HasPrefix(h, "automatable"):
			col["automatable"] = n
		case strings.HasPrefix(h, "human impact"):
			col["impact"] = n
		case strings.Contains(h, "defer") || strings.HasPrefix(h, "priority") ||
			strings.HasPrefix(h, "outcome"):
			col["outcome"] = n
		}
	}
	for _, need := range []string{"exploitation", "exposure", "automatable",
		"impact", "outcome"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("the table has no %s column. This reads "+
				"the deployer table, whose header names Exploitation, "+
				"System Exposure, Automatable, Human Impact and the outcome",
				need)
		}
	}
	t := Tree{}
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "poc" {
			s = "public poc"
		}
		return s
	}
	for n, row := range rows[1:] {
		at := func(name string) string {
			if i := col[name]; i < len(row) {
				return norm(row[i])
			}
			return ""
		}
		k := [4]string{at("exploitation"), at("exposure"), at("automatable"),
			at("impact")}
		out := at("outcome")
		if !among(Exploitations, k[0]) || !among(Exposures, k[1]) ||
			!among(Automatables, k[2]) || !among(Impacts, k[3]) ||
			!among(Outcomes, out) {
			return nil, fmt.Errorf("row %d (%s) uses a value this does not "+
				"know", n+1, strings.Join(row, ","))
		}
		if _, dup := t[k]; dup {
			return nil, fmt.Errorf("row %d repeats %s", n+1,
				strings.Join(k[:], ", "))
		}
		t[k] = out
	}
	want := len(Exploitations) * len(Exposures) * len(Automatables) * len(Impacts)
	if len(t) != want {
		return nil, fmt.Errorf("the table has %d of the %d combinations. "+
			"One with a hole answers some vulnerability with nothing",
			len(t), want)
	}
	return t, nil
}

// AssetTag is what an organisation says about some of its own machines.
type AssetTag struct {
	// Match is an asset as issuer:value, or a prefix ending in *.
	Match string `json:"match"`
	// Exposure is how reachable it is: small, controlled or open.
	Exposure string `json:"exposure"`
	// Impact is what is lost if it is compromised: low to very high.
	Impact  string    `json:"impact"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Because string    `json:"because"`
}

// Validate refuses a tag that says nothing or says it about everything.
func (a AssetTag) Validate() error {
	m := strings.TrimSpace(a.Match)
	if m == "" || len(m) > 300 || strings.ContainsAny(m, "\r\n\x00") {
		return fmt.Errorf("a tag is about an asset, as issuer:value, or a " +
			"prefix ending in *")
	}
	if strings.Count(m, "*") > 1 || (strings.Contains(m, "*") &&
		!strings.HasSuffix(m, "*")) {
		return fmt.Errorf("%s: the * goes at the end, once", m)
	}
	if !strings.Contains(strings.TrimSuffix(m, "*"), ":") {
		// "*" or "mdm*": every asset of every tool. One tag for the whole
		// estate is the input nobody recorded, with a name on it.
		return fmt.Errorf("%s would tag assets from every tool alike. "+
			"Name the issuer at least: mdm:*", m)
	}
	if !among(Exposures, a.Exposure) {
		return fmt.Errorf("exposure is %s", strings.Join(Exposures, ", "))
	}
	if !among(Impacts, a.Impact) {
		return fmt.Errorf("impact is %s", strings.Join(Impacts, ", "))
	}
	if strings.TrimSpace(a.By) == "" || strings.TrimSpace(a.Because) == "" {
		return fmt.Errorf("%s: a tag is somebody's judgement and takes "+
			"their name and a reason", m)
	}
	return nil
}

// Tags is the set of them.
type Tags []AssetTag

// For finds the tag that applies to an asset: the exact one, else the
// longest prefix.
func (t Tags) For(where string) (AssetTag, bool) {
	var best AssetTag
	found := false
	for _, a := range t {
		prefix, wild := strings.CutSuffix(a.Match, "*")
		switch {
		case !wild && a.Match == where:
			return a, true
		case wild && strings.HasPrefix(where, prefix) &&
			(!found || len(a.Match) > len(best.Match)):
			best, found = a, true
		}
	}
	return best, found
}

// Decision is the tree's answer for one exposure.
type Decision struct {
	// Worst and Best are the most and least urgent outcomes the known
	// inputs allow. Equal when nothing is missing.
	Worst string `json:"worst"`
	Best  string `json:"best"`
	// Unknown names the inputs nobody has recorded.
	Unknown []string `json:"unknown,omitempty"`
	// Used is each input as it was taken.
	Exploitation, Exposure, Automatable, Impact string
}

// Settled reports whether every input was known.
func (d Decision) Settled() bool { return len(d.Unknown) == 0 }

// Says puts the decision in a line.
func (d Decision) Says() string {
	if d.Settled() {
		return d.Worst
	}
	if d.Worst == d.Best {
		return d.Worst + " whatever the unrecorded inputs are"
	}
	return fmt.Sprintf("%s to %s, depending on %s", d.Best, d.Worst,
		strings.Join(d.Unknown, " and "))
}

// Decide works the tree for one exposure.
func (t Tree) Decide(e Exposure, tags Tags) Decision {
	var d Decision
	exploitation := []string{"none", "public poc"}
	switch yes, _ := e.Advisory.Attested(); {
	case yes:
		// A fact, whatever else the advisory was annotated with.
		exploitation = []string{"active"}
	case among(Exploitations, e.Advisory.Exploitation):
		exploitation = []string{e.Advisory.Exploitation}
	default:
		d.Unknown = append(d.Unknown, "whether a public exploit exists")
	}
	if len(exploitation) == 1 {
		d.Exploitation = exploitation[0]
	}
	automatable := Automatables
	if e.Advisory.Automatable != nil {
		automatable = []string{"no"}
		if *e.Advisory.Automatable {
			automatable = []string{"yes"}
		}
		d.Automatable = automatable[0]
	} else {
		d.Unknown = append(d.Unknown, "whether an attack can be automated")
	}
	exposure, impact := Exposures, Impacts
	if tag, ok := tags.For(e.Component.Where.String()); ok {
		exposure, impact = []string{tag.Exposure}, []string{tag.Impact}
		d.Exposure, d.Impact = tag.Exposure, tag.Impact
	} else {
		d.Unknown = append(d.Unknown, "how exposed and how important "+
			e.Component.Where.String()+" is")
	}
	lo, hi := len(Outcomes), -1
	for _, a := range exploitation {
		for _, b := range exposure {
			for _, c := range automatable {
				for _, h := range impact {
					u := urgency(t[[4]string{a, b, c, h}])
					if u < 0 {
						continue
					}
					if u < lo {
						lo = u
					}
					if u > hi {
						hi = u
					}
				}
			}
		}
	}
	if hi < 0 {
		return Decision{Unknown: []string{"the decision table"}}
	}
	d.Worst, d.Best = Outcomes[hi], Outcomes[lo]
	sort.Strings(d.Unknown)
	return d
}

// More reports whether a is more urgent than b, by its worst case and then
// its best.
func (d Decision) More(o Decision) bool {
	if urgency(d.Worst) != urgency(o.Worst) {
		return urgency(d.Worst) > urgency(o.Worst)
	}
	return urgency(d.Best) > urgency(o.Best)
}
