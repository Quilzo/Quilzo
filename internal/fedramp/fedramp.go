// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package fedramp relates Quilzo to FedRAMP 20x's Key Security Indicators.
//
// An indicator is something a cloud service provider shows, persistently
// and preferably by machine, about how it operates: that changes are
// logged, that least privilege holds, that logs reach a SIEM. FedRAMP
// relates each to SP 800-53 controls. Quilzo is one component of whatever
// service a provider authorises, so it cannot meet an indicator; what it
// can do is say, for each one, which of the related controls it implements
// (internal/controls), whether its own checks are passing on them now, and
// which indicators it has nothing to do with — training, recovery tests,
// executive support — so that a provider sees where Quilzo's evidence ends.
//
// The indicators are FedRAMP's, embedded from its consolidated rules (a US
// government work); internal/fedramp/gen refreshes them.
package fedramp

import (
	_ "embed"
	"encoding/json"
	"sort"

	"github.com/quilzo/quilzo/internal/controls"
)

//go:embed ksi.json
var raw []byte

// Source is where the indicators came from.
type Source struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	LastUpdated string `json:"last_updated"`
	URL         string `json:"url"`
}

// Indicator is one Key Security Indicator.
type Indicator struct {
	ID        string   `json:"id"`
	Theme     string   `json:"theme"`
	ThemeName string   `json:"theme_name"`
	Name      string   `json:"name"`
	Statement string   `json:"statement"`
	Controls  []string `json:"controls"`
	// OptionalFor names the FedRAMP classes at which the indicator is
	// optional; the statement is the wording where it is required.
	OptionalFor []string `json:"optional_for,omitempty"`
}

// Indicators is FedRAMP's list, and where it came from.
func Indicators() (Source, []Indicator, error) {
	var doc struct {
		Source     Source      `json:"source"`
		Indicators []Indicator `json:"indicators"`
	}
	err := json.Unmarshal(raw, &doc)
	return doc.Source, doc.Indicators, err
}

// Standing is what Quilzo has to show for an indicator.
type Standing string

const (
	// Contributes: Quilzo implements some of the related controls and its
	// checks on them are passing.
	Contributes Standing = "contributes"
	// Failing: a check on a related control is failing now.
	Failing Standing = "failing"
	// Elsewhere: Quilzo implements none of the related controls; the
	// indicator is shown by the provider's own process.
	Elsewhere Standing = "elsewhere"
)

// Evidence is one related control Quilzo has a part in.
type Evidence struct {
	Control        string   `json:"control"`
	Responsibility string   `json:"responsibility"`
	Statement      string   `json:"statement"`
	Rules          []string `json:"checked_by,omitempty"`
	Failing        []string `json:"failing,omitempty"`
}

// Result is one indicator with what Quilzo has to show for it.
type Result struct {
	Indicator
	Standing Standing   `json:"standing"`
	Covered  int        `json:"related_controls_quilzo_has_a_part_in"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Assess relates every indicator to Quilzo's controls and the findings
// raised against them now (by control, in OSCAL form).
func Assess(failing map[string][]string) (Source, []Result, error) {
	src, all, err := Indicators()
	if err != nil {
		return src, nil, err
	}
	table := map[string]controls.Implementation{}
	for _, im := range controls.All() {
		table[controls.Normal(im.Control)] = im
	}
	var out []Result
	for _, in := range all {
		r := Result{Indicator: in, Standing: Elsewhere}
		for _, c := range in.Controls {
			im, ok := table[controls.Normal(c)]
			if !ok || im.Responsibility == controls.Customer {
				continue
			}
			r.Covered++
			ev := Evidence{Control: im.Control, Responsibility: string(im.Responsibility),
				Statement: im.Statement, Rules: im.Rules, Failing: failing[controls.Normal(c)]}
			r.Evidence = append(r.Evidence, ev)
			if len(ev.Failing) > 0 {
				r.Standing = Failing
			} else if r.Standing != Failing {
				r.Standing = Contributes
			}
		}
		sort.Slice(r.Evidence, func(i, j int) bool { return controls.Less(r.Evidence[i].Control, r.Evidence[j].Control) })
		out = append(out, r)
	}
	return src, out, nil
}
