// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package controls says how Quilzo implements each NIST SP 800-53 control
// it has anything to do with, and who is responsible for the rest.
//
// A system security plan is mostly this table, written by hand, months
// after the software changed, by somebody who has to guess what the code
// does. Here it is kept beside the code: one statement per control, written
// by the people who wrote the code, with the responsibility split stated
// (Quilzo does it; the customer does it; or Quilzo provides it and the
// customer runs it), and joined at runtime to what proves it — the posture
// rules that check it, the settings that hold its values, and the
// organisation's declared parameters (internal/odp). A control a rule or a
// setting cites must have a statement here, which a test enforces, so the
// plan cannot fall behind the checks.
//
// What a statement is: how this software implements the control, in words
// an assessor can test. What it is not: a claim the deployment is compliant.
// A shared control is only as implemented as the customer's half.
package controls

import (
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/oscal"
	"github.com/quilzo/quilzo/internal/posture"
)

// Responsibility is who implements a control.
type Responsibility string

const (
	// Quilzo: the software implements it with nothing for the customer to do.
	Quilzo Responsibility = "quilzo"
	// Shared: the software provides it and the customer configures or runs
	// it; Customer says which part.
	Shared Responsibility = "shared"
	// Customer: the customer's own; Quilzo helps only where Statement says.
	Customer Responsibility = "customer"
)

// Implementation is one control.
type Implementation struct {
	Control        string         `json:"control"`
	Title          string         `json:"title"`
	Responsibility Responsibility `json:"responsibility"`
	// Statement is how Quilzo implements it.
	Statement string `json:"statement"`
	// Customer is the customer's part, for Shared and Customer.
	Customer string `json:"customer,omitempty"`
	// Where names the commands, screens and packages that do it.
	Where []string `json:"where,omitempty"`
	// Rules, Settings and Params are joined in from the posture rules, the
	// settings and the organisation's parameters by All.
	Rules    []string `json:"rules,omitempty"`
	Settings []string `json:"settings,omitempty"`
	Params   []string `json:"params,omitempty"`
}

// All is every implementation, joined to its rules, settings and
// parameters, in control order.
func All() []Implementation {
	rules := map[string][]string{}
	for _, r := range posture.Rules() {
		for _, c := range r.Controls {
			rules[c] = append(rules[c], r.ID)
		}
	}
	settings := map[string][]string{}
	for _, s := range config.All() {
		for _, c := range s.Controls {
			settings[c] = append(settings[c], s.Key)
		}
	}
	params := map[string][]string{}
	for _, p := range odp.Params {
		params[p.Control] = append(params[p.Control], p.ID)
	}
	out := make([]Implementation, len(table))
	copy(out, table)
	for i := range out {
		c := out[i].Control
		out[i].Rules, out[i].Settings, out[i].Params = rules[c], settings[c], params[c]
	}
	sort.Slice(out, func(i, j int) bool { return Less(out[i].Control, out[j].Control) })
	return out
}

// Lookup finds one control, written as the catalogue writes it or in
// OSCAL's form (ac-2.5).
func Lookup(id string) (Implementation, bool) {
	want := Normal(id)
	for _, im := range All() {
		if Normal(im.Control) == want {
			return im, true
		}
	}
	return Implementation{}, false
}

// Normal is a control id in OSCAL's form: AC-2(5) is ac-2.5.
func Normal(id string) string { return oscal.ControlID(id) }

// Less orders controls the way the catalogue does: by family, then number,
// then enhancement.
func Less(a, b string) bool {
	na, nb := Normal(a), Normal(b)
	fa, ra, _ := strings.Cut(na, "-")
	fb, rb, _ := strings.Cut(nb, "-")
	if fa != fb {
		return fa < fb
	}
	pa, pb := strings.Split(ra, "."), strings.Split(rb, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if x, y := atoi(pa[i]), atoi(pb[i]); x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// Count is how many controls each party carries.
func Count(all []Implementation) map[Responsibility]int {
	out := map[Responsibility]int{}
	for _, im := range all {
		out[im.Responsibility]++
	}
	return out
}
