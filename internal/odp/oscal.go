// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package odp

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/oscal"
)

// SetParameters is every parameter this program answers for, as OSCAL
// set-parameters: the declared value where the organisation declared one,
// and what the deployment does otherwise. Each says which, and a declared
// one says whether it is met now.
func SetParameters(pol *Policy, cfg *config.Config) []oscal.SetParameter {
	var out []oscal.SetParameter
	for _, p := range Params {
		sp := oscal.SetParameter{ParamID: p.ID}
		source := "effective"
		switch p.How {
		case Fixed:
			source = "fixed"
		case Described:
			source = "described"
		}
		value := Effective(p, cfg)
		if pol != nil {
			if d, ok := pol.Find(p.ID); ok {
				source, value = "declared", d.Value
				met := "true"
				if !Met(d, cfg) {
					met = "false"
				}
				sp.Props = append(sp.Props, oscal.Prop{Name: "met", NS: oscal.Namespace, Value: met})
			}
		}
		sp.Values = splitValues(p, value)
		sp.Props = append([]oscal.Prop{{Name: "source", NS: oscal.Namespace, Value: source}}, sp.Props...)
		if p.Setting != "" {
			sp.Props = append(sp.Props, oscal.Prop{Name: "setting", NS: oscal.Namespace, Value: p.Setting})
		}
		sp.Remarks = p.Means
		out = append(out, sp)
	}
	return out
}

func splitValues(p Param, v string) []string {
	if p.Kind == Choice {
		return splitChoices(v)
	}
	return []string{v}
}

// Imported is what an OSCAL document's parameters became.
type Imported struct {
	// Kind is the document read: profile, system security plan, …
	Kind string
	// Changes are the parameters this program can keep, ready to propose.
	Changes []Change
	// Unchanged are declared already with the same value.
	Unchanged []string
	// NotOurs are parameters about something else — the organisation's
	// people and processes, or other systems — which this program neither
	// enforces nor contradicts.
	NotOurs []string
	// Refused are parameters this program answers for and cannot keep at
	// the value given, each with the reason.
	Refused []string
}

// FromOSCAL reads an OSCAL document's parameters against the closed list.
func FromOSCAL(body []byte, pol *Policy) (Imported, error) {
	params, kind, err := oscal.ReadSetParameters(body)
	if err != nil {
		return Imported{}, err
	}
	im := Imported{Kind: kind}
	for _, sp := range params {
		p, ok := Lookup(sp.ParamID)
		if !ok {
			im.NotOurs = append(im.NotOurs, sp.ParamID)
			continue
		}
		if p.How == Described {
			im.NotOurs = append(im.NotOurs, sp.ParamID+" (this program describes it; the settings it describes are declared instead)")
			continue
		}
		value := strings.TrimSpace(strings.Join(sp.Values, "\n"))
		if p.Kind != Choice && len(sp.Values) > 1 {
			im.Refused = append(im.Refused, fmt.Sprintf("%s has %d values; it takes one", p.ID, len(sp.Values)))
			continue
		}
		if err := p.Check(value); err != nil {
			im.Refused = append(im.Refused, err.Error())
			continue
		}
		if pol != nil {
			if d, ok := pol.Find(p.ID); ok && d.Value == value {
				im.Unchanged = append(im.Unchanged, p.ID)
				continue
			}
		}
		im.Changes = append(im.Changes, Change{Param: p.ID, Value: value})
	}
	return im, nil
}
