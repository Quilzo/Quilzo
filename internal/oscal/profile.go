// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oscal

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Organisation-defined parameters, in and out.
//
// An organisation keeps its parameter values in its governance tool, and
// OSCAL carries them in three places: a profile's modify block (the
// organisation's tailoring of the catalogue), a system security plan's
// control implementation, and a component definition's control
// implementations. Each is a list of set-parameters, a parameter id and its
// values. ReadSetParameters takes any of the three; ParameterProfile writes
// the first, which is the document a governance tool imports.

// CatalogHref is NIST's SP 800-53 Rev 5 catalogue in OSCAL JSON, which the
// parameter ids refer to.
const CatalogHref = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"

// Namespace marks properties this program adds.
const Namespace = "https://quilzo.org/ns/oscal"

// Prop is an OSCAL property.
type Prop struct {
	Name  string `json:"name"`
	NS    string `json:"ns,omitempty"`
	Value string `json:"value"`
}

// SetParameter is one parameter's value.
type SetParameter struct {
	ParamID string   `json:"param-id"`
	Values  []string `json:"values,omitempty"`
	Props   []Prop   `json:"props,omitempty"`
	Remarks string   `json:"remarks,omitempty"`
}

// Profile is the root of a profile document.
type Profile struct {
	Profile ProfileBody `json:"profile"`
}

// ProfileBody is the profile object.
type ProfileBody struct {
	UUID     string    `json:"uuid"`
	Metadata Metadata  `json:"metadata"`
	Imports  []Import  `json:"imports"`
	Modify   *Modify   `json:"modify,omitempty"`
	Merge    *struct{} `json:"merge,omitempty"`
}

// Import names the catalogue the profile tailors.
type Import struct {
	Href       string    `json:"href"`
	IncludeAll *struct{} `json:"include-all,omitempty"`
}

// Modify carries the parameter values.
type Modify struct {
	SetParameters []ParameterSetting `json:"set-parameters"`
}

// ParameterSetting is a profile's setting of a parameter. Not SetParameter:
// a profile's schema allows usage and no remarks, an implementation's the
// other way round, and a document with the wrong one fails validation.
type ParameterSetting struct {
	ParamID string   `json:"param-id"`
	Props   []Prop   `json:"props,omitempty"`
	Usage   string   `json:"usage,omitempty"`
	Values  []string `json:"values,omitempty"`
}

// ParameterProfile is a profile that sets parameters of the 800-53
// catalogue and changes nothing else.
func ParameterProfile(title, version string, at time.Time, params []SetParameter) (Profile, error) {
	id, err := newUUID()
	if err != nil {
		return Profile{}, err
	}
	return Profile{Profile: ProfileBody{
		UUID: id,
		Metadata: Metadata{
			Title: nonEmpty(title, "Organisation-defined parameters"), LastModified: at.UTC().Format(time.RFC3339),
			Version: nonEmpty(version, "1"), OSCALVersion: Version,
			Remarks: "The organisation-defined parameter values this deployment holds. A value marked " +
				"declared was adopted by the organisation and is enforced as a floor; effective is what the " +
				"deployment does now; fixed is the program's own behaviour.",
		},
		Imports: []Import{{Href: CatalogHref, IncludeAll: &struct{}{}}},
		Modify:  &Modify{SetParameters: settings(params)},
	}}, nil
}

// settings turns implementation set-parameters into a profile's settings,
// their remarks becoming the usage a profile carries.
func settings(in []SetParameter) []ParameterSetting {
	out := make([]ParameterSetting, 0, len(in))
	for _, p := range in {
		out = append(out, ParameterSetting{ParamID: p.ParamID, Props: p.Props, Usage: p.Remarks, Values: p.Values})
	}
	return out
}

// ReadSetParameters finds the parameter values in an OSCAL document: a
// profile, a system security plan, a component definition, or a bare
// {"set-parameters": [...]}. It says which it read.
func ReadSetParameters(body []byte) ([]SetParameter, string, error) {
	if len(body) > 32<<20 {
		return nil, "", errors.New("that document is larger than 32 MiB, which is not a parameter list")
	}
	var doc struct {
		Profile *struct {
			Modify *struct {
				SetParameters []SetParameter `json:"set-parameters"`
			} `json:"modify"`
		} `json:"profile"`
		SSP *struct {
			ControlImplementation struct {
				SetParameters           []SetParameter `json:"set-parameters"`
				ImplementedRequirements []struct {
					SetParameters []SetParameter `json:"set-parameters"`
					ByComponents  []struct {
						SetParameters []SetParameter `json:"set-parameters"`
					} `json:"by-components"`
				} `json:"implemented-requirements"`
			} `json:"control-implementation"`
		} `json:"system-security-plan"`
		ComponentDefinition *struct {
			Components []struct {
				ControlImplementations []struct {
					SetParameters           []SetParameter `json:"set-parameters"`
					ImplementedRequirements []struct {
						SetParameters []SetParameter `json:"set-parameters"`
					} `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
		SetParameters []SetParameter `json:"set-parameters"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("that is not an OSCAL document in JSON: %w", err)
	}
	var out []SetParameter
	kind := ""
	switch {
	case doc.Profile != nil:
		kind = "profile"
		if doc.Profile.Modify != nil {
			out = doc.Profile.Modify.SetParameters
		}
	case doc.SSP != nil:
		kind = "system security plan"
		ci := doc.SSP.ControlImplementation
		out = append(out, ci.SetParameters...)
		for _, ir := range ci.ImplementedRequirements {
			out = append(out, ir.SetParameters...)
			for _, bc := range ir.ByComponents {
				out = append(out, bc.SetParameters...)
			}
		}
	case doc.ComponentDefinition != nil:
		kind = "component definition"
		for _, c := range doc.ComponentDefinition.Components {
			for _, ci := range c.ControlImplementations {
				out = append(out, ci.SetParameters...)
				for _, ir := range ci.ImplementedRequirements {
					out = append(out, ir.SetParameters...)
				}
			}
		}
	case doc.SetParameters != nil:
		kind = "parameter list"
		out = doc.SetParameters
	default:
		return nil, "", errors.New("no profile, system security plan or component definition found, and no set-parameters")
	}
	// The same parameter set twice in one document is a conflict the
	// document's author has to settle; taking either silently would be
	// choosing for them.
	seen := map[string]string{}
	for i := range out {
		out[i].ParamID = strings.ToLower(strings.TrimSpace(out[i].ParamID))
		v := strings.Join(out[i].Values, "\n")
		if prev, dup := seen[out[i].ParamID]; dup && prev != v {
			return nil, kind, fmt.Errorf("%s is set twice in that %s, to different values", out[i].ParamID, kind)
		}
		seen[out[i].ParamID] = v
	}
	return dedupe(out), kind, nil
}

func dedupe(in []SetParameter) []SetParameter {
	seen := map[string]bool{}
	var out []SetParameter
	for _, p := range in {
		if p.ParamID == "" || seen[p.ParamID] {
			continue
		}
		seen[p.ParamID] = true
		out = append(out, p)
	}
	return out
}
