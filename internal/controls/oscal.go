// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package controls

import (
	"time"

	"github.com/quilzo/quilzo/internal/oscal"
)

// ComponentDefinition is the table as an OSCAL component definition: Quilzo
// as a software component, each control implemented with its statement,
// who is responsible, the rules that check it and the settings that hold
// it, and the parameter values this deployment has.
func ComponentDefinition(version string, params []oscal.SetParameter, at time.Time) (oscal.ComponentDefinition, error) {
	var reqs []oscal.ImplementedRequirement
	for _, im := range All() {
		id, err := oscal.NewUUID()
		if err != nil {
			return oscal.ComponentDefinition{}, err
		}
		r := oscal.ImplementedRequirement{UUID: id, ControlID: Normal(im.Control), Description: im.Statement,
			Props: []oscal.Prop{{Name: "responsibility", NS: oscal.Namespace, Value: string(im.Responsibility)}}}
		for _, rule := range im.Rules {
			r.Props = append(r.Props, oscal.Prop{Name: "checked-by", NS: oscal.Namespace, Value: rule})
		}
		for _, key := range im.Settings {
			r.Props = append(r.Props, oscal.Prop{Name: "set-by", NS: oscal.Namespace, Value: key})
		}
		switch im.Responsibility {
		case Quilzo:
			r.ResponsibleRoles = []oscal.ResponsibleRole{{RoleID: "provider"}}
		case Shared:
			r.ResponsibleRoles = []oscal.ResponsibleRole{{RoleID: "provider"}, {RoleID: "customer"}}
		case Customer:
			r.ResponsibleRoles = []oscal.ResponsibleRole{{RoleID: "customer"}}
		}
		if im.Customer != "" {
			r.Remarks = "The customer's part: " + im.Customer
		}
		reqs = append(reqs, r)
	}
	ciID, err := oscal.NewUUID()
	if err != nil {
		return oscal.ComponentDefinition{}, err
	}
	compID, err := oscal.NewUUID()
	if err != nil {
		return oscal.ComponentDefinition{}, err
	}
	comp := oscal.DefinedComponent{
		UUID: compID, Type: "software", Title: "Quilzo",
		Description: "A single self-hosted binary: content platform, admin, security console, agent runtime and " +
			"machine interface, with the Go standard library as its only dependency.",
		Purpose: "To publish and administer sites and run agents under one access policy and one audit log.",
		Props:   []oscal.Prop{{Name: "version", Value: version}},
		ControlImplementations: []oscal.ControlImplementation{{
			UUID: ciID, Source: oscal.CatalogHref,
			Description: "How Quilzo implements NIST SP 800-53 Rev 5 controls. A statement says what the " +
				"software does; for a shared control the customer's part is in the remarks, and the " +
				"control is only as implemented as that part.",
			SetParameters:           oscal.ForImplementation(params),
			ImplementedRequirements: reqs,
		}},
	}
	roles := []oscal.Role{
		{ID: "provider", Title: "Provider", Description: "Quilzo, the software."},
		{ID: "customer", Title: "Customer", Description: "The organisation that runs it."},
	}
	return oscal.NewComponentDefinition("Quilzo: control implementations", version, at, roles, []oscal.DefinedComponent{comp})
}
