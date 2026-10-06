// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package controls

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/oscal"
)

// A system security plan for one deployment, drafted from what is known:
// the baseline for the impact level the owner chose, the statements in the
// table split between Quilzo and the organisation, the declared
// parameters, and the posture scan's live findings, which turn a control
// Quilzo implements into a partial one for as long as a check fails.
//
// Drafted, not finished: the organisation's part of every shared control
// is named for it to describe, and the information types and boundary are
// the owner's to confirm. The document says so where it matters.

// SSPInput is what the plan is drafted from.
type SSPInput struct {
	// Impact is low, moderate or high (FIPS 199), chosen by the owner.
	Impact string
	// SystemID identifies this deployment across revisions of the plan.
	SystemID     string
	SystemName   string
	Organisation string
	Version      string
	At           time.Time
	Params       []oscal.SetParameter
	// Failing is, by control in OSCAL form, the findings the last scan
	// raised against it.
	Failing map[string][]string
}

// SystemSecurityPlan drafts the plan.
func SystemSecurityPlan(in SSPInput) (oscal.SSP, error) {
	switch in.Impact {
	case "low", "moderate", "high":
	default:
		return oscal.SSP{}, fmt.Errorf("the impact level is low, moderate or high (FIPS 199); %q is none of them", in.Impact)
	}
	level := "fips-199-" + in.Impact
	ids := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		id, err := oscal.NewUUID()
		if err != nil {
			return oscal.SSP{}, err
		}
		ids = append(ids, id)
	}
	docID, thisSystem, quilzo, infoID, orgID := ids[0], ids[1], ids[2], ids[3], ids[4]
	name := in.SystemName
	if name == "" {
		name = "Quilzo deployment"
	}

	var reqs []oscal.SSPImplementation
	for _, im := range All() {
		rid, err := oscal.NewUUID()
		if err != nil {
			return oscal.SSP{}, err
		}
		cid := Normal(im.Control)
		req := oscal.SSPImplementation{UUID: rid, ControlID: cid,
			Props: []oscal.Prop{{Name: "responsibility", NS: oscal.Namespace, Value: string(im.Responsibility)}}}
		if im.Responsibility != Customer {
			bid, err := oscal.NewUUID()
			if err != nil {
				return oscal.SSP{}, err
			}
			status := &oscal.State{State: "implemented"}
			if found := in.Failing[cid]; len(found) > 0 {
				sort.Strings(found)
				status = &oscal.State{State: "partial", Remarks: "The posture scan reports, for this control: " +
					strings.Join(found, "; ") + "."}
			}
			req.ByComponents = append(req.ByComponents, oscal.ByComponent{ComponentUUID: quilzo, UUID: bid,
				Description: im.Statement, ImplementationStatus: status,
				ResponsibleRoles: []oscal.ResponsibleRole{{RoleID: "provider"}}})
		}
		if im.Customer != "" {
			bid, err := oscal.NewUUID()
			if err != nil {
				return oscal.SSP{}, err
			}
			desc := im.Customer
			if im.Responsibility == Customer && im.Statement != "" {
				desc += " Quilzo's help: " + im.Statement
			}
			req.ByComponents = append(req.ByComponents, oscal.ByComponent{ComponentUUID: thisSystem, UUID: bid,
				Description: desc, ResponsibleRoles: []oscal.ResponsibleRole{{RoleID: "customer"}},
				Remarks: "The organisation's part: describe how it is done here before this plan is submitted."})
		}
		reqs = append(reqs, req)
	}

	return oscal.SSP{SystemSecurityPlan: oscal.SSPBody{
		UUID: docID,
		Metadata: oscal.PartyMetadata{
			Title: name + ": system security plan", LastModified: in.At.UTC().Format(time.RFC3339),
			Version: nonEmpty(in.Version, "1"), OSCALVersion: oscal.Version,
			Roles: []oscal.Role{
				{ID: "provider", Title: "Provider", Description: "Quilzo, the software."},
				{ID: "customer", Title: "Customer", Description: "The organisation that runs it."},
				{ID: "reader", Title: "Reader"}, {ID: "author", Title: "Author"},
				{ID: "publisher", Title: "Publisher"}, {ID: "admin", Title: "Administrator"},
			},
			Parties: []oscal.Party{{UUID: orgID, Type: "organization", Name: nonEmpty(in.Organisation, name)}},
			Remarks: "Drafted by Quilzo from its control statements, the organisation's declared parameters and the " +
				"latest posture scan. Quilzo's part of each control is written; the organisation's part of every " +
				"shared or customer control is named and must be described before submission. The information " +
				"types and the boundary are for the system owner to confirm.",
		},
		ImportProfile: oscal.ImportProfile{Href: oscal.BaselineHref(in.Impact),
			Remarks: "NIST's SP 800-53 Rev 5 " + in.Impact + " baseline. Replace it with the organisation's own tailored profile where there is one."},
		SystemCharacteristics: oscal.SystemCharacteristics{
			SystemIDs:  []oscal.SystemID{{IdentifierType: "https://ietf.org/rfc/rfc4122", ID: in.SystemID}},
			SystemName: name,
			Description: "A Quilzo deployment: the self-hosted control plane for the organisation's AI agents and the " +
				"content they produce — the published site, the admin, the agents and the security console, as one binary.",
			SecuritySensitivityLevel: level,
			SystemInformation: oscal.SystemInformation{InformationTypes: []oscal.InformationType{{
				UUID: infoID, Title: "Published content and its administration",
				Description: "Pages, media and records written for publication; the accounts, credentials, audit log " +
					"and configuration that administer them; submissions to the site's forms. The system owner " +
					"confirms the types and their levels against NIST SP 800-60.",
				ConfidentialityImpact: &oscal.Impact{Base: level}, IntegrityImpact: &oscal.Impact{Base: level},
				AvailabilityImpact: &oscal.Impact{Base: level},
			}}},
			SecurityImpactLevel: &oscal.SecurityImpactLevel{Confidentiality: level, Integrity: level, Availability: level},
			Status:              oscal.State{State: "operational"},
			AuthorizationBoundary: oscal.AuthorizationBoundary{Description: "Inside: the Quilzo processes (the public " +
				"site, the admin, the log collector), the store and its keys on the host that runs them. Outside, " +
				"and covered by their own authorisations: the proxy that terminates TLS, the identity provider, " +
				"model providers reached through the gateway, and any system an integration calls."},
		},
		SystemImplementation: oscal.SystemImplementation{
			Users: []oscal.SystemUser{
				{UUID: ids[5], Title: "Administrators", Description: "Change access, settings, the policy and integrations.", RoleIDs: []string{"admin"}},
				{UUID: ids[6], Title: "Publishers and authors", Description: "Write and publish content.", RoleIDs: []string{"publisher", "author"}},
				{UUID: ids[7], Title: "Readers", Description: "Read drafts and reports; auditors are readers of the compliance and log areas.", RoleIDs: []string{"reader"}},
			},
			Components: []oscal.SystemComponent{
				{UUID: thisSystem, Type: "this-system", Title: name,
					Description: "The system as a whole, as the organisation operates it.", Status: oscal.State{State: "operational"}},
				{UUID: quilzo, Type: "software", Title: "Quilzo",
					Description: "The Quilzo binary; its control implementations are its component definition's.",
					Props:       []oscal.Prop{{Name: "version", Value: nonEmpty(in.Version, "unknown")}},
					Status:      oscal.State{State: "operational"}},
			},
		},
		ControlImplementation: oscal.SSPControls{
			Description:             "Quilzo's part of each control, and the organisation's part to describe.",
			SetParameters:           oscal.ForImplementation(in.Params),
			ImplementedRequirements: reqs,
		},
	}}, nil
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
