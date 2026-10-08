// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oscal

import (
	"strings"
	"time"
)

// A component definition: how a piece of software implements controls,
// published by whoever makes it so that whoever runs it can import it into
// their own system security plan instead of writing it again.

// ComponentDefinition is the root of the document.
type ComponentDefinition struct {
	ComponentDefinition ComponentDefinitionBody `json:"component-definition"`
}

// ComponentDefinitionBody is the component-definition object.
type ComponentDefinitionBody struct {
	UUID       string             `json:"uuid"`
	Metadata   RolesMetadata      `json:"metadata"`
	Components []DefinedComponent `json:"components"`
}

// RolesMetadata is Metadata with the roles responsible-roles refer to.
type RolesMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
	Roles        []Role `json:"roles,omitempty"`
	Remarks      string `json:"remarks,omitempty"`
}

// Role is a role a party plays.
type Role struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// DefinedComponent is one piece of software.
type DefinedComponent struct {
	UUID                   string                  `json:"uuid"`
	Type                   string                  `json:"type"`
	Title                  string                  `json:"title"`
	Description            string                  `json:"description"`
	Purpose                string                  `json:"purpose,omitempty"`
	Props                  []Prop                  `json:"props,omitempty"`
	ControlImplementations []ControlImplementation `json:"control-implementations,omitempty"`
}

// ControlImplementation is the controls implemented against one source.
type ControlImplementation struct {
	UUID                    string                   `json:"uuid"`
	Source                  string                   `json:"source"`
	Description             string                   `json:"description"`
	SetParameters           []SetParameter           `json:"set-parameters,omitempty"`
	ImplementedRequirements []ImplementedRequirement `json:"implemented-requirements"`
}

// ImplementedRequirement is one control.
type ImplementedRequirement struct {
	UUID             string            `json:"uuid"`
	ControlID        string            `json:"control-id"`
	Description      string            `json:"description"`
	Props            []Prop            `json:"props,omitempty"`
	ResponsibleRoles []ResponsibleRole `json:"responsible-roles,omitempty"`
	Remarks          string            `json:"remarks,omitempty"`
}

// ResponsibleRole names a role responsible for a requirement.
type ResponsibleRole struct {
	RoleID string `json:"role-id"`
}

// NewComponentDefinition wraps components in a document.
func NewComponentDefinition(title, version string, at time.Time, roles []Role, components []DefinedComponent) (ComponentDefinition, error) {
	id, err := newUUID()
	if err != nil {
		return ComponentDefinition{}, err
	}
	return ComponentDefinition{ComponentDefinition: ComponentDefinitionBody{
		UUID: id,
		Metadata: RolesMetadata{Title: title, LastModified: at.UTC().Format(time.RFC3339),
			Version: nonEmpty(version, "1"), OSCALVersion: Version, Roles: roles},
		Components: components,
	}}, nil
}

// NewUUID is a version-4 UUID, for callers building documents.
func NewUUID() (string, error) { return newUUID() }

// ForImplementation is set-parameters as an implementation may carry them:
// a component definition's and a system security plan's allow an id,
// values and remarks, and no properties, so what the properties said is
// written into the remarks.
func ForImplementation(in []SetParameter) []SetParameter {
	out := make([]SetParameter, 0, len(in))
	for _, p := range in {
		var said []string
		for _, pr := range p.Props {
			said = append(said, pr.Name+": "+pr.Value)
		}
		remarks := p.Remarks
		if len(said) > 0 {
			remarks = strings.TrimSpace(remarks + " (" + strings.Join(said, "; ") + ")")
		}
		out = append(out, SetParameter{ParamID: p.ParamID, Values: p.Values, Remarks: remarks})
	}
	return out
}
