// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oscal

// A system security plan: one deployment, the baseline it is held to, what
// it is and where its boundary runs, and how each control is implemented
// and by which component.

// BaselineHref is NIST's SP 800-53 Rev 5 baseline profile for an impact
// level: low, moderate or high.
func BaselineHref(impact string) string {
	return "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_" +
		map[string]string{"low": "LOW", "moderate": "MODERATE", "high": "HIGH"}[impact] + "-baseline_profile.json"
}

// SSP is the root of the document.
type SSP struct {
	SystemSecurityPlan SSPBody `json:"system-security-plan"`
}

// SSPBody is the system-security-plan object.
type SSPBody struct {
	UUID                  string                `json:"uuid"`
	Metadata              PartyMetadata         `json:"metadata"`
	ImportProfile         ImportProfile         `json:"import-profile"`
	SystemCharacteristics SystemCharacteristics `json:"system-characteristics"`
	SystemImplementation  SystemImplementation  `json:"system-implementation"`
	ControlImplementation SSPControls           `json:"control-implementation"`
}

// PartyMetadata is Metadata with roles and parties.
type PartyMetadata struct {
	Title        string  `json:"title"`
	LastModified string  `json:"last-modified"`
	Version      string  `json:"version"`
	OSCALVersion string  `json:"oscal-version"`
	Roles        []Role  `json:"roles,omitempty"`
	Parties      []Party `json:"parties,omitempty"`
	Remarks      string  `json:"remarks,omitempty"`
}

// ImportProfile names the baseline.
type ImportProfile struct {
	Href    string `json:"href"`
	Remarks string `json:"remarks,omitempty"`
}

// SystemCharacteristics is what the system is.
type SystemCharacteristics struct {
	SystemIDs                []SystemID            `json:"system-ids"`
	SystemName               string                `json:"system-name"`
	Description              string                `json:"description"`
	SecuritySensitivityLevel string                `json:"security-sensitivity-level,omitempty"`
	SystemInformation        SystemInformation     `json:"system-information"`
	SecurityImpactLevel      *SecurityImpactLevel  `json:"security-impact-level,omitempty"`
	Status                   State                 `json:"status"`
	AuthorizationBoundary    AuthorizationBoundary `json:"authorization-boundary"`
	Remarks                  string                `json:"remarks,omitempty"`
}

// SystemID identifies the system.
type SystemID struct {
	IdentifierType string `json:"identifier-type,omitempty"`
	ID             string `json:"id"`
}

// SystemInformation is the information the system handles.
type SystemInformation struct {
	InformationTypes []InformationType `json:"information-types"`
}

// InformationType is one kind of information.
type InformationType struct {
	UUID                  string  `json:"uuid,omitempty"`
	Title                 string  `json:"title"`
	Description           string  `json:"description"`
	ConfidentialityImpact *Impact `json:"confidentiality-impact,omitempty"`
	IntegrityImpact       *Impact `json:"integrity-impact,omitempty"`
	AvailabilityImpact    *Impact `json:"availability-impact,omitempty"`
}

// Impact is a FIPS 199 level.
type Impact struct {
	Base string `json:"base"`
}

// SecurityImpactLevel is the system's overall levels.
type SecurityImpactLevel struct {
	Confidentiality string `json:"security-objective-confidentiality"`
	Integrity       string `json:"security-objective-integrity"`
	Availability    string `json:"security-objective-availability"`
}

// State is a status.
type State struct {
	State   string `json:"state"`
	Remarks string `json:"remarks,omitempty"`
}

// AuthorizationBoundary describes what is inside.
type AuthorizationBoundary struct {
	Description string `json:"description"`
}

// SystemImplementation is the system's users and components.
type SystemImplementation struct {
	Users      []SystemUser      `json:"users,omitempty"`
	Components []SystemComponent `json:"components"`
	Remarks    string            `json:"remarks,omitempty"`
}

// SystemUser is a kind of user.
type SystemUser struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	RoleIDs     []string `json:"role-ids,omitempty"`
}

// SystemComponent is a component of this system.
type SystemComponent struct {
	UUID        string `json:"uuid"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Props       []Prop `json:"props,omitempty"`
	Status      State  `json:"status"`
}

// SSPControls is the control implementation.
type SSPControls struct {
	Description             string              `json:"description"`
	SetParameters           []SetParameter      `json:"set-parameters,omitempty"`
	ImplementedRequirements []SSPImplementation `json:"implemented-requirements"`
}

// SSPImplementation is one control in the plan.
type SSPImplementation struct {
	UUID         string        `json:"uuid"`
	ControlID    string        `json:"control-id"`
	Props        []Prop        `json:"props,omitempty"`
	ByComponents []ByComponent `json:"by-components,omitempty"`
}

// ByComponent is one component's part in a control.
type ByComponent struct {
	ComponentUUID        string            `json:"component-uuid"`
	UUID                 string            `json:"uuid"`
	Description          string            `json:"description"`
	ImplementationStatus *State            `json:"implementation-status,omitempty"`
	ResponsibleRoles     []ResponsibleRole `json:"responsible-roles,omitempty"`
	Remarks              string            `json:"remarks,omitempty"`
}
