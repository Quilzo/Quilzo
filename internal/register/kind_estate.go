// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import "fmt"

// The kinds that hold what the organisation depends on and answers for:
// its vendors, the services that must keep running, the AI systems it uses,
// its incidents, and its policies with who has read them.

// Criticality is how much the organisation depends on something.
type Criticality string

// Values lists the criticalities, most critical first.
func (Criticality) Values() []string { return []string{"critical", "important", "standard"} }

// Service is something the organisation does that must keep working: a
// critical or important function, in the words of DORA and NIS2.
type Service struct {
	Name        string      `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title       string      `json:"title" reg:"required,label" about:"what people call it"`
	Owner       ID          `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
	Criticality Criticality `json:"criticality" reg:"required" about:"how much the organisation depends on it"`
}

const KindService Kind = "Service"

func (Service) Kind() Kind              { return KindService }
func (s Service) Key() (string, string) { return Local, s.Name }
func (Service) Check() error            { return nil }
func (s Service) index(r *Row)          { r.About, r.State = s.Owner.bytes(), ordinal(s.Criticality) }

var _ = define[Service]("Something the organisation does that must keep working.", ClassInternal)

// VendorStatus is where a vendor stands.
type VendorStatus string

// Values lists the statuses of a vendor.
func (VendorStatus) Values() []string { return []string{"proposed", "approved", "retired"} }

// Vendor is an outside party the organisation depends on. Approving one is
// a decision, and the record then carries the approval.
type Vendor struct {
	Name     string       `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title    string       `json:"title" reg:"required,label" about:"the vendor's name"`
	Owner    ID           `json:"owner" reg:"required,ref=Subject" about:"who answers for the relationship"`
	Tier     Criticality  `json:"tier" reg:"required" about:"how much the organisation depends on it"`
	Status   VendorStatus `json:"status" reg:"required" about:"where it stands"`
	Services []ID         `json:"services,omitempty" reg:"ref=Service" about:"the services that depend on it"`
	Reviewed Time         `json:"reviewed,omitempty" about:"when it was last assessed"`
	Approval *Approval    `json:"approval,omitempty" about:"the approval that accepted it"`
}

const KindVendor Kind = "Vendor"

func (Vendor) Kind() Kind              { return KindVendor }
func (v Vendor) Key() (string, string) { return Local, v.Name }
func (v Vendor) Check() error {
	if v.Status == "approved" && v.Approval == nil {
		return fmt.Errorf("an approved vendor carries the approval that accepted it")
	}
	return nil
}
func (v Vendor) index(r *Row) {
	r.About, r.At, r.State, r.Grade = v.Owner.bytes(), int64(v.Reviewed), ordinal(v.Status), ordinal(v.Tier)
}

var _ = define[Vendor]("An outside party the organisation depends on.", ClassConfidential)

// AIRole is the organisation's role for an AI system under the EU AI Act.
type AIRole string

// Values lists the roles.
func (AIRole) Values() []string {
	return []string{"provider", "deployer", "importer", "distributor"}
}

// AIRisk is the category of duties an AI system falls under. It is worked
// out by code from typed intake answers; a use that may be prohibited is
// flagged for a person, never decided here.
type AIRisk string

// Values lists the categories.
func (AIRisk) Values() []string {
	return []string{"prohibited-flagged", "high-risk", "transparency", "other"}
}

// AIStatus is where an AI system stands.
type AIStatus string

// Values lists the statuses of an AI system.
func (AIStatus) Values() []string { return []string{"proposed", "live", "suspended", "retired"} }

// Enforcement says how far the decision about an AI system is enforced
// where its traffic is: by a gateway that fetches the allow-list, only
// recorded here, or not at all.
type Enforcement string

// Values lists the three states.
func (Enforcement) Values() []string { return []string{"enforced", "recorded", "none"} }

// AISystem is an AI system or agent the organisation uses: one it built, a
// vendor's, or an agent declared in Quilzo itself. It does not go live
// without a person's approval, and the approval has an end.
type AISystem struct {
	Name        string      `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title       string      `json:"title" reg:"required,label" about:"what people call it"`
	Owner       ID          `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
	Vendor      ID          `json:"vendor,omitempty" reg:"ref=Vendor" about:"the vendor that supplies it"`
	Purpose     Text        `json:"purpose,omitempty" about:"what it is used for, held as a digest"`
	Role        AIRole      `json:"role" reg:"required" about:"the organisation's role for it under the EU AI Act"`
	Risk        AIRisk      `json:"risk" reg:"required" about:"the category of duties it falls under, worked out by code"`
	Classes     []Class     `json:"classes,omitempty" about:"the classes of data it handles"`
	Status      AIStatus    `json:"status" reg:"required" about:"where it stands"`
	Enforcement Enforcement `json:"enforcement" reg:"required" about:"how far the decision is enforced where its traffic is"`
	AllowList   int64       `json:"allow_list,omitempty" reg:"min=0" about:"the version of the allow-list it was last published in"`
	Expires     Time        `json:"expires,omitempty" about:"when its approval ends"`
	Approval    *Approval   `json:"approval,omitempty" about:"the approval to go live"`
}

const KindAISystem Kind = "AISystem"

func (AISystem) Kind() Kind              { return KindAISystem }
func (a AISystem) Key() (string, string) { return Local, a.Name }
func (a AISystem) Check() error {
	if a.Status == "live" {
		if a.Approval == nil {
			return fmt.Errorf("an AI system does not go live without an approval")
		}
		if a.Expires == 0 {
			return fmt.Errorf("an approval to go live has an end; say when it expires")
		}
	}
	return nil
}
func (a AISystem) index(r *Row) {
	r.About, r.Via, r.At, r.State, r.Grade = a.Owner.bytes(), a.Vendor.bytes(), int64(a.Expires), ordinal(a.Status), ordinal(a.Enforcement)
}

var _ = define[AISystem]("An AI system or agent the organisation uses, and whether it may run.", ClassInternal)

// Severity is how bad an incident is.
type Severity string

// Values lists the severities, least first.
func (Severity) Values() []string { return []string{"low", "medium", "high", "critical"} }

// IncidentStatus is where an incident stands.
type IncidentStatus string

// Values lists the statuses of an incident.
func (IncidentStatus) Values() []string { return []string{"open", "contained", "closed"} }

// Incident is something that went wrong and the moment the organisation
// knew, which is when the regulatory clocks start. Who must be told, and by
// when, is worked out from this record by code and decided by named people.
type Incident struct {
	Ref      string         `json:"ref" reg:"required,label" about:"the organisation's own reference; its natural key"`
	Title    string         `json:"title" reg:"required,label" about:"what happened, in a line"`
	Owner    ID             `json:"owner" reg:"required,ref=Subject" about:"who is running the response"`
	Severity Severity       `json:"severity" reg:"required" about:"how bad it is"`
	Status   IncidentStatus `json:"status" reg:"required" about:"where it stands"`
	Aware    Time           `json:"aware" reg:"required" about:"when the organisation became aware, which starts the clocks"`
	Summary  Text           `json:"summary,omitempty" about:"what is known, held as a digest"`
	// Privileged marks a record kept under legal privilege, which narrows
	// who may read it.
	Privileged bool `json:"privileged,omitempty" about:"it is kept under legal privilege"`
}

const KindIncident Kind = "Incident"

func (Incident) Kind() Kind              { return KindIncident }
func (i Incident) Key() (string, string) { return Local, i.Ref }
func (Incident) Check() error            { return nil }
func (i Incident) index(r *Row) {
	r.About, r.At, r.State, r.Grade = i.Owner.bytes(), int64(i.Aware), ordinal(i.Status), ordinal(i.Severity)
	if i.Privileged {
		r.Flags |= FlagPrivileged
	}
}

var _ = define[Incident]("Something that went wrong, and when the organisation knew.", ClassRestricted)

// PolicyStatus is where a policy stands.
type PolicyStatus string

// Values lists the statuses of a policy.
func (PolicyStatus) Values() []string { return []string{"draft", "approved", "retired"} }

// Policy is a rule the organisation set for itself, as a document somebody
// approved. The record holds the digest of the document as approved, so an
// acknowledgement can say exactly which words were read.
type Policy struct {
	Name      string       `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title     string       `json:"title" reg:"required,label" about:"the policy's title"`
	Owner     ID           `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
	Version   string       `json:"version" reg:"required,label" about:"the version of the document"`
	Document  Digest       `json:"document" reg:"required" about:"the digest of the document at this version"`
	Status    PolicyStatus `json:"status" reg:"required" about:"where it stands"`
	Effective Time         `json:"effective,omitempty" about:"when it takes effect"`
	Review    Time         `json:"review,omitempty" about:"when it is next due for review"`
	Approval  *Approval    `json:"approval,omitempty" about:"the approval of this version"`
}

const KindPolicy Kind = "Policy"

func (Policy) Kind() Kind              { return KindPolicy }
func (p Policy) Key() (string, string) { return Local, p.Name }
func (p Policy) Check() error {
	if p.Status == "approved" && p.Approval == nil {
		return fmt.Errorf("an approved policy carries the approval of this version")
	}
	return nil
}
func (p Policy) index(r *Row) {
	r.About, r.At, r.State = p.Owner.bytes(), int64(p.Review), ordinal(p.Status)
}

var _ = define[Policy]("A rule the organisation set for itself, as an approved document.", ClassInternal)

// Acknowledgement says a person read a policy: which person, which policy,
// and the commit of the register that held the version they were shown. A
// policy changed afterwards is a version nobody has acknowledged yet.
type Acknowledgement struct {
	Policy  ID     `json:"policy" reg:"required,ref=Policy" about:"the policy that was read"`
	Subject ID     `json:"subject" reg:"required,ref=Subject" about:"who read it"`
	Commit  string `json:"commit" reg:"required,oid" about:"the register commit that held the version they were shown"`
	At      Time   `json:"at" reg:"required" about:"when they acknowledged it"`
}

const KindAcknowledgement Kind = "Acknowledgement"

func (Acknowledgement) Kind() Kind { return KindAcknowledgement }
func (a Acknowledgement) Key() (string, string) {
	return Local, string(a.Policy) + "/" + string(a.Subject) + "/" + a.Commit
}
func (Acknowledgement) Check() error { return nil }
func (a Acknowledgement) index(r *Row) {
	r.About, r.Via, r.At = a.Policy.bytes(), a.Subject.bytes(), int64(a.At)
}

var _ = define[Acknowledgement]("That a person read a policy, at a version.", ClassRestricted, immutable)
