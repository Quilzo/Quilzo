// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package vendor is third-party risk, tiered by what a vendor can reach
// rather than by what they are paid.
//
// # Two directions, and only one of them is usually modelled
//
// A vendor this organisation holds an API token for is one thing: if their
// service lies to us we get bad data, and if our token leaks somebody reads
// their system as us. Bounded, and unpleasant.
//
// A vendor holding a token in *our* estate is a different thing entirely.
// Their compromise is our breach. Between 9 and 17 August 2025 the cluster
// tracked as UNC6395 used OAuth tokens stolen from one chat-widget vendor to
// query Salesforce in more than 700 organisations, and combed the results for
// AWS keys and passwords sitting in support-case text. Not one of those
// organisations was broken into. Their vendor was.
//
// Every third-party risk product treats these as one field called "access".
// They are separate here, they tier differently, and a vendor holding a
// standing credential in this estate is critical whatever anybody wrote on an
// inherent risk questionnaire.
//
// # The tier is derived, not declared
//
// The standard practice is an inherent risk questionnaire filled in at
// onboarding, which produces a tier that is correct on the day and drifts
// from then on: the vendor adds a scope, an engineer connects a second
// system, the contract renews for more. The published guidance is already
// that tiering should follow data and system access rather than contract
// value; the part nobody does is deriving it from what access actually
// exists.
//
// So Tier is a function of what the vendor reaches, and Reconcile compares
// the register against the connectors this deployment has configured. A
// vendor with a connector and no entry in the register is not a paperwork
// problem — it is a processor nobody has assessed, and a register that only
// knows what somebody typed into it will always be behind.
//
// # A terminated vendor with a live credential
//
// The single most useful thing this package computes. Offboarding is a
// checklist item that reliably gets half done, and nothing else in an
// organisation notices: the contract ends, the vendor's row goes grey, and
// the token keeps working.
package vendor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// MaxReview is how long a vendor may go unreviewed before it stops meaning
// anything.
//
// A year for most, and Tier itself shortens it: a vendor holding a credential
// in this estate is reviewed twice as often, because what makes it critical
// is a thing that changes without anybody telling us.
const MaxReview = 365 * 24 * time.Hour

// Reach is what a vendor can do, and in which direction.
type Reach string

const (
	// WeRead is this organisation holds a credential to their system.
	//
	// Our connector, our token. If their service lies to us we get bad
	// data; if our token leaks somebody reads their system as us.
	WeRead Reach = "we-read-them"
	// WeSend is we push data to them and hold no standing credential —
	// a file transfer, an email, a form.
	WeSend Reach = "we-send-them"
	// TheyRead is they hold a credential inside this estate.
	//
	// The Drift case. Their compromise is our breach, and the credential
	// works until somebody revokes it rather than until the contract ends.
	TheyRead Reach = "they-read-us"
	// TheyWrite is the same and they can change things.
	TheyWrite Reach = "they-write-us"
	// TheyHost is they run something this organisation depends on, with no
	// credential either way: a cloud provider, a payment processor.
	TheyHost Reach = "they-host-us"
)

// Reaches lists them.
func Reaches() []Reach {
	return []Reach{WeRead, WeSend, TheyRead, TheyWrite, TheyHost}
}

func (r Reach) known() bool {
	for _, x := range Reaches() {
		if x == r {
			return true
		}
	}
	return false
}

// Inbound reports whether the vendor holds a credential in this estate.
//
// The distinction the whole package turns on. Every product in this category
// has one field called "access"; this is the half of it where their breach is
// our breach.
func (r Reach) Inbound() bool { return r == TheyRead || r == TheyWrite }

// Describe says what a reach means for somebody reading a report.
func (r Reach) Describe() string {
	switch r {
	case WeRead:
		return "we hold a credential to their system"
	case WeSend:
		return "we send them data and hold no standing credential"
	case TheyRead:
		return "they hold a credential inside this estate and can read with it"
	case TheyWrite:
		return "they hold a credential inside this estate and can change things"
	case TheyHost:
		return "they run something we depend on"
	default:
		return string(r)
	}
}

// Access is one thing a vendor can reach.
type Access struct {
	Reach Reach `json:"reach"`
	// What is the system: "salesforce", "okta", "the staff directory".
	What string `json:"what"`
	// Scopes are what the credential permits, as the granting system names
	// them. Carried verbatim, because a scope paraphrased into English is a
	// scope nobody can compare against the one actually granted.
	Scopes []string `json:"scopes,omitempty"`
	// Since is when this access was granted.
	Since time.Time `json:"since,omitempty"`
	// Connector names the manifest this was derived from, where it was.
	Connector string `json:"connector,omitempty"`
}

// Validate refuses access nothing can be assessed from.
func (a Access) Validate() error {
	if !a.Reach.known() {
		return fmt.Errorf("%q is not a direction of access", a.Reach)
	}
	if strings.TrimSpace(a.What) == "" {
		return fmt.Errorf("%s reaches something unnamed", a.Reach)
	}
	return nil
}

// Data is a category this organisation hands over.
//
// Free-form on purpose: the categories that matter are the ones in this
// organisation's own records of processing, and a closed list here would be
// a second vocabulary that drifts from the first.
type Data string

// Sensitive is the mark an operator puts on a category that raises the tier.
const Sensitive = "sensitive"

// Subprocessor is one of the vendor's own vendors.
type Subprocessor struct {
	Name string `json:"name"`
	// For is what they do for the vendor.
	For string `json:"for,omitempty"`
	// Region matters because it is usually why anybody asked.
	Region string `json:"region,omitempty"`
}

// Status is where a vendor is in its life.
type Status string

const (
	// Considering is under assessment and not yet used.
	Considering Status = "considering"
	// Active is in use.
	Active Status = "active"
	// Exiting is the contract is ending and the access has not gone yet.
	//
	// A state of its own because it is the window in which everything goes
	// wrong: the relationship is over in everybody's mind and the credential
	// still works.
	Exiting Status = "exiting"
	// Terminated is finished, and nothing of theirs should remain.
	Terminated Status = "terminated"
)

// Statuses lists them.
func Statuses() []Status {
	return []Status{Considering, Active, Exiting, Terminated}
}

func (s Status) known() bool {
	for _, x := range Statuses() {
		if x == s {
			return true
		}
	}
	return false
}

// Tier is how much scrutiny a vendor warrants.
type Tier int

const (
	// Routine is a vendor that holds nothing and touches nothing.
	Routine Tier = 1
	// Elevated is one we read from, or one we send data to.
	Elevated Tier = 2
	// High is one handling data this organisation marked sensitive, or one
	// the business could not run without.
	High Tier = 3
	// Critical is one holding a credential inside this estate.
	//
	// Whatever anybody wrote on an inherent risk questionnaire. What makes
	// it critical is not a judgement, it is a token.
	Critical Tier = 4
)

// String names the tier.
func (t Tier) String() string {
	switch t {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Elevated:
		return "elevated"
	default:
		return "routine"
	}
}

// Vendor is a third party.
type Vendor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Purpose is what they do for us, in one line.
	Purpose string `json:"purpose"`
	Owner   string `json:"owner,omitempty"`
	Status  Status `json:"status"`

	Access []Access `json:"access,omitempty"`
	// Data are the categories handed over. A category named in Sensitive
	// raises the tier.
	Data []Data `json:"data,omitempty"`
	// Essential says the business stops without them.
	Essential bool `json:"essential,omitempty"`

	// Subprocessors are their vendors. Empty means nobody asked, which is
	// different from their having none — see Findings.
	Subprocessors []Subprocessor `json:"subprocessors,omitempty"`
	// Asked is when this organisation last asked them for that list.
	Asked time.Time `json:"asked,omitempty"`

	// Reviewed is when somebody last looked at this relationship.
	Reviewed time.Time `json:"reviewed,omitempty"`
	// Since and Until bound the contract.
	Since time.Time `json:"since,omitempty"`
	Until time.Time `json:"until,omitempty"`

	Note string `json:"note,omitempty"`
}

// Validate refuses a vendor that cannot be assessed.
func (v Vendor) Validate() error {
	if strings.TrimSpace(v.ID) == "" {
		return fmt.Errorf("a vendor needs an identifier")
	}
	if v.ID != strings.ToLower(v.ID) || strings.ContainsAny(v.ID, " /\\:") {
		return fmt.Errorf(
			"%q is not usable as a vendor identifier. Lowercase, no spaces "+
				"and no slashes: it has to match the name a connector "+
				"manifest uses, or the two registers can never be compared",
			v.ID)
	}
	if strings.TrimSpace(v.Name) == "" {
		return fmt.Errorf("%s has no name", v.ID)
	}
	if strings.TrimSpace(v.Purpose) == "" {
		return fmt.Errorf(
			"%s says nothing about what they do for us. A register whose "+
				"entries cannot be explained is one nobody can prune, and "+
				"the vendors nobody can explain are the ones still holding "+
				"credentials", v.ID)
	}
	if !v.Status.known() {
		return fmt.Errorf("%s: %q is not a status", v.ID, v.Status)
	}
	for _, a := range v.Access {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("%s: %w", v.ID, err)
		}
	}
	return nil
}

// Tier works out how much scrutiny this vendor warrants.
//
// From what they reach, not from what they cost. The published guidance is
// already that tiering should follow data and system access; the part nobody
// does is deriving it rather than asking somebody to choose it once at
// onboarding and never again.
func (v Vendor) Tier() (Tier, string) {
	for _, a := range v.Access {
		if a.Reach.Inbound() {
			return Critical, fmt.Sprintf(
				"they hold a credential in %s. Their compromise is our "+
					"breach, which is not a judgement about them — it is a "+
					"token", a.What)
		}
	}
	for _, d := range v.Data {
		if strings.Contains(strings.ToLower(string(d)), Sensitive) {
			return High, fmt.Sprintf(
				"they process %s, which this organisation marked sensitive",
				d)
		}
	}
	if v.Essential {
		return High, "the business stops without them"
	}
	for _, a := range v.Access {
		if a.Reach == WeRead {
			return Elevated, fmt.Sprintf(
				"we hold a credential to %s, so a leak of it reads their "+
					"system as us", a.What)
		}
	}
	if len(v.Data) > 0 || len(v.Access) > 0 {
		return Elevated, "data goes to them"
	}
	return Routine, "they hold nothing and we send them nothing"
}

// Inbound returns the access where the vendor holds a credential here.
func (v Vendor) Inbound() []Access {
	var out []Access
	for _, a := range v.Access {
		if a.Reach.Inbound() {
			out = append(out, a)
		}
	}
	return out
}

// Due is when this vendor should next be reviewed.
//
// Shortened for the critical ones, because what makes them critical is a
// thing that changes without anybody telling us: a scope is added, an
// integration is re-authorised with more, and the annual review is eleven
// months away.
func (v Vendor) Due() time.Time {
	if v.Reviewed.IsZero() {
		return time.Time{}
	}
	every := MaxReview
	if tier, _ := v.Tier(); tier == Critical {
		every /= 2
	}
	return v.Reviewed.Add(every)
}

// Overdue reports whether the review has lapsed.
func (v Vendor) Overdue(now time.Time) bool {
	due := v.Due()
	return due.IsZero() || now.After(due)
}

// Why explains a vendor's standing in one line.
func (v Vendor) Why(now time.Time) string {
	tier, because := v.Tier()
	switch {
	case v.Status == Terminated && len(v.Access) > 0:
		return fmt.Sprintf(
			"terminated, and still reaching %d thing(s) here. Offboarding "+
				"is the checklist item that reliably gets half done",
			len(v.Access))
	case v.Status == Exiting && len(v.Inbound()) > 0:
		return fmt.Sprintf(
			"exiting, and still holding a credential in %s. The "+
				"relationship is over in everybody's mind and the token "+
				"still works", v.Inbound()[0].What)
	case v.Reviewed.IsZero():
		return fmt.Sprintf("%s: %s. Never reviewed", tier, because)
	case v.Overdue(now):
		return fmt.Sprintf("%s: %s. Review was due %s", tier, because,
			v.Due().Format("2006-01-02"))
	default:
		return fmt.Sprintf("%s: %s. Reviewed %s", tier, because,
			v.Reviewed.Format("2006-01-02"))
	}
}

// Record turns a vendor assessment into an audit entry.
func (v Vendor) Record(by string, kind audit.Kind) audit.Record {
	tier, because := v.Tier()
	return audit.Record{
		Action: "vendor." + string(v.Status), Resource: "/vendor/" + v.ID,
		Outcome: audit.Success, Principal: by, Kind: kind,
		Verified: kind != audit.KindUnknown,
		Detail: map[string]string{
			"vendor": v.ID, "status": string(v.Status),
			"tier": tier.String(), "because": because,
			"purpose": v.Purpose,
		},
	}
}

// Register is the vendors this organisation knows about.
type Register struct {
	byID  map[string]Vendor
	order []string
}

// NewRegister starts an empty one.
func NewRegister() *Register { return &Register{byID: map[string]Vendor{}} }

// Add puts a vendor in the register.
func (r *Register) Add(v Vendor) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if _, seen := r.byID[v.ID]; !seen {
		r.order = append(r.order, v.ID)
	}
	r.byID[v.ID] = v
	return nil
}

// Get returns one vendor.
func (r *Register) Get(id string) (Vendor, bool) {
	v, ok := r.byID[id]
	return v, ok
}

// All returns every vendor, worst tier first.
func (r *Register) All() []Vendor {
	out := make([]Vendor, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, _ := out[i].Tier()
		tj, _ := out[j].Tier()
		if ti != tj {
			return ti > tj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Len is how many vendors are registered.
func (r *Register) Len() int { return len(r.byID) }
