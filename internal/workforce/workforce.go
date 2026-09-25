// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package workforce reconciles people and their devices across the systems
// that each hold a different, partial, confident answer.
//
// The identity provider knows who exists. The MDM knows which laptops check
// in. The training platform knows who clicked the phishing simulation. The
// compliance platform knows what it was told. None of them knows any of the
// others, and every interesting question is a join: who has a device that has
// not checked in for a month, who left in March and still has one that has,
// who is in the directory and in no other system at all.
//
// # The join is the hard part and products pretend it is not
//
// There is no shared key. Okta has jane.doe@acme.com, the MDM has the device
// assigned to jdoe@, the training platform has a display name, and the
// compliance platform has an internal identifier it invented. Every product
// that does this matches on email, calls it done, and reports a percentage.
//
// The failure is silent and it is always in the same direction. Somebody who
// does not match is in no result: no finding is raised about them, no control
// reports them missing, and a dashboard reading 94% is 94% of the people the
// join happened to work for. The 6% is not the remainder, it is the part
// nobody looked at — and the leaver whose account was renamed on the way out
// is in it.
//
// So an unmatched identity is the headline output here rather than a
// suppressed error, and Coverage refuses to summarise a reconciliation whose
// join did not work. The same shape as internal/baseline reporting "not
// enough observations" instead of "normal": a number nobody can stand behind
// is worse than no number.
//
// # Matching is evidence, not a guess
//
// A Link is an assertion that two identifiers are one person, and it carries
// who asserted it, when, and on what grounds. Exactly one rule proposes links
// automatically — an exact match on a normalised email address — and even
// that one states what would make it wrong. Everything else is a Proposal a
// person confirms, because merging two people's records means one person's
// device compliance is reported as another's, and a merge nobody can point
// at a reason for is one nobody can unpick afterwards.
//
// A model may propose and may not confirm, for the reason internal/finding
// gives about closing findings: a model that can merge two people can merge
// the auditor into the intern.
package workforce

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Subject is what an identity is.
type Subject string

const (
	// APerson is somebody who can be phished.
	APerson Subject = "person"
	// ADevice is something that checks in.
	ADevice Subject = "device"
	// AService is an account nobody logs into: a CI runner, an integration.
	//
	// Kept apart because every control that asks "has this person completed
	// training" produces a false finding for every service account, and the
	// usual fix is an exclusion list that also quietly excludes the
	// contractor somebody added to it once.
	AService Subject = "service"
)

// Subjects lists them.
func Subjects() []Subject { return []Subject{APerson, ADevice, AService} }

func (s Subject) known() bool {
	for _, x := range Subjects() {
		if x == s {
			return true
		}
	}
	return false
}

// Identity is one system's record of somebody or something.
type Identity struct {
	ID      telemetry.ID `json:"id"`
	Subject Subject      `json:"subject"`
	// Email and Name as that system holds them. Both mutable, both
	// unreliable, and email is the only one anything here joins on.
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	// Active is whether that system considers this current.
	//
	// A pointer, because "this system does not say" and "this system says no"
	// are different facts and collapsing them into false turns every source
	// that omits the field into a source reporting everybody as a leaver.
	Active *bool `json:"active,omitempty"`

	// Owner is the person a device belongs to, in whatever namespace the
	// device's own system used.
	Owner telemetry.ID `json:"owner,omitempty"`
	// Seen is when this thing last checked in, signed in or was touched.
	Seen time.Time `json:"seen,omitempty"`
	// Observed is when this record was read from its system.
	Observed time.Time `json:"observed"`

	// Attributes is whatever else that system said: OS version, disk
	// encryption, a training score, a policy acceptance date. Strings,
	// because comparing across JSON's number and string ambiguity is where
	// reconciliation bugs live.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Validate refuses a record nothing can be done with.
func (i Identity) Validate() error {
	if i.ID.Zero() {
		return fmt.Errorf("an identity needs an identifier")
	}
	if i.ID.Issuer == "" {
		return fmt.Errorf(
			"%q has no issuer, and the whole point here is that two systems "+
				"both say \"1043\" and mean different people", i.ID.Value)
	}
	if !i.Subject.known() {
		return fmt.Errorf("%s is not a kind of subject", i.Subject)
	}
	if i.Observed.IsZero() {
		return fmt.Errorf(
			"%s does not say when it was read. A reconciliation over records "+
				"of unknown age reports a leaver as current and a current "+
				"person as gone, depending on which export was stale", i.ID)
	}
	if i.Subject == ADevice && !i.Owner.Zero() && i.Owner.Issuer == "" {
		return fmt.Errorf(
			"%s names an owner with no issuer. That is the join this package "+
				"exists to do properly, and doing it on a bare value here "+
				"would be doing it badly in the one place it matters", i.ID)
	}
	return nil
}

// Live reports whether a system considers this identity current.
//
// Unknown counts as live. A source that does not report the field has told us
// nothing, and treating silence as "gone" would quietly stop raising findings
// about everybody in it.
func (i Identity) Live() bool { return i.Active == nil || *i.Active }

// Says reports whether the source explicitly said this is not current.
func (i Identity) Says(active bool) bool {
	return i.Active != nil && *i.Active == active
}

// Link asserts that two identifiers are the same person.
type Link struct {
	A telemetry.ID `json:"a"`
	B telemetry.ID `json:"b"`
	// At, By and Kind are who said so.
	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
	// Rule names the automatic rule that produced it, empty for a human.
	Rule string `json:"rule,omitempty"`
	// Because is the evidence, in one line.
	Because string `json:"because"`
}

// Validate refuses a link that cannot be defended.
func (l Link) Validate() error {
	if l.A.Zero() || l.B.Zero() {
		return fmt.Errorf("a link needs two identifiers")
	}
	if l.A.Issuer == "" || l.B.Issuer == "" {
		return fmt.Errorf("both sides of a link need an issuer")
	}
	if l.A == l.B {
		return fmt.Errorf("%s is already itself", l.A)
	}
	if l.A.Issuer == l.B.Issuer {
		// Two records in one system are that system's problem to merge, and
		// a reconciliation that merged them would be overruling the system
		// of record using less information than it has.
		return fmt.Errorf(
			"%s and %s are both from %s. Two accounts in one system are that "+
				"system's duplicate to resolve, and merging them here means "+
				"overruling the system of record with less information than "+
				"it has", l.A, l.B, l.A.Issuer)
	}
	if l.At.IsZero() {
		return fmt.Errorf("a link needs a time")
	}
	if strings.TrimSpace(l.By) == "" {
		return fmt.Errorf(
			"a link needs whoever asserted it. Merging two people's records " +
				"reports one person's device as another's, and a merge with " +
				"nobody's name on it is one nobody can unpick")
	}
	if l.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s to %s was asserted by a model. A model that can merge two "+
				"people can merge the auditor into the intern; it may "+
				"propose, and a person confirms", l.A, l.B)
	}
	if strings.TrimSpace(l.Because) == "" {
		return fmt.Errorf(
			"%s to %s records no reason. Six months from now the question "+
				"is not whether these are the same person, it is why "+
				"anybody thought so", l.A, l.B)
	}
	return nil
}

// Record turns a link into an audit entry.
func (l Link) Record() audit.Record {
	detail := map[string]string{
		"a": l.A.String(), "b": l.B.String(), "because": l.Because,
	}
	if l.Rule != "" {
		detail["rule"] = l.Rule
	}
	return audit.Record{
		Action: "workforce.linked", Resource: "/workforce/" + l.A.String(),
		Outcome: audit.Success, Principal: l.By, Kind: l.Kind,
		Verified: l.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Person is a set of identifiers somebody has asserted are one person.
type Person struct {
	// Key is the lowest identifier in the set, so a person has a stable name
	// that does not depend on which system was read first.
	Key        string              `json:"key"`
	Identities map[string]Identity `json:"identities"`
	Devices    []Identity          `json:"devices,omitempty"`
	Links      []Link              `json:"links,omitempty"`
}

// Issuers lists the systems this person appears in, sorted.
func (p Person) Issuers() []string {
	seen := map[string]bool{}
	for _, i := range p.Identities {
		seen[i.ID.Issuer] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// In reports whether this person appears in a system.
func (p Person) In(issuer string) bool {
	for _, i := range p.Identities {
		if i.ID.Issuer == issuer {
			return true
		}
	}
	return false
}

// Name is the best label anybody has for this person.
func (p Person) Name() string {
	var names, emails []string
	for _, i := range p.Identities {
		if strings.TrimSpace(i.Name) != "" {
			names = append(names, i.Name)
		}
		if strings.TrimSpace(i.Email) != "" {
			emails = append(emails, strings.ToLower(i.Email))
		}
	}
	sort.Strings(names)
	sort.Strings(emails)
	if len(names) > 0 {
		return names[0]
	}
	if len(emails) > 0 {
		return emails[0]
	}
	return p.Key
}

// Gone reports whether any system says this person has left.
//
// Any, not all. A leaver is usually disabled in the directory first and
// everywhere else eventually, and the window between those is the one worth
// looking at — so one system saying so is enough to ask the question.
func (p Person) Gone() (bool, []string) {
	var who []string
	for _, i := range p.Identities {
		if i.Says(false) {
			who = append(who, i.ID.Issuer)
		}
	}
	sort.Strings(who)
	return len(who) > 0, who
}
