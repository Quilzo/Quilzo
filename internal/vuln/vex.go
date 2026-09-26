// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Saying a vulnerability does not apply, in a way somebody can check.
//
// Presence is not exposure. A vulnerable library in an image that never loads
// it, a CVE in a code path this build does not compile, a flaw reachable only
// by an administrator who could do worse directly: all of them are real
// vulnerabilities and none of them is work. A queue that cannot express that
// is a queue where the only way to make something go away is to close it with
// no reason, and six months later nobody can tell that from a fix.
//
// The VEX statuses and the five justifications for not_affected are OpenVEX's
// and are used unchanged, because an assessment written here should be
// readable by whatever the next tool is. The one thing added is a deadline on
// under_investigation.
//
// # An investigation that never ends is an unassessed vulnerability
//
// under_investigation is the status every backlog fills with. It reads as
// work in progress and behaves as closed: it leaves the queue, nothing
// chases it, and the vulnerability is exactly as present as it was. So it
// expires here, and a lapsed investigation returns to the queue at the weight
// it had — which is the same rule internal/finding applies to an accepted
// risk, for the same reason.

// Status is a VEX status.
type Status string

const (
	// Affected is the product is affected and something has to be done.
	Affected Status = "affected"
	// NotAffected is it is present and does not apply. Needs a reason from
	// the enumerated list.
	NotAffected Status = "not_affected"
	// Fixed is it was affected and no longer is.
	Fixed Status = "fixed"
	// UnderInvestigation is nobody knows yet. Expires.
	UnderInvestigation Status = "under_investigation"
)

// Statuses lists them.
func Statuses() []Status {
	return []Status{Affected, NotAffected, Fixed, UnderInvestigation}
}

func (s Status) known() bool {
	for _, x := range Statuses() {
		if x == s {
			return true
		}
	}
	return false
}

// Justification is why a product is not affected.
//
// OpenVEX's five, unchanged. A free-text reason would be a field nobody can
// aggregate, compare between products, or check — and the point of a closed
// list is that "we looked and it is fine" is not one of the options.
type Justification string

const (
	// ComponentNotPresent is the component is not in the product at all.
	ComponentNotPresent Justification = "component_not_present"
	// VulnerableCodeNotPresent is the component is there and the vulnerable
	// part of it is not.
	VulnerableCodeNotPresent Justification = "vulnerable_code_not_present"
	// VulnerableCodeNotInExecutePath is the vulnerable code is present and
	// never reached, given this product's architecture and configuration.
	VulnerableCodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"
	// VulnerableCodeCannotBeControlledByAdversary is it is reachable and no
	// attacker can influence the inputs that would trigger it.
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	// InlineMitigationsAlreadyExist is something already in place stops it.
	InlineMitigationsAlreadyExist Justification = "inline_mitigations_already_exist"
)

// Justifications lists them.
func Justifications() []Justification {
	return []Justification{ComponentNotPresent, VulnerableCodeNotPresent,
		VulnerableCodeNotInExecutePath,
		VulnerableCodeCannotBeControlledByAdversary,
		InlineMitigationsAlreadyExist}
}

func (j Justification) known() bool {
	for _, x := range Justifications() {
		if x == j {
			return true
		}
	}
	return false
}

// MaxInvestigation is how long a vulnerability may sit under investigation.
//
// Fourteen days. Long enough to read the code and ask the vendor, short
// enough that the answer arrives while anybody still remembers the question.
const MaxInvestigation = 14 * 24 * time.Hour

// Assessment is this organisation's statement about one vulnerability in one
// place.
type Assessment struct {
	Advisory string `json:"advisory"`
	// Component is the package key, and Where the asset. Empty Where means
	// the statement is about every installation of that package, which is
	// the usual case for "the vulnerable code is not in our execute path".
	Component string `json:"component"`
	Where     string `json:"where,omitempty"`

	Status        Status        `json:"status"`
	Justification Justification `json:"justification,omitempty"`
	// Impact is the free-text detail OpenVEX allows alongside the
	// justification. It never replaces one.
	Impact string `json:"impact,omitempty"`

	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
	// Until is when an investigation lapses.
	Until time.Time `json:"until,omitempty"`
	// Because is the evidence, in one line.
	Because string `json:"because"`
}

// Validate refuses an assessment that would take something out of the queue
// without saying anything.
func (a Assessment) Validate() error {
	if strings.TrimSpace(a.Advisory) == "" {
		return fmt.Errorf("an assessment needs a vulnerability")
	}
	if strings.TrimSpace(a.Component) == "" {
		return fmt.Errorf("%s: an assessment needs a component", a.Advisory)
	}
	if !a.Status.known() {
		return fmt.Errorf("%s is not a VEX status", a.Status)
	}
	if a.At.IsZero() {
		return fmt.Errorf("%s has no time", a.Advisory)
	}
	if strings.TrimSpace(a.By) == "" {
		return fmt.Errorf(
			"%s names nobody. Deciding a vulnerability does not apply is a "+
				"judgement, and one with nobody's name on it cannot be "+
				"questioned afterwards", a.Advisory)
	}
	if a.Kind == audit.KindAI {
		// The same rule internal/finding applies to closing findings and
		// internal/workforce to merging people. A model that can mark
		// things not_affected can mark the one that mattered.
		return fmt.Errorf(
			"%s was assessed by a model. Deciding that vulnerable code is "+
				"unreachable is a claim about a whole system that a model "+
				"cannot see; it may propose, and a person signs it",
			a.Advisory)
	}
	if strings.TrimSpace(a.Because) == "" {
		return fmt.Errorf(
			"%s records no evidence. Six months from now the question is "+
				"not whether this was reachable, it is what anybody checked",
			a.Advisory)
	}
	switch a.Status {
	case NotAffected:
		if !a.Justification.known() {
			return fmt.Errorf(
				"%s is not_affected with no justification from the "+
					"enumerated list. OpenVEX requires one, and the reason "+
					"the list is closed is that \"we looked and it is fine\" "+
					"is not on it", a.Advisory)
		}
	case UnderInvestigation:
		if a.Until.IsZero() {
			return fmt.Errorf(
				"%s is under investigation for ever. That status reads as "+
					"work in progress and behaves as closed: it leaves the "+
					"queue, nothing chases it, and the vulnerability is as "+
					"present as it was. Give it a date", a.Advisory)
		}
		if !a.Until.After(a.At) {
			return fmt.Errorf("%s is under investigation until a moment "+
				"that has already passed", a.Advisory)
		}
		if a.Until.Sub(a.At) > MaxInvestigation {
			return fmt.Errorf(
				"%s is under investigation for %s. The ceiling is %s: long "+
					"enough to read the code and ask the vendor, short "+
					"enough that the answer arrives while anybody still "+
					"remembers the question", a.Advisory,
				a.Until.Sub(a.At).Round(24*time.Hour), MaxInvestigation)
		}
	default:
		if a.Justification != "" {
			return fmt.Errorf(
				"%s is %s and carries a justification, which only "+
					"not_affected takes", a.Advisory, a.Status)
		}
	}
	return nil
}

// Lapsed reports whether an investigation has run out.
func (a Assessment) Lapsed(now time.Time) bool {
	return a.Status == UnderInvestigation && !a.Until.IsZero() &&
		now.After(a.Until)
}

// Silences reports whether this assessment takes a vulnerability out of the
// queue at a given moment.
func (a Assessment) Silences(now time.Time) bool {
	switch a.Status {
	case NotAffected, Fixed:
		return true
	case UnderInvestigation:
		return !a.Lapsed(now)
	default:
		return false
	}
}

// Record turns an assessment into an audit entry.
func (a Assessment) Record() audit.Record {
	detail := map[string]string{
		"advisory": a.Advisory, "component": a.Component,
		"status": string(a.Status), "because": a.Because,
	}
	if a.Where != "" {
		detail["where"] = a.Where
	}
	if a.Justification != "" {
		detail["justification"] = string(a.Justification)
	}
	if !a.Until.IsZero() {
		detail["until"] = a.Until.UTC().Format(time.RFC3339)
	}
	outcome := audit.Success
	if a.Status == NotAffected {
		// Recorded as a denial of the work, for the reason an accepted risk
		// is: somebody decided not to fix something, and a log where that
		// reads the same as fixing it cannot be searched for the
		// interesting cases.
		outcome = audit.Denied
	}
	return audit.Record{
		Action: "vuln." + string(a.Status), Resource: "/vuln/" + a.Advisory,
		Outcome: outcome, Principal: a.By, Kind: a.Kind,
		Verified: a.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Key identifies the thing an assessment is about.
func (a Assessment) Key() string {
	if a.Where == "" {
		return a.Advisory + "\x00" + a.Component
	}
	return a.Advisory + "\x00" + a.Component + "\x00" + a.Where
}
