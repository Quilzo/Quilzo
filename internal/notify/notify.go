// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package notify tells customers and subscribers that something happened.
//
// An incident, a breach, a product change, a deprecation. The mechanism is
// ordinary — a list of contacts and a message — and everything difficult
// about it is legal, so the law is in the type system rather than in a
// runbook somebody reads once.
//
// # The mistake this package exists to make impossible
//
// A product with a notification feature almost always grows one switch:
// "unsubscribe from all emails". Somebody uses it. Six months later their
// personal data is in a breach, the notification job reads the same
// preference table every other message reads, and they are not told.
//
// That is a UX affordance breaking Article 34. A breach notification to the
// people whose data leaked is a legal obligation under Article 6(1)(c). It is
// not marketing, it has no lawful opt-out, and a system where one preference
// governs both has built the failure in.
//
// So the lawful basis is a property of the kind of notice, fixed in code and
// not configurable, and only the kinds resting on consent or legitimate
// interest can be objected to. Kind.Objectable() is the whole answer, and it
// is one line that cannot be edited in a settings screen.
//
// # The clock that is usually wrong
//
// Article 33(1) gives 72 hours to notify the supervisory authority, counted
// from becoming aware of the breach — not from the breach. Occurred and Aware
// are separate fields for the same reason the spool keeps two clocks: they
// are different facts, one of them is often unknown for weeks, and deriving a
// deadline from the wrong one is how an organisation reports late while
// believing it reported early.
//
// Article 34, notifying the people affected, has no 72-hour deadline. It says
// "without undue delay" and it means it: for a breach where the risk is
// immediate, 72 hours may itself be undue. Products routinely show one
// countdown labelled 72 hours and apply it to both, which tells a team they
// have three days to tell the people at risk. SubjectDue returns no deadline
// and says why, because a number invented here would be worse than none.
//
// # What a breach notice must contain
//
// Article 34(2) lists four things, and Validate refuses a breach notice
// missing any of them: the nature of the breach, the name and contact details
// of the data protection officer or other contact point, the likely
// consequences, and the measures taken or proposed. These are not house
// style. A notice without them does not discharge the obligation, and the
// moment nobody has time to check is the moment it is being written.
package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// AuthorityDeadline is Article 33(1): 72 hours from awareness.
//
// The only fixed number in data protection law that this package knows, and
// it applies to the supervisory authority and to nothing else.
const AuthorityDeadline = 72 * time.Hour

// Kind is what happened. It decides the lawful basis and the opt-out.
type Kind string

const (
	// Breach is a personal data breach: Articles 33 and 34.
	Breach Kind = "breach"
	// Incident is a service problem that is not a personal data breach.
	// Kept separate because calling everything an incident is how a breach
	// gets handled on the wrong clock, and calling everything a breach is how
	// an organisation reports twenty of them a year to a regulator.
	Incident Kind = "incident"
	// Maintenance is planned work.
	Maintenance Kind = "maintenance"
	// Change is something about the product being different.
	Change Kind = "change"
	// Deprecation is something going away, which a customer has to act on.
	Deprecation Kind = "deprecation"
	// Marketing is anything sent because somebody might buy something.
	Marketing Kind = "marketing"
)

// Kinds lists them.
func Kinds() []Kind {
	return []Kind{Breach, Incident, Maintenance, Change, Deprecation, Marketing}
}

func (k Kind) known() bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// Basis is the Article 6(1) lawful basis for processing a contact's data in
// order to send them this.
type Basis string

const (
	// LegalObligation is Article 6(1)(c). Article 34 makes telling affected
	// people about a breach an obligation, and an obligation has no opt-out.
	LegalObligation Basis = "legal-obligation"
	// Contract is Article 6(1)(b): messages a customer needs in order to use
	// what they are paying for. A service incident and a deprecation are
	// both this. A customer can stop being a customer; they cannot be a
	// customer and decline to be told the service is down.
	Contract Basis = "contract"
	// LegitimateInterest is Article 6(1)(f), and comes with an absolute right
	// to object under Article 21(1).
	LegitimateInterest Basis = "legitimate-interest"
	// Consent is Article 6(1)(a): freely given, and withdrawable at any time
	// as easily as it was given.
	Consent Basis = "consent"
)

// Basis is the lawful basis for a kind of notice.
//
// A function and not a configuration field. Every deployment that could set
// this would eventually set breach notification to something withdrawable,
// because the person changing the setting is thinking about complaints rather
// than about Article 34.
func (k Kind) Basis() Basis {
	switch k {
	case Breach:
		return LegalObligation
	case Incident, Maintenance, Deprecation:
		return Contract
	case Change:
		return LegitimateInterest
	default:
		return Consent
	}
}

// Objectable reports whether a contact can decline this kind of notice.
//
// The one line that keeps a preference screen from breaking Article 34.
func (k Kind) Objectable() bool {
	switch k.Basis() {
	case LegalObligation, Contract:
		return false
	default:
		return true
	}
}

// NeedsConsent reports whether this kind may only be sent to somebody who
// opted in. Article 6(1)(a), and for electronic marketing also PECR.
func (k Kind) NeedsConsent() bool { return k.Basis() == Consent }

// Urgent reports whether a kind is one where delay is itself a harm.
func (k Kind) Urgent() bool { return k == Breach || k == Incident }

// Notice is one thing to tell people.
type Notice struct {
	ID      string `json:"id"`
	Kind    Kind   `json:"kind"`
	Subject string `json:"subject"`
	Body    string `json:"body"`

	// Occurred is when the thing happened, as best anybody knows.
	Occurred time.Time `json:"occurred"`
	// Aware is when this organisation became aware of it.
	//
	// The one that starts the Article 33 clock, and routinely weeks after
	// Occurred. Kept apart so a late discovery does not silently produce a
	// deadline that passed before anybody knew there was one.
	Aware time.Time `json:"aware"`

	// The four things Article 34(2) requires of a breach notice.
	Nature       string `json:"nature,omitempty"`
	Contact      string `json:"contact,omitempty"`
	Consequences string `json:"consequences,omitempty"`
	Measures     string `json:"measures,omitempty"`

	// Affected names who this is about. Empty means everybody on the list
	// for this kind, which is right for a product change and wrong for a
	// breach — see Validate.
	Affected []telemetry.ID `json:"affected,omitempty"`

	// Mitigated records an Article 34(3)(a) or (b) exemption: the data was
	// unintelligible to whoever got it, or subsequent measures removed the
	// high risk. Written out in full because a regulator will ask, and
	// because writing it out is the moment somebody notices it is not true.
	Mitigated string `json:"mitigated,omitempty"`
	// Public records an Article 34(3)(c) public communication, used when
	// individual notification would involve disproportionate effort.
	Public string `json:"public,omitempty"`

	// Author is the person who wrote it. Notices are not sent by models; see
	// Validate.
	Author string     `json:"author"`
	Kinded audit.Kind `json:"kinded,omitempty"`
}

// Ident derives a stable id from a notice's content.
func Ident(kind Kind, subject string, aware time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		string(kind), strings.ToLower(strings.TrimSpace(subject)),
		aware.UTC().Format(time.RFC3339),
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// Validate refuses a notice that would not do its job or would not be lawful.
func (n Notice) Validate() error {
	if strings.TrimSpace(n.ID) == "" {
		return fmt.Errorf("a notice needs an id")
	}
	if !n.Kind.known() {
		return fmt.Errorf("%s is not a kind of notice", n.Kind)
	}
	if strings.TrimSpace(n.Subject) == "" {
		return fmt.Errorf("%s has no subject", n.ID)
	}
	if strings.TrimSpace(n.Body) == "" {
		return fmt.Errorf("%s has no body", n.ID)
	}
	if strings.TrimSpace(n.Author) == "" {
		return fmt.Errorf(
			"%s names no author. Somebody is accountable for what an "+
				"organisation tells its customers", n.ID)
	}
	if n.Kinded == audit.KindAI {
		// The same rule internal/finding applies to closing findings, for a
		// heavier reason. A notice is the organisation speaking: it goes to
		// a regulator's file, it is read as an admission, and a model that
		// can send one can settle the facts of an incident before anybody
		// has established them.
		return fmt.Errorf(
			"%s was composed by a model. A notice is the organisation "+
				"speaking to its customers and to a regulator; a model may "+
				"draft one and a person sends it", n.ID)
	}
	if n.Occurred.IsZero() {
		return fmt.Errorf("%s does not say when it happened", n.ID)
	}
	if n.Aware.IsZero() {
		return fmt.Errorf(
			"%s does not say when this organisation became aware. That is "+
				"the moment Article 33's 72 hours starts, and it is not the "+
				"moment it happened", n.ID)
	}
	if n.Aware.Before(n.Occurred) {
		return fmt.Errorf(
			"%s says it was known about %s before it happened", n.ID,
			n.Occurred.Sub(n.Aware))
	}
	if n.Kind != Breach {
		if n.Mitigated != "" || n.Public != "" {
			return fmt.Errorf(
				"%s is a %s and claims an Article 34(3) exemption, which "+
					"exists only for a personal data breach", n.ID, n.Kind)
		}
		return nil
	}
	return n.validateBreach()
}

// validateBreach checks Article 34(2) and the exemptions in 34(3).
func (n Notice) validateBreach() error {
	for _, f := range []struct{ name, value, article string }{
		{"the nature of the breach", n.Nature, "34(2)(a) with 33(3)(a)"},
		{"a contact point", n.Contact, "34(2)(b)"},
		{"the likely consequences", n.Consequences, "34(2)(c)"},
		{"the measures taken or proposed", n.Measures, "34(2)(d)"},
	} {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf(
				"%s does not describe %s, which Article %s requires. A "+
					"notice missing it does not discharge the obligation, "+
					"however sincerely it is worded", n.ID, f.name, f.article)
		}
	}
	if len(n.Affected) == 0 && n.Public == "" {
		// Broadcasting a breach notice to everybody on the list tells people
		// who were not affected that they were, and tells the ones who were
		// nothing specific. Article 34(1) is about "the data subject", and
		// the only lawful way to send one message to everybody is 34(3)(c).
		return fmt.Errorf(
			"%s names nobody affected. A breach notice to the whole list "+
				"alarms people whose data is fine and tells the people "+
				"whose data is not nothing they can act on. Either name who "+
				"is affected, or record the Article 34(3)(c) reason a "+
				"public communication is being used instead", n.ID)
	}
	return nil
}

// AuthorityDue is when Article 33(1) requires the supervisory authority to
// have been told.
func (n Notice) AuthorityDue() time.Time {
	if n.Kind != Breach || n.Aware.IsZero() {
		return time.Time{}
	}
	return n.Aware.Add(AuthorityDeadline)
}

// Overdue reports whether the Article 33 deadline has passed.
func (n Notice) Overdue(now time.Time) bool {
	due := n.AuthorityDue()
	return !due.IsZero() && now.After(due)
}

// SubjectDue is when the people affected must have been told. There is no
// such moment, and saying so is the point.
//
// Article 34(1) says "without undue delay" and sets no number. The 72 hours
// everybody quotes is Article 33 and is about the regulator. A product that
// shows one countdown for both has told its incident team they have three
// days to warn people whose data is at risk, which for a breach exposing
// credentials is plainly undue.
//
// So this returns nothing, and Undue returns how long it has actually been —
// which is the number a person should be looking at.
func (n Notice) SubjectDue() (time.Time, string) {
	return time.Time{}, "Article 34 says \"without undue delay\" and sets no " +
		"deadline. The 72 hours is Article 33 and is the regulator's. " +
		"Whether this is undue depends on the risk to the people affected " +
		"and is a judgement somebody has to make now, not in three days"
}

// Undue is how long it has been since this organisation became aware.
func (n Notice) Undue(now time.Time) time.Duration { return now.Sub(n.Aware) }

// Record is the Article 33(5) documentation of the notice itself.
//
// "The controller shall document any personal data breaches, comprising the
// facts relating to the personal data breach, its effects and the remedial
// action taken." That documentation has to let a supervisory authority verify
// compliance, which means it has to be something other than a row somebody
// could edit afterwards. It goes in the hash-chained, twice-signed log.
//
// No addresses and no names of the people affected: the record of a breach is
// not itself a place to accumulate personal data. Counts and pseudonyms only.
func (n Notice) Record(recipients, withheld int) audit.Record {
	detail := map[string]string{
		"notice":     n.ID,
		"notice_of":  string(n.Kind),
		"basis":      string(n.Kind.Basis()),
		"occurred":   n.Occurred.UTC().Format(time.RFC3339),
		"aware":      n.Aware.UTC().Format(time.RFC3339),
		"recipients": fmt.Sprint(recipients),
		"withheld":   fmt.Sprint(withheld),
	}
	if n.Kind == Breach {
		detail["authority_due"] = n.AuthorityDue().UTC().Format(time.RFC3339)
		detail["nature"] = n.Nature
		detail["consequences"] = n.Consequences
		detail["measures"] = n.Measures
		if n.Mitigated != "" {
			detail["mitigated"] = n.Mitigated
		}
		if n.Public != "" {
			detail["public"] = n.Public
		}
	}
	return audit.Record{
		Action: "notice." + string(n.Kind), Resource: "/notice/" + n.ID,
		Outcome: audit.Success, Principal: n.Author, Kind: n.Kinded,
		Verified: n.Kinded != audit.KindUnknown, Detail: detail,
	}
}
