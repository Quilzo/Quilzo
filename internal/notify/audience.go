// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Who gets told, what they agreed to, and what survives them asking to be
// forgotten.
//
// # Erasure and the suppression list
//
// Article 17 says delete it. Article 21(3) says that once somebody objects to
// direct marketing you must never process their data for that purpose again.
// Those two together are a trap that almost every list hits: the objection is
// honoured by deleting the record, the CRM syncs the same person back in
// next week, and they are mailed again — a fresh infringement, produced by
// complying with the first request.
//
// The way out is a suppression list that holds no addresses. Erase clears the
// address, the name and the consent text, and keeps a keyed fingerprint. Add
// refuses anybody whose fingerprint is on it. The list is useless to whoever
// steals it: HMAC-SHA256 under a key kept outside the file, so it cannot be
// checked against a dictionary of addresses the way a bare hash can.
//
// # What erasure costs, said out loud
//
// A contact who has been erased cannot be sent a breach notice, because there
// is nothing left to send it to. That is the correct outcome and it is also a
// real consequence: it can be the reason an organisation has to fall back on
// an Article 34(3)(c) public communication. Plan reports erased contacts as
// withheld with that reason rather than passing over them, because a breach
// where nobody noticed that a tenth of the affected list was unreachable is
// one where the regulator notices instead.

// Channel is how a contact is reached.
type Channel string

const (
	// InApp is the default and the only one that needs no address: a notice
	// waiting in the product for somebody who signs in. It cannot be
	// intercepted in transit, it cannot go to a stale mailbox, and it is
	// the only channel where "delivered" is a fact rather than a hope.
	InApp Channel = "app"
	// Email is the one a regulator expects for a breach.
	Email Channel = "email"
	// Webhook is for a customer's own systems.
	Webhook Channel = "webhook"
)

// Channels lists them.
func Channels() []Channel { return []Channel{InApp, Email, Webhook} }

func (c Channel) known() bool {
	for _, x := range Channels() {
		if x == c {
			return true
		}
	}
	return false
}

// NeedsAddress reports whether a channel requires somewhere to send to.
func (c Channel) NeedsAddress() bool { return c != InApp }

// Contact is somebody who gets told things.
type Contact struct {
	// ID is issuer-qualified, so the same person held in a CRM and in the
	// product is one contact and not two notices.
	ID      telemetry.ID `json:"id"`
	Name    string       `json:"name,omitempty"`
	Channel Channel      `json:"channel"`
	Address string       `json:"address,omitempty"`

	// Source is where this contact came from, and Since is when.
	//
	// Articles 13 and 14 require telling somebody where their data came
	// from; this is the field that makes that answerable rather than a
	// reconstruction. A contact whose provenance nobody can state is one
	// that should not be on the list.
	Source string    `json:"source"`
	Since  time.Time `json:"since"`

	// Consent records an opt-in: when, and the exact words agreed to.
	//
	// The words, not a boolean. Article 7(1) puts the burden of
	// demonstrating consent on the controller, and "the box was ticked" does
	// not demonstrate what it was ticked for.
	ConsentAt   time.Time `json:"consent_at,omitempty"`
	ConsentText string    `json:"consent_text,omitempty"`

	// Objected records an Article 21 objection. Empty ObjectedTo with a time
	// set means every kind that can be objected to.
	ObjectedAt time.Time `json:"objected_at,omitempty"`
	ObjectedTo []Kind    `json:"objected_to,omitempty"`

	// ErasedAt records an Article 17 erasure. Address, Name and ConsentText
	// are cleared; Fingerprint survives so the person stays suppressed.
	ErasedAt time.Time `json:"erased_at,omitempty"`
	// Fingerprint is a keyed hash of the address. Never the address.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Erased reports whether this contact has been forgotten.
func (c Contact) Erased() bool { return !c.ErasedAt.IsZero() }

// Objects reports whether the contact has declined a kind of notice.
//
// An objection to a kind that cannot be objected to is recorded and does not
// take effect. Recording it matters: somebody who asked not to be told about
// breaches has told you something, and a system that silently discards the
// request cannot answer for it afterwards.
func (c Contact) Objects(k Kind) bool {
	if c.ObjectedAt.IsZero() || !k.Objectable() {
		return false
	}
	if len(c.ObjectedTo) == 0 {
		return true
	}
	for _, x := range c.ObjectedTo {
		if x == k {
			return true
		}
	}
	return false
}

// MayReceive says whether a kind of notice may lawfully be sent, and why not.
func (c Contact) MayReceive(k Kind) (bool, string) {
	switch {
	case c.Erased():
		why := "erased under Article 17; there is nothing left to send to"
		if k == Breach {
			// Only for a breach. On a marketing plan this sentence would be
			// advising a public communication about a newsletter, and a
			// reason that is wrong three times out of four is one nobody
			// reads the fourth time.
			why += ", and for a breach that is a reason to consider an " +
				"Article 34(3)(c) public communication"
		}
		return false, why
	case c.Objects(k):
		return false, fmt.Sprintf(
			"objected under Article 21 on %s; %s rests on %s and is "+
				"declinable", c.ObjectedAt.Format("2006-01-02"), k,
			k.Basis())
	case k.NeedsConsent() && c.ConsentAt.IsZero():
		return false, fmt.Sprintf(
			"%s needs consent under Article 6(1)(a) and none is recorded", k)
	case c.Channel.NeedsAddress() && strings.TrimSpace(c.Address) == "":
		return false, fmt.Sprintf("no %s address", c.Channel)
	}
	return true, ""
}

// Validate refuses a contact that cannot be defended.
func (c Contact) Validate() error {
	if c.ID.Zero() {
		return fmt.Errorf("a contact needs an identifier")
	}
	if c.ID.Issuer == "" {
		// The same rule telemetry.ID enforces everywhere else. Two systems
		// both issue "1043", and a notification list that joined on the bare
		// value has sent somebody else's breach notice to the wrong person.
		return fmt.Errorf(
			"%q has no issuer. Two systems both issue the same customer "+
				"number, and a list that joins on the value alone sends one "+
				"person's breach notice to another", c.ID.Value)
	}
	if !c.Channel.known() {
		return fmt.Errorf("%s is not a channel", c.Channel)
	}
	if c.Channel.NeedsAddress() && strings.TrimSpace(c.Address) == "" &&
		!c.Erased() {
		return fmt.Errorf("%s has no %s address", c.ID, c.Channel)
	}
	if strings.TrimSpace(c.Source) == "" {
		return fmt.Errorf(
			"%s does not say where it came from. Articles 13 and 14 require "+
				"being able to tell somebody where their data was obtained, "+
				"and a contact whose provenance nobody can state is one "+
				"that should not be on the list", c.ID)
	}
	if c.Since.IsZero() {
		return fmt.Errorf("%s does not say when it was added", c.ID)
	}
	if !c.ConsentAt.IsZero() && strings.TrimSpace(c.ConsentText) == "" {
		return fmt.Errorf(
			"%s records consent with no record of what was agreed to. "+
				"Article 7(1) puts the burden of demonstrating consent on "+
				"the controller, and a timestamp demonstrates nothing", c.ID)
	}
	return nil
}

// Audience is the list, its suppressions, and the key that keeps the
// suppression list from being a list of addresses.
type Audience struct {
	key        []byte
	byID       map[string]*Contact
	order      []string
	suppressed map[string]time.Time
}

// NewKey generates a fingerprinting key.
func NewKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// NewAudience starts an empty list.
//
// The key is required. Without one the suppression list is a list of hashed
// addresses, which is a list of addresses to anybody with a dictionary — and
// a suppression list is by construction a list of people who asked to be left
// alone, which makes it the worst thing in the building to leak.
func NewAudience(key []byte) (*Audience, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf(
			"a fingerprinting key must be at least 16 bytes. Without one " +
				"the suppression list is a dictionary attack away from " +
				"being a list of the addresses of people who asked to be " +
				"left alone")
	}
	return &Audience{
		key: key, byID: map[string]*Contact{},
		suppressed: map[string]time.Time{},
	}, nil
}

// fingerprintOf is what a contact is suppressed by.
//
// The address where there is one, and the identifier where there is not. An
// in-app contact has no address, and fingerprinting only addresses meant an
// erased in-app contact left nothing behind to suppress — the re-import this
// whole mechanism exists to refuse would have gone straight through.
//
// It is still only as good as what it can recognise: somebody re-imported
// under a fresh identifier and a fresh address is a new person as far as any
// list can tell. That is a limit of the idea rather than of this code, and it
// is why the address is preferred where one exists.
func (a *Audience) fingerprintOf(c Contact) string {
	if strings.TrimSpace(c.Address) != "" {
		return a.Fingerprint(c.Address)
	}
	return a.Fingerprint(c.ID.String())
}

// Fingerprint is the keyed handle for an address.
func (a *Audience) Fingerprint(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return ""
	}
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(address))
	return "c_" + hex.EncodeToString(m.Sum(nil))[:32]
}

// Matches reports whether a fingerprint belongs to an address.
//
// How a subject access request is answered without the file holding
// addresses: somebody with the key and a claimed address can confirm it, and
// somebody with only the file can enumerate nobody.
func (a *Audience) Matches(fingerprint, address string) bool {
	return fingerprint != "" &&
		hmac.Equal([]byte(fingerprint), []byte(a.Fingerprint(address)))
}

// Add puts a contact on the list, or updates the one already there.
//
// Refuses anybody suppressed. This is the whole point of keeping the
// fingerprint through an erasure: the re-import that would otherwise turn one
// honoured objection into a fresh infringement next week.
func (a *Audience) Add(c Contact) (*Contact, error) {
	if c.Since.IsZero() {
		c.Since = time.Now().UTC()
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	fp := a.fingerprintOf(c)
	if fp != "" {
		if when, no := a.suppressed[fp]; no {
			return nil, fmt.Errorf(
				"that address was suppressed on %s. Article 21(3) says once "+
					"somebody has objected you must not process their data "+
					"for that purpose again, and re-importing them from a "+
					"CRM is processing", when.Format("2006-01-02"))
		}
		c.Fingerprint = fp
	}
	key := c.ID.String()
	if existing, ok := a.byID[key]; ok {
		if existing.Erased() {
			return nil, fmt.Errorf(
				"%s was erased on %s and cannot be re-added under the same "+
					"identifier", key, existing.ErasedAt.Format("2006-01-02"))
		}
		*existing = c
		return existing, nil
	}
	copied := c
	a.byID[key] = &copied
	a.order = append(a.order, key)
	return &copied, nil
}

// Object records an Article 21 objection.
//
// Kinds that cannot be objected to are recorded and reported back, rather
// than refused. Somebody asking not to be told about a breach has told you
// something real; the answer is that the law does not let them decline, and
// the answer is more useful than an error.
func (a *Audience) Object(id telemetry.ID, kinds []Kind, at time.Time) (
	[]Kind, error) {

	c, ok := a.byID[id.String()]
	if !ok {
		return nil, fmt.Errorf("%s is not on the list", id)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	c.ObjectedAt = at
	c.ObjectedTo = kinds

	var ignored []Kind
	want := kinds
	if len(want) == 0 {
		want = Kinds()
	}
	for _, k := range want {
		if !k.Objectable() {
			ignored = append(ignored, k)
		}
	}
	return ignored, nil
}

// Erase honours an Article 17 request.
//
// Clears everything that identifies a person and keeps two things: the
// identifier, so the record of what was sent before still refers to
// something, and the fingerprint, so a re-import is refused. Neither is an
// address, and neither can be turned back into one without the key.
func (a *Audience) Erase(id telemetry.ID, at time.Time) error {
	c, ok := a.byID[id.String()]
	if !ok {
		return fmt.Errorf("%s is not on the list", id)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if c.Fingerprint != "" {
		a.suppressed[c.Fingerprint] = at
	}
	c.Address = ""
	c.Name = ""
	c.ConsentText = ""
	c.ErasedAt = at
	return nil
}

// Suppress adds an address to the suppression list without it ever having
// been a contact — somebody who asked never to hear from you.
func (a *Audience) Suppress(address string, at time.Time) error {
	fp := a.Fingerprint(address)
	if fp == "" {
		return fmt.Errorf("nothing to suppress")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	a.suppressed[fp] = at
	return nil
}

// Suppressed reports whether an address is on the suppression list.
func (a *Audience) Suppressed(address string) bool {
	_, no := a.suppressed[a.Fingerprint(address)]
	return no
}

// All returns the contacts in the order they were added.
func (a *Audience) All() []Contact {
	out := make([]Contact, 0, len(a.order))
	for _, k := range a.order {
		out = append(out, *a.byID[k])
	}
	return out
}

// Len is how many contacts are on the list, erased ones included.
func (a *Audience) Len() int { return len(a.byID) }

// Reachable is how many could actually be sent a kind of notice.
//
// Reported separately from Len because the gap is the number that matters
// during a breach and the one nobody looks at beforehand.
func (a *Audience) Reachable(k Kind) int {
	var n int
	for _, key := range a.order {
		if ok, _ := a.byID[key].MayReceive(k); ok {
			n++
		}
	}
	return n
}

// Find returns one contact.
func (a *Audience) Find(id telemetry.ID) (*Contact, bool) {
	c, ok := a.byID[id.String()]
	return c, ok
}

// Suppressions returns the fingerprints on the suppression list, with when.
func (a *Audience) Suppressions() map[string]time.Time {
	out := make(map[string]time.Time, len(a.suppressed))
	for k, v := range a.suppressed {
		out[k] = v
	}
	return out
}

// Load restores an audience from stored contacts and suppressions.
func (a *Audience) Load(contacts []Contact, suppressed map[string]time.Time) {
	for _, c := range contacts {
		copied := c
		key := c.ID.String()
		if _, seen := a.byID[key]; !seen {
			a.order = append(a.order, key)
		}
		a.byID[key] = &copied
	}
	for fp, at := range suppressed {
		a.suppressed[fp] = at
	}
}
