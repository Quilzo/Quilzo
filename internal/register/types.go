// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The value types a record's fields are made of.
//
// A field's Go type is its schema. The validator (validate.go) reads the type
// and holds the value to it, so a field declared ID cannot hold a name and a
// field declared Text cannot hold the text itself. That is what lets the
// rules about personal data be rules about types: a person is a Subject's
// identifier, free text is a digest, and neither rule depends on anybody
// remembering it at a call site.

// ID is the identifier of a register record: 32 lowercase hexadecimal
// characters, 128 bits. It is derived from what the record is (id.go), never
// chosen by the writer.
type ID string

var reID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Valid reports whether id has the shape of an identifier.
func (id ID) Valid() bool { return reID.MatchString(string(id)) }

// bytes is the identifier as the index holds it. An identifier that is not
// valid is sixteen zero bytes, which no record has.
func (id ID) bytes() (b [16]byte) {
	if id.Valid() {
		hex.Decode(b[:], []byte(id))
	}
	return b
}

// idOf is the identifier sixteen bytes of an index row spell.
func idOf(b [16]byte) ID { return ID(hex.EncodeToString(b[:])) }

// NewSubjectID mints the identifier of a Subject: 128 random bits.
//
// A Subject is the one kind whose identifier is not derived. Derived from a
// person's address or account name, it could be recomputed by anybody who
// knows the address, and a pseudonym that can be recomputed names the person
// to everybody who already knows them. The map from this identifier to the
// person is kept outside the immutable store, where it can be erased.
func NewSubjectID() (ID, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no entropy for a subject identifier: %w", err)
	}
	return ID(hex.EncodeToString(b)), nil
}

// Digest names content kept outside the store by its hash: a raw evidence
// file, a signed minute, a questionnaire as it was received. It is written
// "sha256:" and 64 lowercase hexadecimal characters.
type Digest string

var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Valid reports whether d has the shape of a digest.
func (d Digest) Valid() bool { return reDigest.MatchString(string(d)) }

// Text is free text a person wrote, held as the digest of the text and not
// as the text: a justification, a commentary, a note. The words themselves
// live in the erasable side store, because free text is where a person's
// name ends up, and the store these records are written to cannot forget.
type Text string

// Valid reports whether t has the shape of a digest.
func (t Text) Valid() bool { return reDigest.MatchString(string(t)) }

// Time is a moment, in seconds since the Unix epoch, UTC. A whole number so
// that two writers of one fact produce one record: a time with a zone or a
// fraction is the same moment written two ways, and a record that differs
// only in spelling is a commit nobody needed.
type Time int64

// At is t as a time.Time, in UTC.
func (t Time) At() time.Time { return time.Unix(int64(t), 0).UTC() }

// TimeOf is a time.Time as a record holds it.
func TimeOf(t time.Time) Time { return Time(t.Unix()) }

// Scalar is the value of a typed fact: text, a number or a yes or no, and
// nothing else. A list or an object is not a fact a test can assert on, and
// an Observation that held one would be a document filed as a fact.
type Scalar struct{ v any }

// TextValue, NumberValue and BoolValue make a Scalar of each of the three
// types.
func TextValue(s string) Scalar    { return Scalar{s} }
func NumberValue(n float64) Scalar { return Scalar{n} }
func BoolValue(b bool) Scalar      { return Scalar{b} }

// Value is what the scalar holds: a string, a float64 or a bool, or nil when
// it was never set.
func (s Scalar) Value() any { return s.v }

// IsZero reports whether the scalar was never set, which omits it from JSON.
func (s Scalar) IsZero() bool { return s.v == nil }

// String is the value as a person reads it.
func (s Scalar) String() string {
	switch v := s.v.(type) {
	case string:
		return v
	case nil:
		return ""
	}
	b, _ := json.Marshal(s.v)
	return string(b)
}

// MarshalJSON writes the bare value, so a query over a record's fields
// compares the value itself.
func (s Scalar) MarshalJSON() ([]byte, error) { return json.Marshal(s.v) }

// UnmarshalJSON takes text, a number or a yes or no, and refuses the rest.
func (s *Scalar) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch v.(type) {
	case string, float64, bool, nil:
		s.v = v
		return nil
	}
	return fmt.Errorf("a fact's value is text, a number or true or false, not %s", strings.TrimSpace(string(b)))
}

// An enumeration is a named string type with the values it may hold. The
// validator finds the list through this method, so the schema, the refusal
// and the screens that offer a choice all read one list.
type enumeration interface{ Values() []string }

// Grade says how a fact reached the record, which is how far it can be
// trusted to be what the source said. Every Observation and every Evidence
// carries one, and a metric may ask for a minimum.
type Grade string

const (
	// GradeConnector is a fact Quilzo fetched itself from the source's own
	// interface, with a credential it holds.
	GradeConnector Grade = "connector"
	// GradeCI is a fact a pipeline pushed, under an identity its platform
	// attested.
	GradeCI Grade = "ci"
	// GradeSigned is a fact signed by a third party whose key is pinned.
	GradeSigned Grade = "signed"
	// GradeImported is a fact taken from another tool's export.
	GradeImported Grade = "imported"
	// GradeUploaded is a file a person uploaded.
	GradeUploaded Grade = "uploaded"
	// GradeScreenshot is a picture of a screen: the weakest, because it
	// shows what somebody saw and nothing can re-gather it.
	GradeScreenshot Grade = "screenshot"
)

// Values lists the grades, strongest first.
func (Grade) Values() []string {
	return []string{string(GradeConnector), string(GradeCI), string(GradeSigned),
		string(GradeImported), string(GradeUploaded), string(GradeScreenshot)}
}

// Rank orders the grades for a minimum: a lower rank is a stronger grade, and
// a grade nobody declared ranks below them all.
func (g Grade) Rank() int {
	for i, v := range g.Values() {
		if v == string(g) {
			return i
		}
	}
	return len(g.Values())
}

// Class is how far a record may travel: which people may read it and which
// model routes it may be sent to. Each kind declares one.
type Class string

const (
	// ClassPublic is what the organisation has published.
	ClassPublic Class = "public"
	// ClassInternal is the working record: controls, tests, metrics.
	ClassInternal Class = "internal"
	// ClassConfidential is held under an agreement: vendor reports and what
	// is shared under a non-disclosure agreement.
	ClassConfidential Class = "confidential"
	// ClassRestricted is board, incident and vulnerability material, and
	// anything about a person.
	ClassRestricted Class = "restricted"
)

// Values lists the classes, least restricted first.
func (Class) Values() []string {
	return []string{string(ClassPublic), string(ClassInternal), string(ClassConfidential), string(ClassRestricted)}
}

// Approval is a person's decision, held inside the record it decides. It is
// not a kind of its own: an approval filed apart from what it approves can be
// read without it, and the question an auditor asks is always "who decided
// this, and what were they shown".
//
// What is checked here is its shape and the rule that the person who asked is
// not the person who agreed. Whether the authentication evidence is genuine
// is asked of the Register's Approvals hook, which the approvals module
// supplies.
type Approval struct {
	// Atom is the permission that made the approvers eligible, such as
	// accept-risk.
	Atom string `json:"atom" reg:"required,label" about:"the permission that made the approvers eligible"`
	// Rule is the rule of the organisation's separation policy that applied,
	// by name.
	Rule string `json:"rule" reg:"required,label" about:"the rule of the separation policy that applied"`
	// Needed and Of are the N of M: how many approvers the rule asked for,
	// and how many people were eligible when it was asked.
	Needed int `json:"needed" reg:"required,min=1" about:"how many approvers the rule asked for"`
	Of     int `json:"of" reg:"required,min=1" about:"how many people were eligible to approve"`
	// Surface is the hash of what the approvers were shown: the record, the
	// evidence it cites and the change. An approval of one surface is not an
	// approval of another.
	Surface Digest `json:"surface" reg:"required" about:"the hash of what the approvers were shown"`
	// Raised is the Subject who asked for the decision.
	Raised ID `json:"raised_by" reg:"required,ref=Subject" about:"who asked for the decision"`
	// Signers are the people who agreed, each with when and with the digest
	// of their authentication evidence.
	Signers []Signer `json:"signers" reg:"required" about:"who agreed, when, and on what authentication evidence"`
	// Alone marks a decision made by the only person eligible. It is shown
	// wherever the record is, and ReviewDue is when somebody else has to
	// have looked at it.
	Alone     bool `json:"alone,omitempty" about:"the decision was made by the only person eligible"`
	ReviewDue Time `json:"review_due,omitempty" about:"when a compensating review of a decision made alone is due"`
}

// Signer is one person's agreement.
type Signer struct {
	Subject ID   `json:"subject" reg:"required,ref=Subject" about:"who agreed"`
	At      Time `json:"at" reg:"required" about:"when they agreed"`
	// Assertion is the digest of the authentication evidence that binds
	// this person to the surface: for a passkey, the assertion over a
	// challenge made from the surface's hash.
	Assertion Digest `json:"assertion" reg:"required" about:"the digest of the authentication evidence bound to the surface"`
}

// check holds an approval to its own rules: enough distinct signers, none of
// them the person who asked, unless that person was the only one eligible
// and the record says so.
func (a *Approval) check() error {
	if a.Of < a.Needed && !a.Alone {
		return fmt.Errorf("an approval that needs %d of %d eligible people cannot be met", a.Needed, a.Of)
	}
	if len(a.Signers) < a.Needed {
		return fmt.Errorf("the approval needs %d approver(s) and holds %d", a.Needed, len(a.Signers))
	}
	seen := map[ID]bool{}
	for _, s := range a.Signers {
		if seen[s.Subject] {
			return fmt.Errorf("the same person approved twice; each approver counts once")
		}
		seen[s.Subject] = true
		if s.Subject == a.Raised && !a.Alone {
			return fmt.Errorf("the person who asked for a decision cannot be the one who approves it")
		}
	}
	if a.Alone {
		if len(a.Signers) != 1 || a.Needed != 1 {
			return fmt.Errorf("a decision made alone has one approver")
		}
		if a.ReviewDue == 0 {
			return fmt.Errorf("a decision made alone needs the date its compensating review is due")
		}
	} else if a.ReviewDue != 0 {
		return fmt.Errorf("a compensating review is for a decision made alone")
	}
	return nil
}
