// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import "fmt"

// The erasure of a person: the one decision the register records about
// somebody that leaves them out of it.
//
// What was erased is not in the register and never was. The map from a
// pseudonym to the person, and the free text and files about them, are in
// the side store (privacy.go), and erasing deletes them there. What the
// register keeps is this record: which pseudonym now names nobody, on what
// basis, who decided and with what approval, and how much went. It is a
// decision, so it carries its approval, and it is never changed once
// written, so a later reader can tell an erasure from a record that was
// tidied away.

// ErasureBasis is the ground a person's data was erased on, as data
// protection law names them.
type ErasureBasis string

// Values lists the bases of an erasure: the person asked (GDPR Article
// 17(1)), objected to the processing (Article 21), withdrew their consent,
// the data is no longer needed for its purpose, it was processed
// unlawfully, or a law requires it gone.
func (ErasureBasis) Values() []string {
	return []string{"request", "objection", "consent-withdrawn", "no-longer-needed", "unlawful", "legal-obligation"}
}

// Erasure records that a person was erased.
type Erasure struct {
	Subject ID           `json:"subject" reg:"required,ref=Subject" about:"the pseudonym whose person was erased; from then on it names nobody"`
	Basis   ErasureBasis `json:"basis" reg:"required" about:"the ground it was erased on"`
	Decider ID           `json:"decider" reg:"required,ref=Subject" about:"who decided it"`
	At      Time         `json:"at" reg:"required" about:"when it was erased"`
	// Map says the map's entry from the pseudonym to the person was
	// deleted; Entries and Kinds are how many entries of free text and
	// files about them went, and the kinds whose records named them.
	Map     bool     `json:"map,omitempty" about:"the entry naming the person behind the pseudonym was deleted"`
	Entries int64    `json:"entries" reg:"min=0" about:"how many entries of free text and files about them were deleted"`
	Kinds   []string `json:"kinds,omitempty" reg:"label" about:"the kinds whose records named those entries"`
	// Erased is the digest of the list of entries deleted, so a list kept
	// elsewhere can be checked against it without this record holding it.
	Erased   Digest    `json:"erased,omitempty" about:"the digest of the list of entries deleted"`
	Approval *Approval `json:"approval" reg:"required" about:"the decision to erase, with who made it and their authentication evidence"`
}

const KindErasure Kind = "Erasure"

func (Erasure) Kind() Kind { return KindErasure }

// Key is the pseudonym alone: a person is erased once, and the record of it
// is found from the pseudonym that names nobody now.
func (e Erasure) Key() (string, string) { return Local, string(e.Subject) }

func (e Erasure) Check() error {
	if e.Decider == e.Subject {
		return fmt.Errorf("a person does not decide their own erasure: after it, nothing would say who decided")
	}
	if e.Approval != nil && (len(e.Approval.Signers) != 1 || e.Approval.Signers[0].Subject != e.Decider) {
		return fmt.Errorf("an erasure's approval is the decider's, and only theirs")
	}
	return nil
}

func (e Erasure) index(r *Row) {
	r.About, r.Via, r.At, r.N, r.State = e.Subject.bytes(), e.Decider.bytes(), int64(e.At), clamp32(e.Entries), ordinal(e.Basis)
}

var _ = define[Erasure]("A person erased: whose pseudonym now names nobody, on what basis and on whose decision.",
	ClassRestricted, signed, immutable)
