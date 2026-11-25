// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"slices"
)

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
//
// It is raised as a request, by the person who asked or on their behalf by
// somebody who entered it, and waits on the proposals ref; it is decided
// through the approvals module, as every decision is, by somebody who is
// neither the person erased nor, while anybody else may decide it, whoever
// asked or entered it. Who decided it and when are the approval's: the
// decider is its last signer, named by pseudonym alone, and the moment is
// theirs, which is when the person's data went (fromApproval).
type Erasure struct {
	Subject ID           `json:"subject" reg:"required,ref=Subject" about:"the pseudonym whose person was erased; from then on it names nobody"`
	Basis   ErasureBasis `json:"basis" reg:"required" about:"the ground it was erased on"`
	// RequestedBy is who asked for it: the person themselves, or whoever
	// else asked; EnteredBy is who entered the request, when somebody did
	// on their behalf.
	RequestedBy ID   `json:"requested_by,omitempty" reg:"ref=Subject" about:"who asked for it: the person themselves, or whoever else asked"`
	EnteredBy   ID   `json:"entered_by,omitempty" reg:"ref=Subject" about:"who entered the request, on behalf of whoever asked"`
	Decider     ID   `json:"decider" reg:"required,ref=Subject" about:"who decided it: the last to approve it"`
	At          Time `json:"at" reg:"required" about:"when it was erased: when its decider approved it"`
	// Also is the person's other pseudonyms, which maps kept before there
	// was one map gave them, erased with this one.
	Also []ID `json:"also,omitempty" about:"the person's other pseudonyms, erased with this one"`
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
	if a := e.Approval; a != nil {
		for _, s := range a.Signers {
			if s.Subject == e.Subject || slices.Contains(e.Also, s.Subject) {
				return fmt.Errorf("a person does not decide their own erasure: after it, nothing would say who decided")
			}
		}
		if len(a.Signers) == 0 || a.Signers[len(a.Signers)-1].Subject != e.Decider {
			return fmt.Errorf("an erasure's decider is the last to approve it")
		}
	}
	return nil
}

// fromApproval is the erasure with what its approval says of it: who
// decided it, the last to approve it, and when, which is when the person's
// data went. Without an approval it names neither, so what an approver is
// shown is the request, and their approval is not part of what it
// approves.
func (e Erasure) fromApproval(a *Approval) Record {
	e.Decider, e.At = "", 0
	if a != nil && len(a.Signers) > 0 {
		last := a.Signers[len(a.Signers)-1]
		e.Decider, e.At = last.Subject, last.At
	}
	return e
}

func (e Erasure) index(r *Row) {
	r.About, r.Via, r.At, r.N, r.State = e.Subject.bytes(), e.Decider.bytes(), int64(e.At), clamp32(e.Entries), ordinal(e.Basis)
}

var _ = define[Erasure]("A person erased: whose pseudonym now names nobody, on what basis and on whose decision.",
	ClassRestricted, signed, immutable)
