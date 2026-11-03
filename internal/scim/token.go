// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package scim

import "time"

// Who made the provisioning token, and how.
//
// Approving a group mapping that makes administrators hands whoever holds
// the provisioning token the power to make administrators, by putting
// people in the group. A token made while no group made administrators
// was rightly made by one person, and stays valid once such a mapping is
// approved; the approver could not see it, so agreeing to the mapping
// agreed to something they had not been shown. This is what is kept beside
// the token's hash so that the approval can show it.

// How a token came to be made.
const (
	// Unasked is a token made while no group made administrators, so
	// nobody else was asked.
	Unasked = "unasked"
	// Alone is one the only administrator approved, asking for it.
	Alone = "alone"
	// ByTwo is one a second administrator approved.
	ByTwo = "two"
)

// TokenMade is who made the provisioning token and how it was approved.
type TokenMade struct {
	By         string `json:"by,omitempty"`
	Approval   string `json:"approval,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
}

// How is how a token was approved, in words.
func (m TokenMade) How() string {
	switch m.Approval {
	case Alone:
		return "approved alone, as the only administrator"
	case ByTwo:
		return "approved by " + m.ApprovedBy
	}
	return "while no group made administrators, so nobody else was asked"
}

// LiveToken is a provisioning token that works now: how it was made, when,
// and when it stops.
type LiveToken struct {
	TokenMade
	Made, Ends time.Time
}

// Words is a live token as somebody approving a mapping reads it: who
// made it, when, how it was approved, and until when it works.
func (t LiveToken) Words() string {
	made, ends := t.Made.UTC().Format("2 Jan 2006 at 15:04 UTC"), t.Ends.UTC().Format("2 Jan 2006")
	if t.By == "" {
		return "made on " + made + ", before who made a token was kept, so nobody can say who made it " +
			"or whether anybody else agreed; works until " + ends
	}
	return "made by " + t.By + " on " + made + ", " + t.How() + "; works until " + ends
}
