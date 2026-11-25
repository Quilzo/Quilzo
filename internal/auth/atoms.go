// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

// The permissions of the security record (its atoms).
//
// Accepting a risk, granting an exception, signing the board's pack or
// publishing outside the organisation are decisions a person answers for,
// and the separation policy (internal/approval) says who may make each. It
// says so in these words: somebody is eligible to accept a risk because they
// hold accept-risk on the register, and the approval records that atom as
// what made them eligible. Each follows the rung it would have followed had
// it never been named, so a store that grants none of them behaves as it
// did: an administrator of the compliance area may make every one of these
// decisions, and a reader of it may read the evidence. Granted alone, on the
// register (/@compliance/register) or on one kind of record in it, an atom
// is that decision and nothing else, which is how the head of risk becomes
// the second approver of a risk acceptance without becoming an administrator
// of anything.
//
// They are added to the permissions from this file, rather than written into
// the list in permission.go, because they belong to the security record and
// are read by its modules.

const (
	// ActAcceptRisk accepts a risk on the organisation's behalf.
	ActAcceptRisk Action = "accept-risk"
	// ActApproveException lets a control or a risk stand unmet for a set
	// time.
	ActApproveException Action = "approve-exception"
	// ActSignBoardPack signs what goes to the board: its pack and the risk
	// appetite it sets.
	ActSignBoardPack Action = "sign-board-pack"
	// ActPublishExternal publishes something outside the organisation: an
	// attestation, a status page, an answer to a customer.
	ActPublishExternal Action = "publish-external"
	// ActManageConnectors declares a source of evidence and approves a
	// scope that can write to the system it reads.
	ActManageConnectors Action = "manage-connectors"
	// ActReadEvidence reads the raw evidence a record cites.
	ActReadEvidence Action = "read-evidence"
	// ActRunCrew starts one of the security crews.
	ActRunCrew Action = "run-crew"
	// ActRecordMinute records what a board or a committee minuted.
	ActRecordMinute Action = "record-minute"
)

// Atoms are the permissions of the security record, in the order people
// read them.
var Atoms = []Permission{
	{ActAcceptRisk, "accept a risk on the organisation's behalf, in the security record"},
	{ActApproveException, "let a control or a risk stand unmet for a set time, in the security record"},
	{ActSignBoardPack, "sign what goes to the board: its pack and the risk appetite it sets"},
	{ActPublishExternal, "publish something outside the organisation: an attestation, a status page, an answer"},
	{ActManageConnectors, "declare a source of evidence and approve a scope that can write to what it reads"},
	{ActReadEvidence, "read the raw evidence a record of the security record cites"},
	{ActRunCrew, "start one of the security crews"},
	{ActRecordMinute, "record what a board or a committee minuted"},
}

// atomRungs is the rung each atom follows when it is not granted alone: a
// decision is an administrator's, reading evidence a reader's, and starting
// a crew an author's, as starting an agent is.
var atomRungs = map[Action]Role{
	ActAcceptRisk: RoleAdmin, ActApproveException: RoleAdmin, ActSignBoardPack: RoleAdmin,
	ActPublishExternal: RoleAdmin, ActManageConnectors: RoleAdmin, ActRecordMinute: RoleAdmin,
	ActReadEvidence: RoleReader, ActRunCrew: RoleAuthor,
}

func init() {
	for _, a := range Atoms {
		needs[a.Action] = atomRungs[a.Action]
	}
	Permissions = append(Permissions, Atoms...)
}

// IsAtom reports whether an action is one of the security record's atoms.
func IsAtom(a Action) bool {
	for _, p := range Atoms {
		if p.Action == a {
			return true
		}
	}
	return false
}

// MethodSSOPhishingResistant marks a single sign-on whose identity provider
// said the person used a method that cannot be phished: an amr of hwk, phr
// or phrh (RFC 8176), or an acr or SAML class the operator named as meaning
// one. It is recorded beside MethodSSO, never in its place, so everything
// that asks whether a session came through the identity provider still
// finds it did; what it adds is the one fact a person who approves must be
// able to show.
const MethodSSOPhishingResistant = "sso-phr"

// PhishingResistant reports whether a session's methods include one that
// cannot be phished: a passkey, which a browser offers to no other site, or
// a single sign-on its provider said used such a method. "mfa" alone is not
// one: a code typed from a phone is typed as readily into a copy of the
// page.
func PhishingResistant(methods []string) bool {
	for _, m := range methods {
		if m == MethodPasskey || m == MethodSSOPhishingResistant {
			return true
		}
	}
	return false
}
