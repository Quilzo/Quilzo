// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
)

// Dual authorisation, on the screen where publishing happens.
//
// The engine has been here for some time and was reachable only from a
// terminal — which for this particular control is close to useless. The people
// a second-approver rule exists to constrain are the ones publishing through
// the interface, and a control they cannot see is a control they route around
// by publishing through the interface.
//
// # What makes an approval mean something here
//
// It names the exact bytes. An approval carries the content hash of what was
// agreed to, so editing the draft afterwards does not carry the approval
// forward — the approval is still perfectly valid and is about something that
// is no longer proposed. Nothing has to detect the change; the arithmetic
// simply stops counting it.
//
// That is the difference between this and a review flag. A flag is set on a
// thing and stays set while the thing changes underneath it.
//
// # The rule that is not a number
//
// An AI-authored change needs a human approver regardless of the count.
// Without it, two service accounts approving each other satisfies a
// two-approver policy, which is two machines agreeing and is not what anybody
// means by review.

// Approvals gives the admin the proposal and the policy.
type Approvals struct {
	// Policy is how many people must agree, and who counts.
	Policy func() (collab.Policy, error)
	// Current is the proposal for the draft as it stands, or nil when there is
	// none. It is created lazily by Propose rather than on every save: a
	// proposal for content nobody has offered for review is noise.
	Current func() (*collab.Proposal, error)
	// For is the proposal for one commit, for publishing something other
	// than the draft: a promotion from staging into production, asked
	// about what staging holds and not about a later draft. Nil asks
	// Current, which refuses any commit but the draft's.
	For func(commit string) (*collab.Proposal, error)
	// Save records a changed proposal.
	Save func(*collab.Proposal) error
	// KindOf says whether a principal is a person, a service or a model, which
	// is what the human-approver rule turns on.
	KindOf func(principal string) string
	// Notify tells the outside world a change is waiting for agreement.
	//
	// Nil on a build with no webhooks, which is not an error: the review
	// screen still works and somebody has to think to open it. That is the
	// state this exists to improve on, not one it refuses to run in.
	Notify func(*collab.Proposal)
	// SecondPerson says whether by may approve a proposal given who made
	// it, and whether they would be approving it alone: the person whose
	// agent run wrote a draft approves it only when nobody else may
	// publish. Nil approves as before.
	SecondPerson func(prop collab.Proposal, by string) (alone bool, err error)
}

// approvalState is what the review screen shows.
type approvalState struct {
	Configured bool
	Need, Have int
	Allowed    bool
	Reason     string
	Missing    []string
	// Author is who proposed it, and may never approve it.
	Author     string
	AuthorKind string
	Message    string
	// Approvals already given for the content as it stands.
	Approvals []collab.Approval
	// Stale are approvals of content that has since changed. Shown rather than
	// hidden: "your approval no longer counts and here is why" is the message
	// somebody needs, and silently dropping it looks like the system lost it.
	Stale []collab.Approval
	// CanApprove is whether the person looking may add one.
	CanApprove bool
	// Why explains a no, so somebody is not left guessing whether it is a
	// permission or the rule about approving your own work.
	Why string
	// Proposed is whether a proposal exists at all.
	Proposed bool
	// Matches is whether the proposal is for the draft as it stands.
	Matches bool

	// MachineWrote says a model produced the content, and Wrote is the commit
	// message it left.
	//
	// Shown, not merely counted. The rule that an AI-authored change needs a
	// human approval is worth nothing if the human it requires cannot tell
	// which change that is: the reviewer sees a diff, and a diff does not say
	// whether a person or a model wrote it. Naming it is what makes the
	// approval a reading rather than a signature.
	MachineWrote bool
	Wrote        string

	// Unreadable is why the approval policy could not be read, when it
	// could not. Not the same as "not configured": that answer let the
	// browser publish past a damaged approval.json as though nothing were
	// required, while the machine interface refused.
	Unreadable string
	// PersonOnly says no count is set and the one approval needed is a
	// person's, because a model wrote the change.
	PersonOnly bool
}

// approvalFor builds the state for the review screen.
//
// Returns a zero value with Configured false when dual authorisation is off,
// which is a legitimate configuration for one person running their own site
// and a terrible one for anybody else — the screen says which.
//
// Off means no count of approvals and nothing a model wrote. A person
// approves what a model wrote whatever the count, and nothing turns that
// off (cmd/quilzo loadApprovalPolicy), so a policy whose count is zero is
// still asked about a model's draft. It was not: this answered "not
// configured" whenever the count was zero, which on a store nobody
// configured is always, and the browser published an agent's draft that
// the command line and the machine interface refused.
func (s *Server) approvalFor(p principal, draft string) approvalState {
	if s.Approvals == nil || s.Approvals.Policy == nil {
		return approvalState{}
	}
	pol, err := s.Approvals.Policy()
	if err != nil {
		return approvalState{Unreadable: err.Error()}
	}
	// How many are needed, counting the people a policy asks for as well
	// as the approvals. approval.required_humans is a setting of its own
	// ("set to two, nothing publishes without two people"), and this asked
	// only about review.required_approvals: with that at zero a person's
	// draft published from here unapproved while the command line and the
	// machine interface refused it, and with it below the people asked for
	// the screen said "1 of 1" beside a refusal.
	counted := max(pol.Required, pol.RequiredHumans)
	if counted <= 0 && !pol.RequireHumanForAI {
		return approvalState{}
	}

	prop, err := s.Approvals.Current()
	if s.Approvals.For != nil && draft != s.Store.GetRef(site.RefDraft) {
		prop, err = s.Approvals.For(draft)
	}
	if err != nil {
		prop = nil
	}

	// What a model wrote among everything this would put live, and not
	// only in the newest commit (site.MachineWroteSince): read from that
	// one alone, a person's typo fix on top of an agent's change made the
	// agent's change a person's, and Publish put it live unapproved.
	wrote := machineChange(s, draft)

	need := counted
	if need <= 0 {
		// Only the rule about a model's work applies, and only to a model's
		// work: one person running their own site publishes their own words
		// with nobody else asked, as before.
		if !machineWrote(wrote, draft, prop) {
			return approvalState{}
		}
		// One approval, from a person, is what that rule needs. Said as a
		// number so the screen does not read "0 of 0 approvals" beside a
		// refusal, and so Approvals lists it for whoever may give it.
		need = 1
	}

	st := approvalState{Configured: true, Need: need, PersonOnly: counted <= 0}

	if prop == nil {
		st.Why = "Nobody has offered this for review yet."
		return st
	}
	st.Proposed = true
	st.Author, st.AuthorKind, st.Message = prop.Author, prop.AuthorKind, prop.Message
	// What the machine actually did, read from the commit rather than from the
	// proposal's note: the note is what somebody typed when offering it, and
	// the commit is what was done.
	if c, cerr := s.Store.GetCommit(prop.Content); cerr == nil {
		st.Wrote = c.Message
		st.MachineWrote = collab.MachineWrote(c.Message)
	}
	// And what is behind it: the proposal is judged on everything it
	// would put live, and named by the model's change when that is not
	// the newest commit.
	if prop.Content != draft {
		wrote = machineChange(s, prop.Content)
	}
	if wrote != nil {
		st.MachineWrote = true
		if wrote.Message != "" {
			st.Wrote = wrote.Message
		}
	}
	st.Matches = prop.Content == draft
	st.Stale = prop.Stale()

	for _, a := range prop.Approvals {
		if a.Content == prop.Content {
			st.Approvals = append(st.Approvals, a)
		}
	}

	kindOf := s.Approvals.KindOf
	if kindOf == nil {
		kindOf = func(string) string { return "human" }
	}
	// A copy, marked: a proposal recorded as a person's is still a
	// model's when a model wrote some of it, and the hooks' own record is
	// not this screen's to rewrite.
	judged := *prop
	judged.MarkMachine(wrote)
	d := pol.Evaluate(judged, kindOf, time.Now())
	st.Allowed, st.Reason, st.Have, st.Missing = d.Allowed, d.Reason, d.Have, d.Missing

	switch {
	case !s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed:
		st.Why = "Approving is part of publishing, and you cannot publish here."
	case p.Name == prop.Author:
		// The rule that makes the whole thing worth having. Somebody approving
		// their own work satisfies a counter and reviews nothing.
		st.Why = "You proposed this, so you cannot also approve it."
	case pol.Requested(judged, p.Name):
		// What a model wrote for the person looking, with a count set: they
		// asked for it, as they would their own work.
		st.Why = "A model wrote this for you, so you asked for it, and with a " +
			"count of approvals set somebody else approves it."
	case !pol.Counts(p.Name):
		// Asked only who may publish, this offered the approval to
		// somebody the approvers leave out, and theirs was recorded and
		// counted for nothing (collab.Policy.Counts).
		st.Why = "Only approvals from " + strings.Join(pol.Approvers, ", ") +
			" count towards publishing this, so yours is not asked for."
	case !st.Matches:
		st.Why = "The draft has moved since this was proposed. Propose the " +
			"current draft before approving it."
	default:
		already := false
		for _, a := range st.Approvals {
			if a.By == p.Name {
				already = true
			}
		}
		if already {
			st.Why = "You have already approved this."
		} else {
			st.CanApprove = true
		}
	}
	return st
}

// machineChange is the newest change a model wrote among those publishing
// commit would put live, or nil when people wrote all of them.
//
// A commit that cannot be read is answered as a model's, as the walk
// answers one behind it: nothing shows a person wrote it, and publishing
// it fails on its own account anyway. No commit at all, as on a store with
// no draft yet, is nothing anybody wrote.
func machineChange(s *Server, commit string) *collab.MachineChange {
	if commit == "" {
		return nil
	}
	m, err := site.MachineWroteSince(s.Store, commit)
	if err != nil {
		return &collab.MachineChange{Commit: commit, Unread: err.Error()}
	}
	return m
}

// machineWrote reports whether a model wrote any of what publishing commit
// would put live (machineChange), or the proposal for exactly these bytes
// was made as a model's (collab.AuthorKindFor).
func machineWrote(m *collab.MachineChange, commit string, prop *collab.Proposal) bool {
	if prop != nil && prop.Content == commit && prop.AuthorKind == "ai" {
		return true
	}
	return m != nil
}

// handlePropose offers the current draft for review.
func (s *Server) handlePropose(w http.ResponseWriter, r *http.Request) {
	p, ok := s.approvalWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	draft := s.Store.GetRef(site.RefDraft)
	if draft == "" {
		s.approvalRedirect(w, r, "", "there is no draft to propose")
		return
	}

	prop, err := s.Approvals.Current()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Who wrote it, not who is offering it.
	//
	// This read the proposer's kind alone, so a person opening this screen on
	// a draft a model had just written proposed it as "human" — and
	// RequireHumanForAI, the rule that exists to stop two service accounts
	// approving a model's work, never fired. The command line already got this
	// right by reading the commit; the two now share one function so they
	// cannot disagree again.
	proposerKind := "human"
	if s.Approvals.KindOf != nil {
		proposerKind = s.Approvals.KindOf(p.Name)
	}
	authored := ""
	if c, cerr := s.Store.GetCommit(draft); cerr == nil {
		authored = c.Message
	}
	kind := collab.AuthorKindFor(authored, proposerKind)
	// And of every commit behind it that publishing would put live: the
	// newest being a person's typo fix does not make an agent's change
	// under it a person's.
	if machineChange(s, draft) != nil {
		kind = "ai"
	}
	message := strings.TrimSpace(r.FormValue("message"))

	if prop == nil {
		prop = &collab.Proposal{
			Content: draft, Author: p.Name, AuthorKind: kind,
			CreatedAt: time.Now().Unix(), Message: message,
		}
	} else {
		// Rebasing keeps the record of what was approved before rather than
		// discarding it. Those approvals stop counting — they name different
		// bytes — and they are still the truthful history of who agreed to
		// what, which is the part an auditor reads.
		prop.Rebase(draft, p.Name, time.Now())
		// Moved onto content a model wrote some of, it is a model's. Kept
		// as it was otherwise: a person re-offering a model's proposal
		// does not make it theirs.
		if kind == "ai" {
			prop.AuthorKind = kind
		}
		if message != "" {
			prop.Message = message
		}
	}
	if err := s.Approvals.Save(prop); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "approval.propose", "/", map[string]string{
		"commit": shortHash(draft), "author_kind": kind})

	// Tell whoever has to agree that they are being waited on.
	//
	// After the save succeeded, and never able to prevent it: a receiver being
	// unreachable is not a reason to refuse a proposal, and making it one
	// hands anybody who can take an endpoint offline the ability to stop the
	// site being reviewed.
	//
	// Without this the review screen is a page somebody has to think to open.
	// A proposal then sits until its author asks in person, and the reliable
	// way to stop being asked in person is to turn the requirement off.
	if s.Approvals.Notify != nil {
		s.Approvals.Notify(prop)
	}
	s.approvalRedirect(w, r, "proposed for review", "")
}

// handleApprove records one agreement.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.approvalWriter(w, r, auth.ActPublish)
	if !ok {
		return
	}
	prop, err := s.Approvals.Current()
	if err != nil || prop == nil {
		s.approvalRedirect(w, r, "", "there is nothing proposed to approve")
		return
	}
	// Re-checked here rather than trusted from the screen. The button being
	// absent is presentation; this is the control, and a POST does not need a
	// button to have been rendered.
	draft := s.Store.GetRef(site.RefDraft)
	if prop.Content != draft {
		s.approvalRedirect(w, r, "", "the draft has moved since this was "+
			"proposed, so an approval now would name content nobody offered")
		return
	}
	alone := false
	if s.Approvals.SecondPerson != nil {
		var serr error
		if alone, serr = s.Approvals.SecondPerson(*prop, p.Name); serr != nil {
			s.approvalRedirect(w, r, "", serr.Error())
			return
		}
	}
	if err := prop.Approve(p.Name, strings.TrimSpace(r.FormValue("note")),
		time.Now()); err != nil {
		s.approvalRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Approvals.Save(prop); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "approval.approve", "/", map[string]string{
		"commit": shortHash(prop.Content), "alone": strconv.FormatBool(alone)})
	s.approvalRedirect(w, r, "recorded", "")
}

// blockedByApproval is the publish gate.
//
// Returns the reason when publication must not proceed, and the empty string
// when it may. Deliberately not overridable by the reason field the other
// gates accept: an accessibility failure somebody accepts responsibility for is
// a judgement call, and "publish without the approvals the policy requires" is
// the thing the policy exists to prevent.
//
// A policy that cannot be read refuses, as the machine interface and the
// command line do: a gate that cannot run must not answer like a gate that
// passed.
func (s *Server) blockedByApproval(p principal, draft string) string {
	st := s.approvalFor(p, draft)
	if st.Unreadable != "" {
		return "The approval policy could not be read, so publishing would " +
			"claim a check that did not happen: " + st.Unreadable
	}
	if !st.Configured {
		return ""
	}
	if !st.Proposed {
		if st.PersonOnly {
			return "A model wrote this change, so a person approves it before " +
				"it is published. Offer it for review below, and somebody " +
				"who may publish approves it here."
		}
		return "This store requires approval before publishing, and nothing " +
			"has been proposed for review."
	}
	if !st.Matches {
		return "The draft has moved since it was proposed. Propose the " +
			"current draft, and it will need approving again — an approval " +
			"names the exact bytes it agreed to."
	}
	if !st.Allowed {
		if st.MachineWrote || st.AuthorKind == "ai" {
			// Where to give it, beside what is needed: the reason says a
			// person, and the screen it is shown on is where they approve.
			return st.Reason + " Somebody who may publish, and did not " +
				"write it, approves it under Approval on this screen."
		}
		return st.Reason
	}
	return ""
}

func (s *Server) approvalWriter(w http.ResponseWriter, r *http.Request,
	act auth.Action) (principal, bool) {

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, act, "/") {
		return principal{}, false
	}
	if s.Approvals == nil || s.Approvals.Current == nil || s.Approvals.Save == nil {
		s.unwired(w, r, p, "Review", "the approval policy")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) approvalRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/review"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

var _ = fmt.Sprintf
