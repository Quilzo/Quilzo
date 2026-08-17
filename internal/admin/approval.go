package admin

import (
	"fmt"
	"net/http"
	"net/url"
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
	// Save records a changed proposal.
	Save func(*collab.Proposal) error
	// KindOf says whether a principal is a person, a service or a model, which
	// is what the human-approver rule turns on.
	KindOf func(principal string) string
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
}

// approvalFor builds the state for the review screen.
//
// Returns a zero value with Configured false when dual authorisation is off,
// which is a legitimate configuration for one person running their own site
// and a terrible one for anybody else — the screen says which.
func (s *Server) approvalFor(p principal, draft string) approvalState {
	if s.Approvals == nil || s.Approvals.Policy == nil {
		return approvalState{}
	}
	pol, err := s.Approvals.Policy()
	if err != nil || pol.Required == 0 {
		return approvalState{}
	}

	st := approvalState{Configured: true, Need: pol.Required}

	prop, err := s.Approvals.Current()
	if err != nil || prop == nil {
		st.Why = "Nobody has offered this for review yet."
		return st
	}
	st.Proposed = true
	st.Author, st.AuthorKind, st.Message = prop.Author, prop.AuthorKind, prop.Message
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
	d := pol.Evaluate(*prop, kindOf, time.Now())
	st.Allowed, st.Reason, st.Have, st.Missing = d.Allowed, d.Reason, d.Have, d.Missing

	switch {
	case !s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed:
		st.Why = "Approving is part of publishing, and you cannot publish here."
	case p.Name == prop.Author:
		// The rule that makes the whole thing worth having. Somebody approving
		// their own work satisfies a counter and reviews nothing.
		st.Why = "You proposed this, so you cannot also approve it."
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
	kind := "human"
	if s.Approvals.KindOf != nil {
		kind = s.Approvals.KindOf(p.Name)
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
		"commit": shortHash(prop.Content)})
	s.approvalRedirect(w, r, "recorded", "")
}

// blockedByApproval is the publish gate.
//
// Returns the reason when publication must not proceed, and the empty string
// when it may. Deliberately not overridable by the reason field the other
// gates accept: an accessibility failure somebody accepts responsibility for is
// a judgement call, and "publish without the approvals the policy requires" is
// the thing the policy exists to prevent.
func (s *Server) blockedByApproval(p principal, draft string) string {
	st := s.approvalFor(p, draft)
	if !st.Configured {
		return ""
	}
	if !st.Proposed {
		return "This store requires approval before publishing, and nothing " +
			"has been proposed for review."
	}
	if !st.Matches {
		return "The draft has moved since it was proposed. Propose the " +
			"current draft, and it will need approving again — an approval " +
			"names the exact bytes it agreed to."
	}
	if !st.Allowed {
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
