// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/scim"
)

// Privileged changes that wait for a second administrator (internal/dual):
// proposed on the People and Settings screens, decided on People.

// Dual is where the requests are kept, and how the changes this package
// does not make itself are made.
type Dual struct {
	Store *dual.Store
	// Apply makes an approved change of a kind the admin has no part in
	// (the audit log's directory), as by.
	Apply func(r dual.Request, by string) error
}

// onlyAdministrator reports whether name is the only person who could
// approve, and may approve alone: nobody else administers the whole site,
// and no other administrator stopped being one in the last day
// (aloneRefusal), or the record of that cannot be read.
func (s *Server) onlyAdministrator(name string) bool {
	if !s.soleAdministrator(name) {
		return false
	}
	if s.Dual == nil || s.Dual.Store == nil {
		return true
	}
	rm, err := s.Dual.Store.Settling(time.Now())
	return err == nil && rm == nil
}

// soleAdministrator reports whether nobody but name administers the whole
// site now (dual.Administrators).
func (s *Server) soleAdministrator(name string) bool {
	if s.Policy == nil {
		return true
	}
	admins := dual.Administrators(s.Policy)
	return len(admins) == 0 || (len(admins) == 1 && admins[strings.ToLower(name)])
}

// aloneRefusal is the removal that keeps name, the only administrator,
// from approving alone at now, or nil when they are not the only one or
// may.
func (s *Server) aloneRefusal(name string, now time.Time) *dual.Removal {
	if s.Dual == nil || s.Dual.Store == nil || !s.soleAdministrator(name) {
		return nil
	}
	rm, _ := s.Dual.Store.Settling(now)
	return rm
}

// refuseAlone records that the only administrator was refused approving
// alone, with the removal it follows and what they were approving, and is
// the refusal in words.
func (s *Server) refuseAlone(p principal, rm *dual.Removal, about map[string]string) string {
	detail := rm.Detail()
	maps.Copy(detail, about)
	detail["by"] = p.Name
	s.audit("dual.alone-refused", "/", detail)
	return aloneSentence(rm)
}

// aloneSentence is the refusal as a sentence on a screen.
func aloneSentence(rm *dual.Removal) string {
	why := rm.Refusal()
	return strings.ToUpper(why[:1]) + why[1:] + "."
}

// noteAdministrators is updatePolicy's note of an administrator removed
// (dual.Store.NoteAdministrators), for a server that keeps its policy in
// memory and has nothing else to note it.
func (s *Server) noteAdministrators(before map[string]bool) error {
	if s.Dual == nil || s.Dual.Store == nil {
		return nil
	}
	return s.Dual.Store.NoteAdministrators(before, dual.Administrators(s.Policy), time.Now())
}

// proposeSecond records a privileged change made on a screen. It reports
// whether to make it now, because the proposer is the only administrator,
// and otherwise what to tell them.
func (s *Server) proposeSecond(p principal, kind, what string, payload any, why string) (bool, string, error) {
	if s.Dual == nil || s.Dual.Store == nil {
		return false, "", errors.New("this server keeps no requests for a second administrator, so this change cannot be made here")
	}
	now := time.Now()
	alone := s.onlyAdministrator(p.Name)
	r, err := s.Dual.Store.Propose(kind, what, payload, why, p.Name, alone, now)
	if err != nil {
		return false, "", err
	}
	detail := map[string]string{"by": p.Name, "request": r.ID, "kind": kind, "what": what}
	maps.Copy(detail, r.About())
	if alone {
		detail["alone"] = "true"
		s.audit("dual.approved", "/", detail)
		return true, "", nil
	}
	s.audit("dual.proposed", "/", detail)
	msg := fmt.Sprintf("%s waits for a second administrator, who approves it here (request %s).", what, r.ID)
	// The only administrator, whose request would have been approved as
	// they made it, a moment after another administrator was removed.
	if rm := s.aloneRefusal(p.Name, now); rm != nil {
		msg += " " + s.refuseAlone(p, rm, map[string]string{"request": r.ID, "kind": kind})
	}
	return false, msg, nil
}

// applyDual makes an approved change, as by.
func (s *Server) applyDual(r dual.Request, by string) error {
	switch r.Kind {
	case dual.Grant:
		var ch dual.GrantChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		return s.changePolicy(func(p *auth.Policy) error {
			for _, b := range ch.Bindings {
				if err := p.Grant(b); err != nil {
					return err
				}
			}
			return nil
		})
	case dual.Setting:
		var ch dual.SettingChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		if s.Settings == nil {
			return errors.New("no configuration")
		}
		cfg, err := s.Settings.Load()
		if err != nil {
			return err
		}
		if err := cfg.Set(ch.Key, ch.Value, ch.Reason, r.By); err != nil {
			return err
		}
		return s.Settings.Save(cfg)
	case dual.Mapping:
		var ch dual.MappingChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		if s.SCIM == nil || s.SCIM.Map == nil {
			return errors.New("this server has no provisioning")
		}
		return s.SCIM.Map(ch.Group, ch.To, by)
	case dual.Token, dual.Enrol, dual.SCIMToken:
		// Issued to whoever asked: a token on the command line (quilzo
		// pending redeem), a link or a provisioning token there or on
		// People.
		return nil
	}
	if s.Dual.Apply == nil {
		return fmt.Errorf("request %s is a %s, which this server cannot make", r.ID, r.Kind)
	}
	return s.Dual.Apply(r, by)
}

type pendingRow struct {
	dual.Request
	Words                              string
	CanDecide, CanTakeBack, CanReceive bool
	// Gives is what receiving it gives, in words: the link or the token.
	// The button said "the link" for a provisioning token too, which gives
	// no link.
	Gives string
	// Mapping says this is a group mapped to make administrators, and
	// Tokens are the provisioning tokens approving it lets make them, or
	// TokensUnread why they could not be read.
	//
	// A token made while no group made administrators was made by one
	// person, rightly, and stays valid once such a mapping is approved;
	// whoever approved the mapping here could not see it.
	Mapping      bool
	Tokens       []scim.LiveToken
	TokensUnread string
}

// pendingRows are the requests waiting, for the People screen, with what p
// may do about each.
func (s *Server) pendingRows(p principal, now time.Time) []pendingRow {
	if s.Dual == nil || s.Dual.Store == nil {
		return nil
	}
	pend, err := s.Dual.Store.Pending(now)
	if err != nil {
		return nil
	}
	alone := s.onlyAdministrator(p.Name)
	var out []pendingRow
	var tokens []scim.LiveToken
	var unread error
	read := false
	for _, r := range pend {
		mine := strings.EqualFold(r.By, p.Name)
		row := pendingRow{Request: r, Words: dual.StateWords(r, now),
			CanDecide: r.Open(now) && (!mine || alone), CanTakeBack: mine,
			CanReceive: mine && r.Redeemable(now) && receivedHere(r),
			Gives:      map[bool]string{true: "the link", false: "the token"}[r.Kind == dual.Enrol]}
		if r.Kind == dual.Mapping {
			if !read {
				tokens, unread = s.liveTokens()
				read = true
			}
			row.Mapping, row.Tokens = true, tokens
			if unread != nil {
				row.TokensUnread = unread.Error()
			}
		}
		out = append(out, row)
	}
	return out
}

// mappedTokens is, for the only administrator who has just mapped a group
// to make administrators and so approved it alone, which provisioning
// tokens now make them, as People lists them under the request for a
// second administrator. Nothing waited, so nothing was shown, and a token
// made before any group made administrators went on working as a way to
// make them.
func (s *Server) mappedTokens() string {
	live, err := s.liveTokens()
	switch {
	case err != nil:
		return "This lets the provisioning token make administrators, and which tokens work could not be read: " +
			err.Error() + "."
	case len(live) == 0:
		return "No provisioning token works now; one made from now on asks a second administrator, when there is one."
	}
	words := make([]string, 0, len(live))
	for _, t := range live {
		words = append(words, t.Words())
	}
	return "This lets the provisioning token make administrators: " + strings.Join(words, "; ") +
		". If that is not who should hold it, revoke it here."
}

// liveTokens are the provisioning tokens that work now.
func (s *Server) liveTokens() ([]scim.LiveToken, error) {
	if s.SCIM == nil || s.SCIM.LiveTokens == nil {
		return nil, errors.New("this build cannot say which provisioning tokens work")
	}
	return s.SCIM.LiveTokens()
}

// handlePeoplePending approves, declines or withdraws a request.
func (s *Server) handlePeoplePending(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return
	}
	if s.Dual == nil || s.Dual.Store == nil {
		http.NotFound(w, r)
		return
	}
	id, do := strings.TrimSpace(r.FormValue("id")), r.FormValue("do")
	now := time.Now()
	var req dual.Request
	var err error
	switch do {
	case "approve", "decline":
		// Their own request, approved alone: not for a day after another
		// administrator stopped being one.
		if mine, gerr := s.Dual.Store.Get(id); do == "approve" && gerr == nil && strings.EqualFold(mine.By, p.Name) {
			if rm := s.aloneRefusal(p.Name, now); rm != nil {
				s.peopleBack(w, r, s.refuseAlone(p, rm, map[string]string{"request": mine.ID, "kind": mine.Kind}))
				return
			}
		}
		req, err = s.Dual.Store.Decide(id, p.Name, do == "approve", s.onlyAdministrator(p.Name), now)
		if err == nil && do == "approve" {
			if aerr := s.applyDual(req, p.Name); aerr != nil {
				err = fmt.Errorf("approved, and making the change failed: %w", aerr)
			}
		}
	case "withdraw":
		req, err = s.Dual.Store.Withdraw(id, p.Name, now)
	case "receive":
		s.receiveCredential(w, r, p, id, now)
		return
	default:
		err = errors.New("approve, decline or withdraw?")
	}
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	detail := map[string]string{"by": p.Name, "request": req.ID, "kind": req.Kind, "what": req.What, "proposed_by": req.By}
	maps.Copy(detail, req.About())
	if req.Alone {
		detail["alone"] = "true"
	}
	s.audit(map[string]string{"approve": "dual.approved", "decline": "dual.declined", "withdraw": "dual.withdrawn"}[do], "/", detail)
	msg := req.What + ": " + dual.StateWords(req, now) + "."
	if do == "approve" && req.Kind == dual.Token {
		msg += " " + req.By + " receives it with quilzo pending redeem " + req.ID + ", within a day."
	}
	if do == "approve" && dual.Received(req.Kind) && req.Kind != dual.Token {
		if receivedHere(req) {
			msg += " " + req.By + " receives it here, within a day."
		} else {
			msg += " " + req.By + " receives it with quilzo pending redeem " + req.ID + ", within a day."
		}
	}
	s.peopleBack(w, r, msg)
}

// receivedHere reports whether an approved request is received on People:
// an enrolment link, and a provisioning token asked for here. A token, and
// a provisioning token asked for on the command line for a number of days
// the screen cannot make, are received with quilzo pending redeem.
func receivedHere(r dual.Request) bool {
	switch r.Kind {
	case dual.Enrol:
		return true
	case dual.SCIMToken:
		var ch dual.SCIMTokenChange
		return json.Unmarshal(r.Payload, &ch) == nil && ch.Days == 0
	}
	return false
}

// receiveCredential gives whoever asked for an enrolment link or a
// provisioning token what they asked for, once another administrator has
// approved it, and only them.
func (s *Server) receiveCredential(w http.ResponseWriter, r *http.Request, p principal, id string, now time.Time) {
	// Asked before it is redeemed, so nothing is used up here that cannot
	// be given here.
	req, err := s.Dual.Store.Get(id)
	if err == nil && !receivedHere(req) {
		err = fmt.Errorf("request %s is not received here: quilzo pending redeem %s", req.ID, req.ID)
	}
	var ch dual.EnrolChange
	switch {
	case err != nil:
	case req.Kind == dual.Enrol && s.Enrol == nil:
		err = errors.New("this server was started without enrolment links")
	case req.Kind == dual.Enrol:
		if err = json.Unmarshal(req.Payload, &ch); err == nil && len(s.heldBy(ch.Principal)) == 0 {
			err = errors.New("a passkey would sign " + ch.Principal + " in to nothing now: they hold nothing here")
		}
	case s.SCIM == nil || s.SCIM.NewToken == nil:
		err = errors.New("this build has no provisioning")
	}
	if err == nil {
		req, err = s.Dual.Store.Redeem(id, p.Name, now)
	}
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	detail := map[string]string{"by": p.Name, "request": req.ID, "kind": req.Kind, "approved_by": req.DecidedBy}
	maps.Copy(detail, req.About())
	s.audit("dual.redeemed", "/", detail)
	if req.Kind == dual.Enrol {
		s.giveEnrolLink(w, r, p, ch.Principal, ch.For)
		return
	}
	made := scim.TokenMade{By: p.Name, Approval: scim.ByTwo, ApprovedBy: req.DecidedBy}
	if req.Alone {
		made = scim.TokenMade{By: p.Name, Approval: scim.Alone}
	}
	token, err := s.SCIM.NewToken(made)
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	// Shown in this response and never again, as on Provisioning.
	s.renderProvisioning(w, r, p, token)
}
