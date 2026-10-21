// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
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
// approve: nobody else administers the whole site.
func (s *Server) onlyAdministrator(name string) bool {
	if s.Policy == nil {
		return true
	}
	admins := map[string]bool{}
	for _, b := range s.Policy.Snapshot() {
		if !b.Deny && b.Role == auth.RoleAdmin && s.Policy.Evaluate(b.Principal, auth.ActGrant, "/").Allowed {
			admins[strings.ToLower(b.Principal)] = true
		}
	}
	return len(admins) == 0 || (len(admins) == 1 && admins[strings.ToLower(name)])
}

// proposeSecond records a privileged change made on a screen. It reports
// whether to make it now, because the proposer is the only administrator,
// and otherwise what to tell them.
func (s *Server) proposeSecond(p principal, kind, what string, payload any, why string) (bool, string, error) {
	if s.Dual == nil || s.Dual.Store == nil {
		return false, "", errors.New("this server keeps no requests for a second administrator, so this change cannot be made here")
	}
	alone := s.onlyAdministrator(p.Name)
	r, err := s.Dual.Store.Propose(kind, what, payload, why, p.Name, alone, time.Now())
	if err != nil {
		return false, "", err
	}
	detail := map[string]string{"by": p.Name, "request": r.ID, "kind": kind, "what": what}
	if alone {
		detail["alone"] = "true"
		s.audit("dual.approved", "/", detail)
		return true, "", nil
	}
	s.audit("dual.proposed", "/", detail)
	return false, fmt.Sprintf("%s waits for a second administrator, who approves it here (request %s).", what, r.ID), nil
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
	case dual.Token:
		// Issued to whoever asked, on the command line: quilzo pending redeem.
		return nil
	}
	if s.Dual.Apply == nil {
		return fmt.Errorf("request %s is a %s, which this server cannot make", r.ID, r.Kind)
	}
	return s.Dual.Apply(r, by)
}

type pendingRow struct {
	dual.Request
	Words                  string
	CanDecide, CanTakeBack bool
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
	for _, r := range pend {
		mine := strings.EqualFold(r.By, p.Name)
		out = append(out, pendingRow{Request: r, Words: dual.StateWords(r, now),
			CanDecide: r.Open(now) && (!mine || alone), CanTakeBack: mine})
	}
	return out
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
		req, err = s.Dual.Store.Decide(id, p.Name, do == "approve", s.onlyAdministrator(p.Name), now)
		if err == nil && do == "approve" {
			if aerr := s.applyDual(req, p.Name); aerr != nil {
				err = fmt.Errorf("approved, and making the change failed: %w", aerr)
			}
		}
	case "withdraw":
		req, err = s.Dual.Store.Withdraw(id, p.Name, now)
	default:
		err = errors.New("approve, decline or withdraw?")
	}
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	detail := map[string]string{"by": p.Name, "request": req.ID, "kind": req.Kind, "what": req.What, "proposed_by": req.By}
	if req.Alone {
		detail["alone"] = "true"
	}
	s.audit(map[string]string{"approve": "dual.approved", "decline": "dual.declined", "withdraw": "dual.withdrawn"}[do], "/", detail)
	msg := req.What + ": " + dual.StateWords(req, now) + "."
	if do == "approve" && req.Kind == dual.Token {
		msg += " " + req.By + " receives it with quilzo pending redeem " + req.ID + ", within a day."
	}
	s.peopleBack(w, r, msg)
}
