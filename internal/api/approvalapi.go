// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// The approvals of the security record, read: what waits for its
// approvers, one decision as an approver is shown it with the hash of what
// it shows, and the separation policy. The same reads as `quilzo approval`
// and the admin's Sign-off, asked about the register's area.
//
// Nothing here approves. An approval is a person's fresh passkey assertion
// over the hash of exactly what they were shown, and a program calling the
// API shows a person nothing; a module's routes answer GET alone, and a
// POST to any of them is refused with the methods allowed. Each decision
// says where it is approved instead.

func init() {
	list := op("What in the security record waits for its approvers, and the decisions held with theirs",
		"approvalList", nil, nil,
		map[string]any{"200": answer("Each waiting decision with its rule, how many approvals it needs of how many "+
			"eligible and the hash of what it shows; each held decision with where it stands.",
			map[string]any{"type": "object"})})
	one := op("One waiting decision as an approver is shown it", "approvalShow", []any{
		param("id", "path", "the decision's identifier: 32 hexadecimal characters", true, str)}, nil,
		map[string]any{"200": answer("The decision, what it cites and changes, the hash of all of it, and where it is "+
			"approved: in the admin with a passkey, or at the store's console.", map[string]any{"type": "object"})}, "404")
	policy := op("The organisation's separation policy", "approvalPolicy", nil, nil,
		map[string]any{"200": answer("Who may approve each kind of decision, at which level, and how many of them; and "+
			"whether it was declared or is the default.", map[string]any{"type": "object"})})
	registerRoutes(apiModule{
		module: "approval",
		routes: []apiRoute{
			{path: "/api/v1/approvals", handle: (*Server).approvalList,
				describe: map[string]map[string]any{"/api/v1/approvals": {"get": list}}},
			{path: "/api/v1/approvals/policy", handle: (*Server).approvalPolicy,
				describe: map[string]map[string]any{"/api/v1/approvals/policy": {"get": policy}}},
			{path: "/api/v1/approvals/", handle: (*Server).approvalShow,
				describe: map[string]map[string]any{"/api/v1/approvals/{id}": {"get": one}}},
		},
	})
}

// approvalsReadable is the approvals, for a caller who may read the
// register, or the refusal written.
func (s *Server) approvalsReadable(w http.ResponseWriter, r *http.Request) (*approval.Approvals, bool) {
	if err := s.may(r, auth.ActView, register.Area); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted", Detail: err.Error(),
			Fix: "the register is the compliance area's: ask for a role there"})
		return nil, false
	}
	return &approval.Approvals{Root: s.Store.Root(), Register: register.Open(s.Store), Access: s.Policy}, true
}

// approveAt is where a person approves a decision, said with it.
func approveAt(id register.ID, hash register.Digest) string {
	return "in the admin at /register/approvals/item/" + string(id) + ", with a passkey; or at the store's console: " +
		"quilzo approval approve " + string(id) + " --surface " + string(hash)
}

func (s *Server) approvalList(w http.ResponseWriter, r *http.Request) {
	m, ok := s.approvalsReadable(w, r)
	if !ok {
		return
	}
	waiting, err := m.Waiting()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	held, err := m.Held()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	type item struct {
		ID      register.ID     `json:"id"`
		Kind    register.Kind   `json:"kind"`
		Label   string          `json:"label"`
		Rule    string          `json:"rule"`
		Needed  int             `json:"needed"`
		Of      int             `json:"of"`
		Signed  int             `json:"signed"`
		Surface register.Digest `json:"surface"`
		Approve string          `json:"approve"`
	}
	out := []item{}
	for _, a := range waiting {
		out = append(out, item{ID: a.Proposal.ID, Kind: a.Proposal.Kind, Label: register.Label(a.Proposal.Record), Rule: a.Rule.Name,
			Needed: a.Needed, Of: a.Of, Signed: len(a.Signed), Surface: a.Hash, Approve: approveAt(a.Proposal.ID, a.Hash)})
	}
	if held == nil {
		held = []approval.Held{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"waiting": out, "held": held})
}

func (s *Server) approvalShow(w http.ResponseWriter, r *http.Request) {
	m, ok := s.approvalsReadable(w, r)
	if !ok {
		return
	}
	id := register.ID(strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/"))
	a, err := m.Ask(id)
	if errors.Is(err, register.ErrNotFound) || errors.Is(err, approval.ErrRefused) || !id.Valid() {
		writeError(w, http.StatusNotFound, Error{Error: "nothing with that identifier waits for an approval",
			Fix: "GET /api/v1/approvals lists what waits, with the identifiers"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": a.Proposal.ID, "kind": a.Proposal.Kind, "rule": a.Rule.Name,
		"atom": a.Rule.Atom, "who": a.Rule.Describe(), "needed": a.Needed, "of": a.Of, "over": a.Over,
		"signed": len(a.Signed), "surface": a.Hash, "shown": a.Surface, "expires": a.Expires,
		"approve": approveAt(a.Proposal.ID, a.Hash)})
}

func (s *Server) approvalPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.approvalsReadable(w, r); !ok {
		return
	}
	pol, declared, err := approval.LoadPolicy(s.Store.Root())
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the separation policy could not be read", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"declared": declared, "policy": pol})
}
