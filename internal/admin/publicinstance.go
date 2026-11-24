// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/auth"
)

// PublicInstance is the Public instance screen: where the public instance
// is, the key it pins, the attestations it is to show, and their
// publication, which one administrator proposes and another approves on
// People (internal/outpost, internal/attest).
type PublicInstance struct {
	View      func() (PublicView, error)
	SetTarget func(to string, by Actor) error
	SetDraft  func(body []byte, by Actor) error
	// Propose asks for the draft to be published; sent is true only when
	// the proposer is the only administrator, and approved alone.
	Propose func(reason string, by Actor) (sent bool, err error)
	// Resend sends what was published again, with a fresh head.
	Resend func(reason string, by Actor) error
	// Keys is the published head keys, the file the public instance pins.
	Keys func() ([]byte, error)
}

// PublicView is the public instance as the screen shows it.
type PublicView struct {
	Target, KeyID string
	Draft         *attest.File
	// DraftText is the draft as a file, for the editor.
	DraftText       string
	Digest, Problem string
	Sent            *PublicSent
	Waiting         string
}

// PublicSent is the last transfer sent.
type PublicSent struct {
	Digest, To, ApprovedBy string
	At                     time.Time
	Alone                  bool
	Head                   int
}

func (s *Server) handlePublicInstance(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	data := map[string]any{"Nav": "security", "Title": "Public instance", "Principal": p,
		"Message": q.Get("m"), "Error": q.Get("e"), "Field": q.Get("f")}
	if s.PublicInstance == nil || s.PublicInstance.View == nil {
		data["Off"] = true
		s.render(w, r, "publicinstance.html", data)
		return
	}
	v, err := s.PublicInstance.View()
	if err != nil {
		data["Error"] = err.Error()
	}
	data["View"] = v
	data["CanChange"] = s.allows(p, auth.ActGrant, "/")
	data["Published"] = v.Sent != nil && v.Sent.Digest == v.Digest
	s.render(w, r, "publicinstance.html", data)
}

// handlePublicInstanceAct sets where the instance is, keeps a draft,
// proposes a publication or sends the last one again, for an
// administrator.
func (s *Server) handlePublicInstanceAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	op := r.FormValue("op")
	back := func(k, v, field string) {
		to := "/security/public?" + k + "=" + url.QueryEscape(v)
		if field != "" {
			to += "&f=" + url.QueryEscape(field) + "#" + field
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
	}
	pi := s.PublicInstance
	if pi == nil {
		back("e", "the public instance is not wired up in this build", "")
		return
	}
	switch op {
	case "target":
		to := strings.TrimSpace(r.FormValue("to"))
		if to == "" {
			back("e", "Give the public instance's address, or an absolute directory to carry transfers from.", "to")
			return
		}
		if err := pi.SetTarget(to, p.actor()); err != nil {
			back("e", err.Error(), "to")
			return
		}
		back("m", "Transfers go to "+to+".", "")
	case "draft":
		body := strings.TrimSpace(r.FormValue("draft"))
		if body == "" {
			back("e", "Give the attestations, as a file of format 1.", "draft")
			return
		}
		if err := pi.SetDraft([]byte(body), p.actor()); err != nil {
			back("e", err.Error(), "draft")
			return
		}
		back("m", "The draft is kept. Two administrators publish it: propose it below.", "")
	case "publish":
		reason := strings.TrimSpace(r.FormValue("reason"))
		if reason == "" {
			back("e", "Give a reason: publishing speaks for the organisation, and the record keeps why.", "reason")
			return
		}
		sent, err := pi.Propose(reason, p.actor())
		if err != nil {
			back("e", err.Error(), "reason")
			return
		}
		if sent {
			back("m", "Published. You are the only administrator, so it was approved alone, and the record says so.", "")
			return
		}
		back("m", "Proposed. It waits for a second administrator, who approves it on People.", "")
	case "resend":
		if err := pi.Resend(strings.TrimSpace(r.FormValue("why")), p.actor()); err != nil {
			back("e", err.Error(), "why")
			return
		}
		back("m", "Sent again, with a fresh head of the record.", "")
	default:
		back("e", "choose what to do", "")
	}
}

// handlePublicInstanceKeys is the published head keys, to copy to the
// public host and pin there.
func (s *Server) handlePublicInstanceKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.assuranceReader(w, r); !ok {
		return
	}
	if s.PublicInstance == nil || s.PublicInstance.Keys == nil {
		http.Error(w, "this build publishes no keys", http.StatusServiceUnavailable)
		return
	}
	body, err := s.PublicInstance.Keys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="head.pub.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
