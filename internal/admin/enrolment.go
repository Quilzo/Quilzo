// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/enrol"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// Adding a first passkey through a one-time link (internal/enrol).
//
// The link is the whole of the authority: it names one person, it is used
// once, it ends within a day, and what it reaches is these three routes,
// which add a passkey for that person and do nothing else. No session is
// made here; the person signs in with the passkey they have just added.

// enrolStart is the path the links are served under.
const enrolStart = "/enrol/"

func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	if s.Enrol == nil || s.Passkeys == nil {
		http.NotFound(w, r)
		return
	}
	// The secret is in the address: nothing from this page goes anywhere
	// that would be told it, and nothing keeps a copy.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	switch rest := strings.TrimPrefix(r.URL.Path, enrolStart); rest {
	case "challenge":
		s.handleEnrolChallenge(w, r)
	case "register":
		s.handleEnrolRegister(w, r)
	default:
		s.handleEnrolPage(w, r, rest)
	}
}

// enrolLink is the live link a request names, counted as a failure when it
// names none, so the links cannot be guessed at. When there is none, the
// answer has been written, as a page or as JSON.
func (s *Server) enrolLink(w http.ResponseWriter, r *http.Request, secret string, page bool) (enrol.Link, bool) {
	refuse := func(code int, err error) (enrol.Link, bool) {
		if page {
			w.WriteHeader(code)
			s.render(w, r, "enrol.html", map[string]any{"Title": "Add a passkey", "Gone": err.Error()})
		} else {
			writeJSONError(w, code, err)
		}
		return enrol.Link{}, false
	}
	sub := throttle.Subject{Source: sourceOf(r), Principal: "enrol"}
	if s.Throttle != nil {
		if d := s.Throttle.Check(sub); !d.Allowed {
			return refuse(http.StatusTooManyRequests, errors.New(d.Why))
		}
	}
	if s.EnrolBlocked != nil {
		if why := s.EnrolBlocked(time.Now()); why != "" {
			return refuse(http.StatusServiceUnavailable, errors.New(why))
		}
	}
	l, err := s.Enrol.Peek(secret, time.Now())
	if err != nil {
		if s.Throttle != nil {
			if d, alert := s.Throttle.Fail(sub); alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
		}
		s.audit("enrol.refused", "/", map[string]string{"source": sub.Source})
		return refuse(http.StatusNotFound, enrol.ErrNoLink)
	}
	return l, true
}

func (s *Server) handleEnrolPage(w http.ResponseWriter, r *http.Request, secret string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}
	l, ok := s.enrolLink(w, r, secret, true)
	if !ok {
		return
	}
	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}
	s.passkeyPolicy(w, n)
	s.render(w, r, "enrol.html", map[string]any{"Title": "Add a passkey", "Who": l.Principal,
		"Secret": secret, "Nonce": n, "Ends": l.Expires.UTC().Format("15:04 UTC on 2 January")})
}

func (s *Server) handleEnrolChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Secret string `json:"secret"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	l, ok := s.enrolLink(w, r, body.Secret, false)
	if !ok {
		return
	}
	party, err := s.partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	v, err := s.Passkeys.issueChallenge(l.Principal, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{
		"challenge":   v,
		"attestation": s.enrolment().AttestationPreference(),
		"rp":          map[string]string{"id": party.ID, "name": s.SiteName},
		"user": map[string]string{
			"id":   base64.RawURLEncoding.EncodeToString([]byte(l.Principal)),
			"name": l.Principal, "displayName": l.Principal,
		},
		"exclude": credentialIDs(s.Passkeys.list(), l.Principal),
	})
}

func (s *Server) handleEnrolRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		webauthn.Registration
		Secret    string `json:"secret"`
		Challenge string `json:"challenge"`
		Label     string `json:"label"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	l, ok := s.enrolLink(w, r, body.Secret, false)
	if !ok {
		return
	}
	party, err := s.partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	c, found := s.Passkeys.takeChallenge(body.Challenge, time.Now())
	if !found || c.principal != l.Principal {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("this ceremony's challenge is unknown, has expired, "+
			"or was issued for somebody else. Start again"))
		return
	}
	party.Enrol = s.enrolment()
	cred, err := party.Register(c.value, body.Registration)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	if _, exists := s.Passkeys.lookup(cred.ID); exists {
		writeJSONError(w, http.StatusConflict, fmt.Errorf("this key is already registered"))
		return
	}
	// Used before the key is kept: a link that added one passkey must not
	// add a second, whatever happens after.
	if _, err := s.Enrol.Take(body.Secret, time.Now()); err != nil {
		writeJSONError(w, http.StatusNotFound, enrol.ErrNoLink)
		return
	}
	cred.Principal = l.Principal
	cred.Label = strings.TrimSpace(body.Label)
	if cred.Label == "" {
		cred.Label = "a passkey"
	}
	cred.CreatedAt = time.Now().Unix()
	if err := s.Passkeys.add(StoredCredential{Credential: cred, RelyingParty: party.ID}); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errPasskeyExists) {
			code = http.StatusConflict
		}
		writeJSONError(w, code, err)
		return
	}
	// Who it was for, and who gave the link, so a key added through a link
	// that should not have been given can be found again.
	s.audit("passkey.enrolled", "/", map[string]string{"by": l.Principal, "via": "enrolment link",
		"link_by": l.By, "label": cred.Label})
	writeJSON(w, map[string]any{"ok": true, "next": "/signin/passkey"})
}
