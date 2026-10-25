// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/travel"
)

// The sign-in check, "Confirm it's you", and the Sign-ins screen.
//
// Every sign-in to this admin — token, passkey or single sign-on — is put
// to SignInRisk once the session exists and before the person gets it. If
// the sign-in policy says so (cmd/quilzo/signinpolicy.go), the session is
// marked as having to prove its person, and every page sends them to
// "Confirm it's you" until they do: with a passkey, with a fresh single
// sign-on, or by an administrator letting them in from the Sign-ins screen.

// SignInFacts is what the check is told about a sign-in.
type SignInFacts struct {
	Principal string
	Role      auth.Role
	How       string // token, passkey, sso
	Addr      string
	Agent     string
	// Verifying is a sign-in made to prove a stepped-up session's person:
	// it is recorded, and never stepped up itself.
	Verifying bool
}

// SignInVerdict is what the check decided.
type SignInVerdict struct {
	StepUp bool
	Reason string
}

// SessionContext is where a request comes from, as a session is bound to:
// the kind of device and the country.
type SessionContext struct {
	Device, Country string
}

// String is the binding as the token store keeps it.
func (c SessionContext) String() string { return c.Device + "|" + c.Country }

// SessionMove is a session seen somewhere other than where it was issued.
type SessionMove struct {
	Principal string
	Role      auth.Role
	From, To  SessionContext
	Addr      string
}

// SignInHistory is where people signed in from, as the Sign-ins screen
// reaches it.
type SignInHistory struct {
	// Recent lists recent sign-ins, everybody's, newest first.
	Recent func(since time.Time) ([]travel.Recent, error)
	// Geo says where locations come from, in a sentence.
	Geo func() string
}

// clientAddr is the address a sign-in came from, for placing it: the
// client the edge decided (internal/clientip), which believes a forwarded
// address only from a proxy the deployment named.
func (s *Server) clientAddr(r *http.Request) string { return clientip.AddrFrom(r) }

// signInCheck puts a new session's sign-in to the policy, and marks the
// session when it says it must prove its person. It says whether it
// did, so the caller sends the person to verify rather than in.
//
// When the policy decided a step-up and it could not be written down, the
// session is ended and the error returned, and the sign-in is refused: a
// session that should have been stepped up and was let in is the one
// outcome this must never have. (Whether the policy could decide at all is
// its to report: an unreadable history lets sign-ins through and says so
// loudly, rather than locking every administrator out.)
func (s *Server) signInCheck(r *http.Request, name, sessionID, how string, verifying bool) (bool, error) {
	up, err := s.signInRisk(r, name, sessionID, how, verifying)
	// A passkey or single sign-on nothing held back is an administrator
	// where they are: the shield never blocks that source from the admin.
	if err == nil && !up && (how == "passkey" || how == "sso") && s.OnStrongSignIn != nil {
		s.OnStrongSignIn(r, name)
	}
	return up, err
}

// signInRisk puts a sign-in to the sign-in policy.
func (s *Server) signInRisk(r *http.Request, name, sessionID, how string, verifying bool) (bool, error) {
	if s.SignInRisk == nil {
		return false, nil
	}
	v := s.SignInRisk(SignInFacts{Principal: name, Role: s.roleFor(name), How: how,
		Addr: s.clientAddr(r), Agent: r.UserAgent(), Verifying: verifying})
	if !v.StepUp || verifying {
		return false, nil
	}
	err := s.Tokens.RequireStepUp(sessionID, v.Reason)
	if err == nil && s.SaveTokens != nil {
		err = s.SaveTokens(s.Tokens)
	}
	if err != nil {
		_, _ = s.Tokens.Revoke(sessionID)
		if s.SaveTokens != nil {
			_ = s.SaveTokens(s.Tokens)
		}
		s.audit("session.stepup-unrecorded", "/", map[string]string{"by": name, "session": sessionID, "error": err.Error()})
		return false, fmt.Errorf("this sign-in has to be confirmed and that could not be recorded, so it was refused: %w", err)
	}
	s.audit("session.stepup-required", "/", map[string]string{"by": name, "session": sessionID, "reason": v.Reason})
	return true, nil
}

// signInDone binds a new session, whatever the check decided.
func (s *Server) signInDone(r *http.Request, sessionID string) { s.bindSession(r, sessionID) }

// bindSession records where a new session was issued to, so a copy of it
// used elsewhere can be noticed. Best effort: a session not bound is one
// that is not watched for moving, never one that is refused.
func (s *Server) bindSession(r *http.Request, sessionID string) {
	if s.SessionPlace == nil {
		return
	}
	c := s.SessionPlace(s.clientAddr(r), r.UserAgent())
	if c.Device == "" {
		return
	}
	if err := s.Tokens.BindSession(sessionID, c.String()); err == nil && s.SaveTokens != nil {
		_ = s.SaveTokens(s.Tokens)
	}
}

var (
	movedMu   sync.Mutex
	movedSeen = map[string]string{} // session -> the context last judged
)

// sessionMoved checks a request against its session's binding, and when
// it has moved — another kind of device, or another country — puts it to
// the policy once per new context. It says why, when the policy stepped
// the session up. Only the device kind and the country count: a phone moves
// between networks all day, and an address change alone is not a move.
func (s *Server) sessionMoved(r *http.Request, p principal) string {
	if s.SessionPlace == nil || s.SessionMovedTo == nil {
		return ""
	}
	device, country, _ := strings.Cut(p.Bound, "|")
	now := s.SessionPlace(s.clientAddr(r), r.UserAgent())
	moved := (now.Device != "" && device != "" && now.Device != device) ||
		(now.Country != "" && country != "" && now.Country != country)
	if !moved {
		return ""
	}
	key := now.String()
	movedMu.Lock()
	if movedSeen[p.TokenID] == key {
		movedMu.Unlock()
		return ""
	}
	movedSeen[p.TokenID] = key
	movedMu.Unlock()
	from := SessionContext{Device: device, Country: country}
	v := s.SessionMovedTo(SessionMove{Principal: p.Name, Role: s.roleFor(p.Name), From: from, To: now, Addr: s.clientAddr(r)})
	s.audit("session.moved", "/", map[string]string{"by": p.Name, "session": p.TokenID,
		"from": from.String(), "to": now.String()})
	if !v.StepUp {
		return ""
	}
	err := s.Tokens.RequireStepUp(p.TokenID, v.Reason)
	if err == nil && s.SaveTokens != nil {
		err = s.SaveTokens(s.Tokens)
	}
	if err != nil {
		// The policy said to stop it and that could not be written down:
		// end it rather than let it carry on.
		_, _ = s.Tokens.Revoke(p.TokenID)
		if s.SaveTokens != nil {
			_ = s.SaveTokens(s.Tokens)
		}
		return "this session moved and could not be held, so it was ended"
	}
	return v.Reason
}

// stepUpOpen is what a session waiting to prove its person may still reach.
func stepUpOpen(path string) bool {
	switch {
	case path == "/signin/verify", strings.HasPrefix(path, "/signin/verify/"),
		path == "/signin/passkey", strings.HasPrefix(path, "/signin/passkey/"),
		path == "/signout":
		return true
	}
	return false
}

// -- confirm it's you ---------------------------------------------------------

// stepUpFails counts failed passkey confirmations by a session asked to
// confirm it is its person: the third raises verification-failing, and the
// security contact is told nothing could be proved.
var (
	stepUpFailsMu sync.Mutex
	stepUpFails   = map[string]int{}
)

// stepUpFailed notes a failed confirmation from the session r carries, if
// it is one asked to confirm, and returns whose session it is ("" when it
// is not one).
func (s *Server) stepUpFailed(r *http.Request) string {
	p, err := s.authenticate(r)
	if err != nil || p.StepUp == "" {
		return ""
	}
	stepUpFailsMu.Lock()
	stepUpFails[p.TokenID]++
	third := stepUpFails[p.TokenID] == 3
	if len(stepUpFails) > 10000 {
		stepUpFails = map[string]int{p.TokenID: stepUpFails[p.TokenID]}
	}
	stepUpFailsMu.Unlock()
	s.audit("session.stepup-failed", "/", map[string]string{"by": p.Name, "session": p.TokenID})
	if third && s.SignInSignal != nil {
		s.SignInSignal(p.Name, "verification-failing", "three failed passkey confirmations from a session asked to confirm it is them")
	}
	return p.Name
}

func (s *Server) verifyPrincipal(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, err := s.authenticate(r)
	if err != nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return principal{}, false
	}
	if p.StepUp == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return principal{}, false
	}
	return p, true
}

func (s *Server) hasPasskey(name string) bool {
	if s.Passkeys == nil {
		return false
	}
	for _, c := range s.Passkeys.Credentials {
		if strings.EqualFold(c.Principal, name) {
			return true
		}
	}
	return false
}

func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request) {
	p, err := s.authenticate(r)
	if err != nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	if p.StepUp == "" {
		// Nothing to confirm: say so, rather than send them somewhere.
		s.render(w, r, "verify.html", map[string]any{"Title": "Confirm it's you", "Who": p.Name, "Clear": true})
		return
	}
	s.render(w, r, "verify.html", map[string]any{
		"Title": "Confirm it's you", "Who": p.Name, "Reason": p.StepUp,
		"Passkey": s.hasPasskey(p.Name), "FirstFactor": p.Level < 2,
		// Signing on again cannot help a sign-on that said it used one
		// factor: it would say so again.
		"SingleSignOn": (s.OIDC != nil || len(s.ssoChoices()) > 0) && !hasMethod(p.Methods, auth.MethodSSOOneFactor),
		"Error":        r.URL.Query().Get("e"),
	})
}

// handleStepUpReport is the person saying the sign-in was not them. The
// session ends at once, and the policy hears it: a person who knows a
// sign-in was not theirs is the best detector there is.
func (s *Server) handleStepUpReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.verifyPrincipal(w, r)
	if !ok {
		return
	}
	_, _ = s.Tokens.Revoke(p.TokenID)
	if s.SaveTokens != nil {
		_ = s.SaveTokens(s.Tokens)
	}
	s.audit("session.reported", "/", map[string]string{"by": p.Name, "session": p.TokenID, "reason": p.StepUp})
	if s.Reported != nil {
		s.Reported(p.Name, p.TokenID)
	}
	s.clearCookie(w, r, "quilzo_token")
	http.Redirect(w, r, "/signin?e=reported", http.StatusSeeOther)
}

func (s *Server) passStepUp(w http.ResponseWriter, r *http.Request, p principal, how string) {
	if err := s.Tokens.ClearStepUp(p.TokenID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.audit("session.stepup-passed", "/", map[string]string{"by": p.Name, "session": p.TokenID, "how": how})
	http.Redirect(w, r, startPath(r), http.StatusSeeOther)
}

// -- sign-ins -------------------------------------------------------------------

type signInRow struct {
	Person, When, Place, How, Network string
	Provider, Device, Risk, RiskTone  string
	Score                             string
	Signals                           []string
}

// signalWords are the signals as somebody reads them.
var signalWords = map[string]string{
	"impossible-travel": "impossible travel", "new-country": "new country", "new-device": "new kind of device",
	"new-network": "new network provider", "new-ip": "new address", "anonymous-network": "Tor",
	"hosting-network": "hosting provider", "dormant": "back after months", "unusual-hour": "unusual hour",
	"session-moved": "session moved", "verification-failing": "verification failing",
	"account-locked": "locked out after failed sign-ins",
}

var riskTone = map[string]string{"high": "critical", "medium": "warning", "low": "low", "none": "good", "": "good"}

type waitingRow struct {
	Person, Session, Reason, Since string
}

func (s *Server) handleSignIns(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Sign-ins", "Nav": "signins", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	// Who is waiting comes from the sessions themselves, whatever else is
	// wired in.
	var waiting []waitingRow
	now := time.Now()
	for _, t := range s.Tokens.Snapshot() {
		if t.StepUp != "" && !t.Revoked && (t.ExpiresAt == 0 || now.Unix() < t.ExpiresAt) {
			waiting = append(waiting, waitingRow{Person: t.Principal, Session: t.ID, Reason: t.StepUp,
				Since: time.Unix(t.CreatedAt, 0).UTC().Format("2 Jan 15:04")})
		}
	}
	data["Waiting"] = waiting
	data["Held"] = s.heldRows(now)
	if s.SignIns == nil || s.SignIns.Recent == nil {
		data["NoHistory"] = "This build was started without sign-in checks, so where people signed in from is not kept."
		s.render(w, r, "signins.html", data)
		return
	}
	if s.SignIns.Geo != nil {
		data["Geo"] = s.SignIns.Geo()
	}
	recent, err := s.SignIns.Recent(time.Now().Add(-30 * 24 * time.Hour))
	if err != nil {
		data["NoHistory"] = err.Error()
		s.render(w, r, "signins.html", data)
		return
	}
	var rows []signInRow
	for i, in := range recent {
		if i >= 200 {
			break
		}
		row := signInRow{Person: in.Person, When: in.At.Format("2 Jan 15:04"), Place: in.Place.String(),
			How: in.How, Network: in.Place.Kind, Provider: in.Network, Device: in.Device,
			Risk: in.Risk, RiskTone: riskTone[in.Risk]}
		if row.Risk == "" {
			row.Risk = "none"
		}
		if in.Score != 0 {
			row.Score = fmt.Sprintf("How unusual, in bits of surprise: %.1f", in.Score)
		}
		for _, sg := range in.Signals {
			row.Signals = append(row.Signals, signalWords[sg])
		}
		rows = append(rows, row)
	}
	data["Rows"] = rows
	s.render(w, r, "signins.html", data)
}

// handleSignInsAct lets somebody in, or signs them out, from Sign-ins.
func (s *Server) handleSignInsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	back := func(k, v string) {
		http.Redirect(w, r, "/security/signins?"+url.Values{k: {v}}.Encode(), http.StatusSeeOther)
	}
	id := r.FormValue("session")
	var who string
	for _, t := range s.Tokens.Snapshot() {
		if t.ID == id {
			who = t.Principal
		}
	}
	if who == "" {
		back("e", "No such session.")
		return
	}
	if strings.EqualFold(who, p.Name) {
		back("e", "Somebody else has to let you in: that is the point of asking.")
		return
	}
	// Vouching for somebody takes at least their standing: an analyst
	// cannot let an administrator of the whole site past a step-up.
	if r.FormValue("do") == "letin" && s.Policy != nil &&
		s.Policy.Evaluate(who, auth.ActGrant, "/").Allowed &&
		!s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed {
		back("e", who+" administers the whole site; only somebody who does too can let them in.")
		return
	}
	var err error
	switch r.FormValue("do") {
	case "letin":
		err = s.Tokens.ClearStepUp(id)
		s.audit("session.stepup-letin", "/", map[string]string{"by": p.Name, "session": id, "subject": who})
	case "signout":
		_, err = s.Tokens.Revoke(id)
		s.audit("session.stepup-ended", "/", map[string]string{"by": p.Name, "session": id, "subject": who})
	default:
		http.NotFound(w, r)
		return
	}
	if err == nil && s.SaveTokens != nil {
		err = s.SaveTokens(s.Tokens)
	}
	if err != nil {
		back("e", err.Error())
		return
	}
	back("m", "Done: "+who+".")
}
