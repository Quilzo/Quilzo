// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"github.com/quilzo/quilzo/internal/clientip"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/travel"
)

// Automations, and the sign-in check that is their real-time half.
//
// Every sign-in to this admin — token, passkey or single sign-on — is put
// to SignInRisk once the session exists and before the person gets it. If
// a rule says so (internal/automate), the session is marked as having to
// prove its person, and every page sends them to "Confirm it's you" until
// they do: with a passkey, with a code sent to their address, or by an
// administrator letting them in from the Sign-ins screen.

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

// AutomationsAdmin is automations, as the admin reaches them.
type AutomationsAdmin struct {
	Engine *automate.Engine
	// SignIns lists recent sign-ins, everybody's, newest first.
	SignIns func(since time.Time) ([]travel.Recent, error)
	// Geo says where locations come from, in a sentence.
	Geo func() string
}

// clientAddr is the address a sign-in came from, for placing it: the
// client the edge decided (internal/clientip), which believes a forwarded
// address only from a proxy the deployment named.
func (s *Server) clientAddr(r *http.Request) string { return clientip.AddrFrom(r) }

// signInCheck puts a new session's sign-in to the automations, and marks
// the session when they say it must prove its person. It says whether it
// did, so the caller sends the person to verify rather than in.
//
// When the automations decided a step-up and it could not be written
// down, the session is ended and the error returned, and the sign-in is
// refused: a session that should have been stepped up and was let in is
// the one outcome this must never have. (Whether the automations could
// decide at all is theirs to report: an unreadable rules file lets sign-ins
// through and says so loudly, rather than locking every administrator out.)
func (s *Server) signInCheck(r *http.Request, name, sessionID, how string, verifying bool) (bool, error) {
	up, err := s.signInRisk(r, name, sessionID, how, verifying)
	// A passkey or single sign-on nothing held back is an administrator
	// where they are: the shield never blocks that source from the admin.
	if err == nil && !up && (how == "passkey" || how == "sso") && s.OnStrongSignIn != nil {
		s.OnStrongSignIn(r, name)
	}
	return up, err
}

// signInRisk puts a sign-in to the automations' risk rules.
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
// the rules once per new context. It says why, when a rule stepped the
// session up. Only the device kind and the country count: a phone moves
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
		// The rule said to stop it and that could not be written down:
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

type stepCode struct {
	hash    string
	expires time.Time
	tries   int
	// sent counts codes sent to this session in the window, so asking for
	// codes cannot be used to fill somebody's mailbox.
	sent  int
	since time.Time
}

var (
	stepCodesMu sync.Mutex
	stepCodes   = map[string]*stepCode{}
)

const (
	stepCodeTTL   = 10 * time.Minute
	stepCodeTries = 5
	stepCodeSends = 3
)

// purgeCodes forgets expired codes, so the table holds only live ones.
func purgeCodes(now time.Time) {
	for id, c := range stepCodes {
		if now.After(c.expires) && now.Sub(c.since) > stepCodeTTL {
			delete(stepCodes, id)
		}
	}
}

func codeHash(session, code string) string {
	sum := sha256.Sum256([]byte(session + ":" + code))
	return hex.EncodeToString(sum[:])
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
		"Passkey": s.hasPasskey(p.Name), "Mail": s.StepUpMail != nil && strings.Contains(p.Name, "@"),
		"Sent": r.URL.Query().Get("sent") != "", "Error": r.URL.Query().Get("e"),
	})
}

// handleStepUpCode sends a six-digit code to the person's own address.
func (s *Server) handleStepUpCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.verifyPrincipal(w, r)
	if !ok {
		return
	}
	if s.StepUpMail == nil || !strings.Contains(p.Name, "@") {
		http.Redirect(w, r, "/signin/verify?e="+url.QueryEscape("No mail is set up to send a code."), http.StatusSeeOther)
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		http.Error(w, "no randomness", http.StatusInternalServerError)
		return
	}
	code := fmt.Sprintf("%06d", n.Int64())
	now := time.Now()
	stepCodesMu.Lock()
	purgeCodes(now)
	c := stepCodes[p.TokenID]
	if c == nil || now.Sub(c.since) > stepCodeTTL {
		c = &stepCode{since: now}
		stepCodes[p.TokenID] = c
	}
	if c.sent >= stepCodeSends {
		stepCodesMu.Unlock()
		http.Redirect(w, r, "/signin/verify?sent=1&e="+url.QueryEscape("Three codes have been sent in the last ten minutes. Use the newest one, or wait."), http.StatusSeeOther)
		return
	}
	c.sent++
	c.hash, c.expires, c.tries = codeHash(p.TokenID, code), now.Add(stepCodeTTL), 0
	stepCodesMu.Unlock()
	if err := s.StepUpMail(p.Name, code); err != nil {
		http.Redirect(w, r, "/signin/verify?e="+url.QueryEscape("The code could not be sent: "+err.Error()), http.StatusSeeOther)
		return
	}
	s.audit("session.stepup-code-sent", "/", map[string]string{"by": p.Name, "session": p.TokenID})
	http.Redirect(w, r, "/signin/verify?sent=1", http.StatusSeeOther)
}

// handleStepUpCheck takes the code. Five tries, ten minutes, once.
func (s *Server) handleStepUpCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.verifyPrincipal(w, r)
	if !ok {
		return
	}
	got := strings.TrimSpace(r.FormValue("code"))
	stepCodesMu.Lock()
	c := stepCodes[p.TokenID]
	good := false
	if c != nil && time.Now().Before(c.expires) && c.tries < stepCodeTries {
		c.tries++
		good = c.hash != "" && subtle.ConstantTimeCompare([]byte(c.hash), []byte(codeHash(p.TokenID, got))) == 1
		if good {
			// Used: it works once. The record stays for its window, so the
			// limit on sending counts across a success too.
			c.hash = ""
		}
	}
	stepCodesMu.Unlock()
	if !good {
		s.audit("session.stepup-code-wrong", "/", map[string]string{"by": p.Name, "session": p.TokenID})
		stepCodesMu.Lock()
		third := c != nil && c.tries == 3
		stepCodesMu.Unlock()
		if third && s.SignInSignal != nil {
			s.SignInSignal(p.Name, "verification-failing", "three wrong codes from a session asked to confirm it is them")
		}
		http.Redirect(w, r, "/signin/verify?sent=1&e="+url.QueryEscape("That code is wrong or has expired."), http.StatusSeeOther)
		return
	}
	s.passStepUp(w, r, p, "code")
}

// handleStepUpReport is the person saying the sign-in was not them. The
// session ends at once, and the rules hear it: a person who knows a
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	if s.Automations == nil || s.Automations.SignIns == nil {
		data["NoHistory"] = "This build was started without sign-in checks, so where people signed in from is not kept."
		s.render(w, r, "signins.html", data)
		return
	}
	if s.Automations.Geo != nil {
		data["Geo"] = s.Automations.Geo()
	}
	recent, err := s.Automations.SignIns(time.Now().Add(-30 * 24 * time.Hour))
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

// -- automations -----------------------------------------------------------------

type ruleView struct {
	automate.Rule
	When, Words string
	Fired       int
	Last        string
}

type runView struct {
	automate.Run
	When  string
	Tone  string
	State string
}

func (s *Server) automationActions() map[string]automate.Action {
	if s.Automations == nil || s.Automations.Engine == nil {
		return nil
	}
	return s.Automations.Engine.Actions
}

// ruleWords says a rule in a sentence.
func ruleWords(r automate.Rule, actions map[string]automate.Action) string {
	var b strings.Builder
	b.WriteString(automate.KindNames[r.When])
	for i, c := range r.If {
		if i == 0 {
			b.WriteString(", if ")
		} else {
			b.WriteString(" and ")
		}
		fmt.Fprintf(&b, "%s %s %s", strings.ReplaceAll(c.Field, "_", " "), automate.Ops[c.Op], valueWords(c.Value))
	}
	b.WriteString(": ")
	for i, st := range r.Then {
		if i > 0 {
			b.WriteString(", then ")
		}
		name := st.Action
		if a, ok := actions[st.Action]; ok {
			// Only the first letter: "Suspend in Okta" is "suspend in
			// Okta" mid-sentence, not "suspend in okta".
			name = lowerFirst(a.Name)
		}
		b.WriteString(name)
		if to := st.With["to"]; to != "" {
			fmt.Fprintf(&b, " (%s)", map[string]string{"security": "the security team", "person": "the person"}[to])
		}
	}
	b.WriteString(".")
	return b.String()
}

// valueWords says a condition's value the way the rest of the sentence
// reads: a signal by its name, a product by its own, a check as a check,
// and a list as "this or that".
func valueWords(v string) string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		switch {
		case signalWords[part] != "":
			part = signalWords[part]
		case strings.HasPrefix(part, "estate/"):
			part = "the " + strings.ReplaceAll(strings.TrimPrefix(part, "estate/"), "-", " ") + " check"
		case productName(part) != part:
			part = productName(part)
		default:
			part = strings.ReplaceAll(part, "-", " ")
		}
		out = append(out, part)
	}
	return strings.Join(out, " or ")
}

// lowerFirst lowers a name's first letter for the middle of a sentence.
func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToLower(r)) + s[n:]
}

var runTone = map[string]string{"done": "good", "approved": "good", "watched": "unknown",
	"waiting": "warning", "declined": "unknown", "limited": "serious"}
var runWord = map[string]string{"done": "Done", "approved": "Approved", "watched": "Watched",
	"waiting": "Waiting", "declined": "Declined", "limited": "Over its limit"}

func (s *Server) handleAutomations(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Automations", "Nav": "automations", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Automations == nil || s.Automations.Engine == nil {
		data["Unavailable"] = "This build was started without automations."
		s.render(w, r, "automations.html", data)
		return
	}
	e := s.Automations.Engine
	rules, err := e.Rules()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "automations.html", data)
		return
	}
	runs, _ := e.Runs()
	week := time.Now().Add(-7 * 24 * time.Hour)
	have := map[string]bool{}
	var views []ruleView
	for _, rule := range rules {
		v := ruleView{Rule: rule, When: automate.KindNames[rule.When], Words: ruleWords(rule, e.Actions)}
		for _, run := range runs {
			if run.Rule == rule.ID {
				if v.Last == "" {
					v.Last = run.At.Format("2 Jan 15:04")
				}
				if run.At.After(week) {
					v.Fired++
				}
			}
		}
		views = append(views, v)
		have[rule.Name] = true
	}
	data["Rules"] = views
	var tpls []ruleView
	for _, t := range automate.Templates {
		if !have[t.Name] {
			tpls = append(tpls, ruleView{Rule: t, When: automate.KindNames[t.When], Words: ruleWords(t, e.Actions)})
		}
	}
	data["Templates"] = tpls
	var waiting, history []runView
	for i, run := range runs {
		v := runView{Run: run, When: run.At.Format("2 Jan 15:04"), Tone: runTone[run.State], State: runWord[run.State]}
		if run.State == "waiting" {
			waiting = append(waiting, v)
		}
		if i < 100 {
			history = append(history, v)
		}
	}
	data["Waiting"], data["History"] = waiting, history
	data["Modes"] = automate.Modes
	s.render(w, r, "automations.html", data)
}

// handleAutomationRule is the builder: a new rule, or one to change.
func (s *Server) handleAutomationRule(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if s.Automations == nil || s.Automations.Engine == nil {
		s.render(w, r, "automation_rule.html", map[string]any{"Title": "Automation", "Nav": "automations",
			"Principal": p, "Unavailable": "This build was started without automations."})
		return
	}
	e := s.Automations.Engine
	rule := automate.Rule{Mode: "watch", When: "signin", Enabled: true}
	if id := r.URL.Query().Get("id"); id != "" {
		rules, _ := e.Rules()
		for _, x := range rules {
			if x.ID == id {
				rule = x
			}
		}
	}
	type field struct{ Kind, Name string }
	var fields []field
	var kinds []string
	for k := range automate.Kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		for _, f := range automate.Kinds[k] {
			fields = append(fields, field{k, f})
		}
	}
	type act struct {
		ID, Name, Does, Undo string
		Kinds                string
	}
	var acts []act
	for _, a := range e.Actions {
		acts = append(acts, act{a.ID, a.Name, a.Does, a.Undo, strings.Join(a.Kinds, ", ")})
	}
	sort.Slice(acts, func(i, j int) bool { return acts[i].Name < acts[j].Name })
	// Three rows of each, filled from the rule.
	conds := make([]automate.Condition, 3)
	copy(conds, rule.If)
	steps := make([]automate.Step, 3)
	copy(steps, rule.Then)
	// The rows in use, and one to start with, are shown; the empty rest
	// wait behind "Add a condition" so a new rule is not nine empty fields.
	type condRow struct {
		I     int
		First bool
		automate.Condition
	}
	type stepRow struct {
		I     int
		First bool
		automate.Step
	}
	var condShown, condSpare []condRow
	for i, c := range conds {
		if i == 0 || c.Field != "" {
			condShown = append(condShown, condRow{i, len(condShown) == 0, c})
		} else {
			condSpare = append(condSpare, condRow{i, false, c})
		}
	}
	var stepShown, stepSpare []stepRow
	for i, st := range steps {
		if i == 0 || st.Action != "" {
			stepShown = append(stepShown, stepRow{i, len(stepShown) == 0, st})
		} else {
			stepSpare = append(stepSpare, stepRow{i, false, st})
		}
	}
	s.render(w, r, "automation_rule.html", map[string]any{
		"Title": "Automation", "Nav": "automations", "Principal": p, "Rule": rule,
		"Kinds": kinds, "KindNames": automate.KindNames, "Fields": fields, "Ops": automate.Ops, "OpOrder": automate.OpOrder, "DefaultPerHour": automate.DefaultPerHour,
		"Actions": acts, "Conds": condShown, "SpareConds": condSpare, "Steps": stepShown, "SpareSteps": stepSpare, "Modes": automate.Modes,
		"Error": r.URL.Query().Get("e"),
	})
}

// handleAutomationsAct changes rules and decides waiting runs.
func (s *Server) handleAutomationsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if s.Automations == nil || s.Automations.Engine == nil {
		http.Error(w, "this build has no automations", http.StatusServiceUnavailable)
		return
	}
	e := s.Automations.Engine
	back := func(k, v string) {
		http.Redirect(w, r, "/security/automations?"+url.Values{k: {v}}.Encode(), http.StatusSeeOther)
	}
	// What acts on somebody's access is a whole-site administrator's
	// decision: an analyst who could write "when anybody signs in, sign out
	// the administrators" could lock out everybody above them.
	siteAdmin := s.Policy != nil && s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed
	accessRefused := func(what string) {
		back("e", what+" acts on people's access, which takes an administrator of the whole site.")
	}
	find := func(id string) (automate.Rule, bool) {
		rules, _ := e.Rules()
		for _, x := range rules {
			if x.ID == id {
				return x, true
			}
		}
		return automate.Rule{}, false
	}
	switch r.FormValue("do") {
	case "template":
		for _, t := range automate.Templates {
			if t.ID == r.FormValue("id") {
				if t.Access(e.Actions) && !siteAdmin {
					accessRefused(t.Name)
					return
				}
				t.ID, t.Enabled = "", true
				if _, err := e.Save(t, p.Name); err != nil {
					back("e", err.Error())
					return
				}
				s.audit("automation.added", "/", map[string]string{"by": p.Name, "rule": t.Name, "mode": t.Mode})
				back("m", "Added: "+t.Name+".")
				return
			}
		}
		back("e", "No such template.")
	case "mode", "enable", "disable":
		rule, ok := find(r.FormValue("id"))
		if !ok {
			back("e", "No such rule.")
			return
		}
		switch r.FormValue("do") {
		case "mode":
			rule.Mode = r.FormValue("mode")
		case "enable":
			rule.Enabled = true
		case "disable":
			rule.Enabled = false
		}
		if rule.Enabled && rule.Access(e.Actions) && !siteAdmin {
			accessRefused(rule.Name)
			return
		}
		if _, err := e.Save(rule, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		s.audit("automation.changed", "/", map[string]string{"by": p.Name, "rule": rule.Name,
			"mode": rule.Mode, "enabled": strconv.FormatBool(rule.Enabled)})
		back("m", rule.Name+": saved.")
	case "remove":
		rule, ok := find(r.FormValue("id"))
		if !ok {
			back("e", "No such rule.")
			return
		}
		if err := e.Remove(rule.ID); err != nil {
			back("e", err.Error())
			return
		}
		s.audit("automation.removed", "/", map[string]string{"by": p.Name, "rule": rule.Name})
		back("m", "Removed: "+rule.Name+".")
	case "save":
		rule := automate.Rule{ID: r.FormValue("id"), Name: strings.TrimSpace(r.FormValue("name")),
			Mode: r.FormValue("mode"), When: r.FormValue("when"), Enabled: r.FormValue("enabled") != "off",
			Note: strings.TrimSpace(r.FormValue("note"))}
		if n, err := strconv.Atoi(r.FormValue("per_hour")); err == nil {
			rule.PerHour = n
		}
		for i := 0; i < 3; i++ {
			k := strconv.Itoa(i)
			if f := r.FormValue("field" + k); f != "" {
				// The field list carries its kind, kind:field.
				if _, name, ok := strings.Cut(f, ":"); ok {
					f = name
				}
				rule.If = append(rule.If, automate.Condition{Field: f, Op: r.FormValue("op" + k),
					Value: strings.TrimSpace(r.FormValue("value" + k))})
			}
			if a := r.FormValue("action" + k); a != "" {
				st := automate.Step{Action: a}
				if to := r.FormValue("to" + k); to != "" {
					st.With = map[string]string{"to": to}
				}
				rule.Then = append(rule.Then, st)
			}
		}
		if rule.Enabled && rule.Access(e.Actions) && !siteAdmin {
			accessRefused(rule.Name)
			return
		}
		saved, err := e.Save(rule, p.Name)
		if err != nil {
			http.Redirect(w, r, "/security/automations/rule?"+url.Values{"id": {rule.ID}, "e": {err.Error()}}.Encode(), http.StatusSeeOther)
			return
		}
		s.audit("automation.saved", "/", map[string]string{"by": p.Name, "rule": saved.Name, "mode": saved.Mode})
		back("m", "Saved: "+saved.Name+".")
	case "approve", "decline":
		if r.FormValue("do") == "approve" {
			runs, _ := e.Runs()
			for _, x := range runs {
				if x.ID == r.FormValue("id") && x.Access(e.Actions) && !siteAdmin {
					accessRefused("Approving " + x.Name)
					return
				}
			}
		}
		run, err := e.Decide(r.FormValue("id"), r.FormValue("do") == "approve", p.Name)
		if err != nil {
			back("e", err.Error())
			return
		}
		s.audit("automation.run-"+run.State, "/", map[string]string{"by": p.Name, "rule": run.Name, "subject": run.Event.Subject})
		back("m", run.Name+": "+run.State+".")
	default:
		http.NotFound(w, r)
	}
}
