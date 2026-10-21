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
	"github.com/quilzo/quilzo/internal/lockout"
)

// Smart lockout at the admin's door (internal/lockout).
//
// Few failures here belong to an account: there is no password, a token is
// its own name and secret, and an unknown credential names nobody. The ones
// that do (a passkey the store knows whose signature or check fails, a
// held session that fails to confirm) are counted against the account, so
// whoever is guessing is locked out of it from the places they try from,
// and the person keeps signing in from their own. Everything else is
// slowed per source, by the throttle.

// lockoutCheck refuses an attempt on name from where r comes from, when
// that place is locked out of the account or the account's passkeys are
// off; it writes the answer and reports false.
func (s *Server) lockoutCheck(w http.ResponseWriter, r *http.Request, name string) bool {
	if s.Lockout == nil {
		return true
	}
	d, err := s.Lockout.Check(name, sourceOf(r), time.Now())
	if err != nil || d.Allowed {
		return true
	}
	s.audit("signin.held", "/", map[string]string{"by": name, "source": sourceOf(r),
		"why": map[bool]string{true: "disabled", false: "locked"}[d.Disabled]})
	if d.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
	}
	writeJSONError(w, http.StatusTooManyRequests, fmt.Errorf("%s", d.Why))
	return false
}

// lockoutFail counts a failure against name, and tells the record and the
// automations when it locked places out or turned the passkeys off.
func (s *Server) lockoutFail(r *http.Request, name string) {
	if s.Lockout == nil {
		return
	}
	d, ev, err := s.Lockout.Fail(name, sourceOf(r), time.Now())
	if err != nil {
		return
	}
	switch ev {
	case lockout.Locked:
		s.audit("account.locked", "/", map[string]string{"for": name, "source": sourceOf(r),
			"for_seconds": strconv.Itoa(int(d.RetryAfter.Seconds()))})
		if s.SignInSignal != nil {
			s.SignInSignal(name, "account-locked", "repeated failed sign-ins from places this account is not used from")
		}
	case lockout.Disabled:
		s.audit("account.disabled", "/", map[string]string{"for": name, "source": sourceOf(r)})
		if s.SignInSignal != nil {
			s.SignInSignal(name, "account-locked", fmt.Sprintf("%d failed sign-ins in a row; passkey sign-in is off until it is turned back on", lockout.Ceiling))
		}
	}
}

// lockoutSucceed records a sign-in that worked, and returns where to send
// the person, told how many failures came before it when there were any.
func (s *Server) lockoutSucceed(r *http.Request, name, next string) string {
	return s.withNotice(next, s.lockoutNotice(r, name))
}

// lockoutNotice records a sign-in that worked, and is what to tell the
// person about the failures that came before it, if any did.
func (s *Server) lockoutNotice(r *http.Request, name string) string {
	if s.Lockout == nil {
		return ""
	}
	since, err := s.Lockout.Succeed(name, sourceOf(r), time.Now())
	if err != nil || since == 0 {
		return ""
	}
	return fmt.Sprintf("%d failed %s on your account since you last signed in. If those were not you, tell your "+
		"security team.", since, map[bool]string{true: "sign-in", false: "sign-ins"}[since == 1])
}

// withNotice is next, saying msg when there is one.
func (s *Server) withNotice(next, msg string) string {
	if msg == "" {
		return next
	}
	sep := "?"
	if strings.Contains(next, "?") {
		sep = "&"
	}
	return signFlash(s.flashKey, next+sep+"m="+url.QueryEscape(msg))
}

// lockoutProven is lockoutSucceed for a sign-in made another way than a
// passkey (single sign-on): the person has proved themselves, so their
// passkeys work again, and from everywhere.
func (s *Server) lockoutProven(r *http.Request, name, next string) string {
	if s.Lockout == nil {
		return next
	}
	if held, err := s.Lockout.Unlock(name, time.Now()); err == nil && held {
		s.audit("account.unlocked", "/", map[string]string{"by": name, "for": name, "how": "single sign-on"})
	}
	return s.lockoutSucceed(r, name, next)
}

type heldRow struct {
	Person, Until string
	Disabled      bool
}

// heldRows are the accounts locked out from somewhere, or with passkey
// sign-in off, for Sign-ins.
func (s *Server) heldRows(now time.Time) []heldRow {
	if s.Lockout == nil {
		return nil
	}
	held, err := s.Lockout.Held(now)
	if err != nil {
		return nil
	}
	var out []heldRow
	for _, a := range held {
		row := heldRow{Person: a.Name, Disabled: !a.Disabled.IsZero()}
		if !row.Disabled {
			row.Until = a.LockedUntil.UTC().Format("2 Jan 15:04")
		}
		out = append(out, row)
	}
	return out
}

// handleSignInsUnlock lets an account sign in again from everywhere. Not
// your own, which is what a lockout keeps somebody else from doing, and an
// administrator of the whole site only by another.
func (s *Server) handleSignInsUnlock(w http.ResponseWriter, r *http.Request) {
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
	who := strings.TrimSpace(r.FormValue("person"))
	switch {
	case s.Lockout == nil:
		back("e", "This server was started without lockout.")
		return
	case who == "":
		back("e", "Unlock whom?")
		return
	case strings.EqualFold(who, p.Name):
		back("e", "Somebody else has to unlock you: that is the point of a lockout.")
		return
	case s.Policy != nil && s.Policy.Evaluate(who, auth.ActGrant, "/").Allowed &&
		!s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed:
		back("e", who+" administers the whole site; only somebody who does too can unlock them.")
		return
	}
	found, err := s.Lockout.Unlock(who, time.Now())
	if err != nil {
		back("e", err.Error())
		return
	}
	if !found {
		back("e", who+" is not locked out.")
		return
	}
	s.audit("account.unlocked", "/", map[string]string{"by": p.Name, "for": who})
	back("m", who+" can sign in again from anywhere.")
}
