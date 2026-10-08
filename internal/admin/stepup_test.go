// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A sign-in a rule judged unlike its person reaches nothing but "confirm
// it's you" until somebody else lets them in; they cannot let themselves.
func TestASteppedUpSessionReachesNothingUntilLetIn(t *testing.T) {
	srv, adminToken := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "ada", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	adaToken, _, err := srv.Tokens.Issue("laptop", "ada", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.SignInRisk = func(f SignInFacts) SignInVerdict {
		if f.Principal == "ada" {
			return SignInVerdict{StepUp: true, Reason: "Sydney, AU, 16994 km from London moments earlier"}
		}
		return SignInVerdict{}
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(url.Values{"token": {adaToken}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("the sign-in went to %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "quilzo_token" {
			session = c.Value
		}
	}
	as := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "quilzo_token", Value: session})
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/", "/people", "/security/signins"} {
		if w := as(http.MethodGet, path, ""); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/verify" {
			t.Errorf("%s answered %d %q", path, w.Code, w.Header().Get("Location"))
		}
	}
	if w := as(http.MethodPost, "/save", "name=index"); w.Code != http.StatusForbidden {
		t.Errorf("a write answered %d", w.Code)
	}
	page := as(http.MethodGet, "/signin/verify", "")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Sydney, AU") {
		t.Fatalf("the verify page: %d", page.Code)
	}
	// Ada cannot let herself in: the request never reaches the screen.
	var id string
	for _, tok := range srv.Tokens.Snapshot() {
		if tok.Principal == "ada" && tok.StepUp != "" {
			id = tok.ID
		}
	}
	if id == "" {
		t.Fatal("no session is marked")
	}
	as(http.MethodPost, "/security/signins/act", "do=letin&session="+id)
	if w := as(http.MethodGet, "/", ""); w.Code != http.StatusSeeOther {
		t.Error("the session let itself in")
	}
	// Another administrator sees her waiting, and lets her in.
	list := get(t, srv, "/security/signins", adminToken).Body.String()
	if !strings.Contains(list, "ada") || !strings.Contains(list, "Let them in") {
		t.Error("the waiting session is not listed")
	}
	postForm(t, srv, "/security/signins/act", adminToken, "do=letin&session="+id)
	if w := as(http.MethodGet, "/", ""); w.Code != http.StatusOK {
		t.Errorf("let in, she still gets %d", w.Code)
	}
}

// Without a reason to, a sign-in goes straight in, and the verify page
// says there is nothing to confirm.
func TestASignInNobodyJudgedGoesStraightIn(t *testing.T) {
	srv, token := setup(t)
	srv.SignInRisk = func(SignInFacts) SignInVerdict { return SignInVerdict{} }
	if w := get(t, srv, "/", token); w.Code != http.StatusOK {
		t.Fatalf("/ answered %d", w.Code)
	}
	if body := get(t, srv, "/signin/verify", token).Body.String(); !strings.Contains(body, "nothing to confirm") {
		t.Error("the verify page does not say there is nothing to confirm")
	}
}

// A step-up that cannot be written down refuses the sign-in and ends the
// session: it is never let in unconfirmed.
func TestAStepUpThatCannotBeRecordedRefusesTheSignIn(t *testing.T) {
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "ada", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	adaToken, _, _ := srv.Tokens.Issue("laptop", "ada", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	srv.SignInRisk = func(SignInFacts) SignInVerdict { return SignInVerdict{StepUp: true, Reason: "Sydney"} }
	saves := 0
	srv.SaveTokens = func(*auth.TokenStore) error {
		saves++
		if saves == 2 { // the first save is the new session; the second is the mark
			return errors.New("disk full")
		}
		return nil
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(url.Values{"token": {adaToken}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/signin") || strings.Contains(loc, "verify") {
		t.Fatalf("the sign-in went to %q", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "quilzo_token" && c.Value != "" && c.MaxAge > 0 {
			t.Error("a session cookie was set")
		}
	}
	for _, tok := range srv.Tokens.Snapshot() {
		if tok.Principal == "ada" && tok.IsSession() && !tok.Revoked {
			t.Error("the unconfirmed session was left alive")
		}
	}
}

// The emailed code: it proves the session once, a wrong one does not, five
// wrong ones burn it, and asking for more than three in ten minutes is
// refused, so nobody's mailbox can be filled from here.
func TestTheEmailedCodeProvesTheSessionOnce(t *testing.T) {
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "ada@example.com", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	srv.StepUpMail = func(to, code string) error { sent = append(sent, to+":"+code); return nil }
	secret, tok, err := srv.Tokens.IssueSession("s", "ada@example.com", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Tokens.RequireStepUp(tok.ID, "Sydney"); err != nil {
		t.Fatal(err)
	}
	as := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "quilzo_token", Value: secret})
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	stepped := func() bool {
		for _, x := range srv.Tokens.Snapshot() {
			if x.ID == tok.ID {
				return x.StepUp != ""
			}
		}
		return false
	}
	as("/signin/verify/code", "")
	if len(sent) != 1 || !strings.HasPrefix(sent[0], "ada@example.com:") {
		t.Fatalf("sent %v", sent)
	}
	code := strings.TrimPrefix(sent[0], "ada@example.com:")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	as("/signin/verify/check", "code="+wrong)
	if !stepped() {
		t.Fatal("a wrong code let the session in")
	}
	as("/signin/verify/check", "code="+code)
	if stepped() {
		t.Fatal("the right code did not")
	}
	// It worked once; stepped up again, the same code does nothing.
	srv.Tokens.RequireStepUp(tok.ID, "again")
	as("/signin/verify/check", "code="+code)
	if !stepped() {
		t.Fatal("a used code worked a second time")
	}
	// Burned after five wrong tries, even when the sixth is right.
	as("/signin/verify/code", "")
	code = strings.TrimPrefix(sent[len(sent)-1], "ada@example.com:")
	for i := 0; i < 5; i++ {
		as("/signin/verify/check", "code="+wrong)
	}
	as("/signin/verify/check", "code="+code)
	if !stepped() {
		t.Error("a code was accepted after five wrong tries")
	}
	as("/signin/verify/code", "")
	as("/signin/verify/code", "")
	if len(sent) != 3 {
		t.Errorf("%d codes were sent; the fourth in ten minutes should be refused", len(sent))
	}
}

// A session used from another country, or another kind of device, than it
// was issued to is put to the rules, once for each new place; a new
// address in the same country on the same device is not a move.
func TestASessionUsedSomewhereElseIsCaught(t *testing.T) {
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "ada", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	adaToken, _, _ := srv.Tokens.Issue("laptop", "ada", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	country := map[string]string{"198.51.100.7": "GB", "198.51.100.8": "GB", "203.0.113.5": "AU"}
	srv.SessionPlace = func(addr, agent string) SessionContext {
		d := "Chrome on Windows"
		if strings.Contains(agent, "Firefox") {
			d = "Firefox on Linux"
		}
		return SessionContext{Device: d, Country: country[addr]}
	}
	var moves []SessionMove
	srv.SessionMovedTo = func(m SessionMove) SignInVerdict {
		moves = append(moves, m)
		return SignInVerdict{StepUp: true, Reason: "a session issued in " + m.From.Country + " is now used in " + m.To.Country}
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(url.Values{"token": {adaToken}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows) Chrome/146")
	req.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "quilzo_token" {
			session = c.Value
		}
	}
	from := func(addr, agent string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: "quilzo_token", Value: session})
		r.Header.Set("User-Agent", agent)
		r.RemoteAddr = addr + ":5000"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	chrome := "Mozilla/5.0 (Windows) Chrome/147"
	if w := from("198.51.100.8", chrome); w.Code != 200 || len(moves) != 0 {
		t.Fatalf("a new address in the same country: %d, %d moves", w.Code, len(moves))
	}
	if w := from("203.0.113.5", chrome); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("used from Australia: %d %q", w.Code, w.Header().Get("Location"))
	}
	if len(moves) != 1 || moves[0].From.Country != "GB" || moves[0].To.Country != "AU" {
		t.Fatalf("moves %+v", moves)
	}
	from("203.0.113.5", chrome)
	if len(moves) != 1 {
		t.Error("the same move was judged twice")
	}
	// Reporting it ends the session and tells the rules.
	var reported []string
	srv.Reported = func(who, sess string) { reported = append(reported, who) }
	r := httptest.NewRequest(http.MethodPost, "/signin/verify/report", nil)
	r.AddCookie(&http.Cookie{Name: "quilzo_token", Value: session})
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if len(reported) != 1 || reported[0] != "ada" {
		t.Errorf("reported %v", reported)
	}
	if w := from("198.51.100.7", chrome); w.Code == 200 {
		t.Error("the reported session still works")
	}
}

// Another kind of device counts as a move.
func TestASessionOnAnotherDeviceIsCaught(t *testing.T) {
	srv, _ := setup(t)
	srv.Policy.Grant(auth.Binding{Principal: "bo", Role: auth.RoleAdmin, Resource: "/"})
	secret, tok, _ := srv.Tokens.IssueSession("s", "bo", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	srv.Tokens.BindSession(tok.ID, "Chrome on Windows|GB")
	srv.SessionPlace = func(addr, agent string) SessionContext {
		return SessionContext{Device: "a script on another system", Country: "GB"}
	}
	srv.SessionMovedTo = func(m SessionMove) SignInVerdict { return SignInVerdict{StepUp: true, Reason: "moved"} }
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "quilzo_token", Value: secret})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Errorf("a session copied into a script answered %d", w.Code)
	}
}
