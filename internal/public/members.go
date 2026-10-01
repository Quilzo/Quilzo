// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/member"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// Accounts for a site's visitors.
//
// # What changes, and what does not
//
// The public server had no sessions and set no cookies: it served the same
// bytes to everybody, and the one thing it wrote was a form submission. With
// accounts on, it keeps who is signed in — and nothing else changes. Every
// page that is not for members is served exactly as before, to everybody,
// cacheable, with no cookie read; only /account and a members-only page look
// at the session at all.
//
// # The decisions
//
// Off unless site.members says "open" or "invite". Passkeys to sign in and
// recovery codes for a lost device: no passwords to leak and no mail server
// to need. A session is a random token in a __Host- cookie — HttpOnly,
// Secure, SameSite=Lax, this origin only — and only its hash is stored, so
// a copy of the store signs nobody in. Every change is a POST from this
// site's own pages, checked by Sec-Fetch-Site or Origin before anything is
// read. Sign-up, sign-in and recovery are rate limited per address.
//
// # Pages for members
//
// A page with members_only: true is left out of everything the public reads
// — the sitemap, feeds, search, the chatbot's knowledge, a static copy — by
// the same filter that applies a publish window, so no read path has to
// remember. Asked for by name, it is served to a signed-in member, privately
// and uncached, and to anybody else as a page that says it is for members.

// Members gives the public server its accounts. Nil, or a mode that is not
// open or invite, means there are none and /account is an ordinary address.
type Members struct {
	Store *member.Store
	// Mode is "open", anybody may make an account, or "invite", somebody
	// needs a code from the site's staff.
	Mode string
	// Party is this site as a passkey relying party: its domain and origin.
	Party webauthn.Party
	// Limit bounds sign-ups, sign-ins and recovery attempts per address.
	Limit *throttle.Limiter
	// Audit records what happened to an account, by its random id. Never a
	// name: the audit log outlives an account, and an erased account must
	// not be readable there.
	Audit func(action, member, source string, ok bool)

	mu         sync.Mutex
	ceremonies map[string]ceremony
}

// ceremony is one passkey prompt in progress: server-side, single use and
// short-lived, so a challenge cannot be replayed or kept for later.
type ceremony struct {
	kind    string
	member  string
	name    string
	invite  string
	expires time.Time
}

// MemberCookie names the session cookie. __Host- makes the browser refuse
// it unless it is Secure, for this exact host, and for the whole path.
const MemberCookie = "__Host-qz_member"

// MembersOnlyField marks a page as for members.
const MembersOnlyField = "members_only"

//go:embed account.js
var accountJS string

func (st *Site) membersOn() bool {
	m := st.Members
	return m != nil && m.Store != nil && (m.Mode == "open" || m.Mode == "invite")
}

// signedIn is the member this request's session signs in, if any.
func (st *Site) signedIn(r *http.Request) (member.Member, bool) {
	if !st.membersOn() {
		return member.Member{}, false
	}
	c, err := r.Cookie(MemberCookie)
	if err != nil {
		return member.Member{}, false
	}
	m, err := st.Members.Store.SessionMember(c.Value)
	if err != nil {
		return member.Member{}, false
	}
	return m, true
}

// sameSite reports whether a request came from this site's own pages.
//
// Sec-Fetch-Site where the browser sends it, which every current one does;
// Origin otherwise. A request with neither is refused: it did not come from
// a page of this site, whatever else it is.
func (st *Site) sameSite(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "":
		o := r.Header.Get("Origin")
		return o != "" && o == st.Members.Party.Origin
	}
	return false
}

func (st *Site) audit(action, id string, r *http.Request, ok bool) {
	if st.Members.Audit != nil {
		st.Members.Audit(action, id, sourceOf(r), ok)
	}
}

// limited spends one attempt from this address and reports whether it was
// over the limit, having answered if so.
func (st *Site) limited(w http.ResponseWriter, r *http.Request) bool {
	l := st.Members.Limit
	if l == nil {
		return false
	}
	subj := throttle.Subject{Source: sourceOf(r)}
	if d := l.Check(subj); !d.Allowed {
		jsonError(w, http.StatusTooManyRequests,
			"Too many attempts from here. Wait a minute and try again.")
		return true
	}
	l.Spend(subj)
	return false
}

func (st *Site) startCeremony(c ceremony) (string, error) {
	ch, err := webauthn.NewChallenge()
	if err != nil {
		return "", err
	}
	m := st.Members
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.ceremonies == nil {
		m.ceremonies = map[string]ceremony{}
	}
	for k, v := range m.ceremonies {
		if now.After(v.expires) {
			delete(m.ceremonies, k)
		}
	}
	c.expires = now.Add(webauthn.ChallengeLifetime)
	m.ceremonies[ch] = c
	return ch, nil
}

// takeCeremony returns a ceremony once, if it is the kind expected and has
// not expired.
func (st *Site) takeCeremony(challenge, kind string) (ceremony, bool) {
	m := st.Members
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ceremonies[challenge]
	delete(m.ceremonies, challenge)
	if !ok || c.kind != kind || time.Now().After(c.expires) {
		return ceremony{}, false
	}
	return c, true
}

func (st *Site) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: MemberCookie, Value: token, Path: "/",
		MaxAge:   int(member.SessionMax / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: MemberCookie, Value: "", Path: "/",
		MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	replyJSON(w, code, map[string]string{"error": msg})
}

func replyJSON(w http.ResponseWriter, code int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		jsonError(w, http.StatusBadRequest, "That request could not be read.")
		return false
	}
	return true
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// account answers /account and everything under it.
func (st *Site) account(w http.ResponseWriter, r *http.Request) {
	if !st.membersOn() {
		// An ordinary address when there are no accounts, so a page called
		// "account" on a site without them is still served.
		st.page(w, r)
		return
	}
	switch {
	case r.URL.Path == "/account" || r.URL.Path == "/account/":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET")
			http.Error(w, "use GET", http.StatusMethodNotAllowed)
			return
		}
		m, ok := st.signedIn(r)
		st.renderAccount(w, accountView{Member: m, SignedIn: ok,
			Done: r.URL.Query().Get("done")}, http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if !st.sameSite(r) {
		http.Error(w, "this can only be done from this site's own pages",
			http.StatusForbidden)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/account/") {
	case "signup/start":
		st.signupStart(w, r)
	case "signup/finish":
		st.signupFinish(w, r)
	case "signin/start":
		st.signinStart(w, r)
	case "signin/finish":
		st.signinFinish(w, r)
	case "passkey/start":
		st.passkeyStart(w, r)
	case "passkey/finish":
		st.passkeyFinish(w, r)
	default:
		st.accountForm(w, r, strings.TrimPrefix(r.URL.Path, "/account/"))
	}
}

func (st *Site) signupStart(w http.ResponseWriter, r *http.Request) {
	if st.limited(w, r) {
		return
	}
	var in struct{ Name, Invite string }
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := member.ValidName(in.Name); err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error()+".")
		return
	}
	if st.Members.Mode == "invite" {
		if err := st.Members.Store.CheckInvite(in.Invite); err != nil {
			jsonError(w, http.StatusUnprocessableEntity,
				"That invitation code is not valid. Ask whoever invited you for a new one.")
			return
		}
	}
	ch, err := st.startCeremony(ceremony{kind: "signup", name: in.Name, invite: in.Invite})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	handle := make([]byte, 16)
	_, _ = rand.Read(handle)
	replyJSON(w, http.StatusOK, map[string]any{
		"challenge": ch,
		"rp":        map[string]string{"id": st.Members.Party.ID, "name": st.siteName()},
		"user":      map[string]string{"id": b64(handle), "name": in.Name, "displayName": in.Name},
	})
}

type registrationIn struct {
	Challenge string `json:"challenge"`
	Label     string `json:"label"`
	webauthn.Registration
}

func (st *Site) signupFinish(w http.ResponseWriter, r *http.Request) {
	var in registrationIn
	if !readJSON(w, r, &in) {
		return
	}
	c, ok := st.takeCeremony(in.Challenge, "signup")
	if !ok {
		jsonError(w, http.StatusUnprocessableEntity, "That took too long. Start again.")
		return
	}
	cred, err := st.Members.Party.Register(in.Challenge, in.Registration)
	if err != nil {
		st.audit("member.signup", "", r, false)
		jsonError(w, http.StatusUnprocessableEntity, "That passkey could not be checked. Start again.")
		return
	}
	if st.Members.Mode == "invite" {
		// Spent only now, when everything else has worked, so a prompt
		// somebody closed does not cost them their invitation.
		if err := st.Members.Store.UseInvite(c.invite); err != nil {
			jsonError(w, http.StatusUnprocessableEntity, "That invitation has been used or has expired.")
			return
		}
	}
	m, codes, err := st.Members.Store.Create(c.name, cred)
	if err != nil {
		st.audit("member.signup", "", r, false)
		jsonError(w, http.StatusUnprocessableEntity, err.Error()+".")
		return
	}
	token, err := st.Members.Store.StartSession(m.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Your account was made, but you are not signed in. Sign in with your passkey.")
		return
	}
	st.setSession(w, token)
	st.audit("member.signup", m.ID, r, true)
	replyJSON(w, http.StatusOK, map[string]any{"codes": codes})
}

func (st *Site) signinStart(w http.ResponseWriter, r *http.Request) {
	ch, err := st.startCeremony(ceremony{kind: "signin"})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	replyJSON(w, http.StatusOK, map[string]string{"challenge": ch, "rpId": st.Members.Party.ID})
}

func (st *Site) signinFinish(w http.ResponseWriter, r *http.Request) {
	if st.limited(w, r) {
		return
	}
	var in struct {
		Challenge string `json:"challenge"`
		webauthn.Assertion
	}
	if !readJSON(w, r, &in) {
		return
	}
	// One answer for every failure: which part failed would tell somebody
	// probing whether a credential belongs to an account here.
	refuse := func(id string) {
		st.audit("member.signin", id, r, false)
		jsonError(w, http.StatusUnauthorized, "That passkey did not sign you in.")
	}
	if _, ok := st.takeCeremony(in.Challenge, "signin"); !ok {
		jsonError(w, http.StatusUnprocessableEntity, "That took too long. Start again.")
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(in.ID, "="))
	if err != nil {
		refuse("")
		return
	}
	m, cred, err := st.Members.Store.ByCredential(credID)
	if err != nil {
		refuse("")
		return
	}
	count, err := st.Members.Party.Verify(cred, in.Challenge, in.Assertion)
	if err != nil || m.Disabled {
		refuse(m.ID)
		return
	}
	_ = st.Members.Store.Used(m.ID, credID, count)
	token, err := st.Members.Store.StartSession(m.ID)
	if err != nil {
		refuse(m.ID)
		return
	}
	st.setSession(w, token)
	st.audit("member.signin", m.ID, r, true)
	replyJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (st *Site) passkeyStart(w http.ResponseWriter, r *http.Request) {
	m, ok := st.signedIn(r)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "Sign in first.")
		return
	}
	ch, err := st.startCeremony(ceremony{kind: "add", member: m.ID})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	var exclude []string
	for _, c := range m.Passkeys {
		exclude = append(exclude, b64(c.ID))
	}
	handle := make([]byte, 16)
	_, _ = rand.Read(handle)
	replyJSON(w, http.StatusOK, map[string]any{
		"challenge": ch, "exclude": exclude,
		"rp":   map[string]string{"id": st.Members.Party.ID, "name": st.siteName()},
		"user": map[string]string{"id": b64(handle), "name": m.Name, "displayName": m.Name},
	})
}

func (st *Site) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	m, ok := st.signedIn(r)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "Sign in first.")
		return
	}
	var in registrationIn
	if !readJSON(w, r, &in) {
		return
	}
	c, ok := st.takeCeremony(in.Challenge, "add")
	if !ok || c.member != m.ID {
		jsonError(w, http.StatusUnprocessableEntity, "That took too long. Start again.")
		return
	}
	cred, err := st.Members.Party.Register(in.Challenge, in.Registration)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "That passkey could not be checked. Start again.")
		return
	}
	cred.Label = clipLabel(in.Label)
	if err := st.Members.Store.AddPasskey(m.ID, cred); err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error()+".")
		return
	}
	st.audit("member.passkey-added", m.ID, r, true)
	replyJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func clipLabel(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 40 {
		s = string(r[:40])
	}
	return s
}

// accountForm handles the account page's ordinary forms.
func (st *Site) accountForm(w http.ResponseWriter, r *http.Request, action string) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that could not be read", http.StatusBadRequest)
		return
	}
	back := func(done string) {
		http.Redirect(w, r, "/account?done="+done, http.StatusSeeOther)
	}
	if action == "recover" {
		if st.limited(w, r) {
			return
		}
		m, err := st.Members.Store.Recover(r.PostFormValue("code"))
		if err != nil {
			st.audit("member.recover", "", r, false)
			st.renderAccount(w, accountView{Problem: "That recovery code did not work. " +
				"Each code works once; check it and try another."}, http.StatusUnauthorized)
			return
		}
		token, err := st.Members.Store.StartSession(m.ID)
		if err != nil {
			st.renderAccount(w, accountView{Problem: "That account cannot be signed in to."},
				http.StatusForbidden)
			return
		}
		st.setSession(w, token)
		st.audit("member.recover", m.ID, r, true)
		back("recovered")
		return
	}

	m, ok := st.signedIn(r)
	if !ok {
		back("signed-out")
		return
	}
	store := st.Members.Store
	switch action {
	case "signout":
		if c, err := r.Cookie(MemberCookie); err == nil {
			store.EndSession(c.Value)
		}
		clearSession(w)
		st.audit("member.signout", m.ID, r, true)
		back("signed-out")
	case "signout-all":
		store.EndSessions(m.ID)
		clearSession(w)
		st.audit("member.signout-all", m.ID, r, true)
		back("signed-out")
	case "name":
		if err := store.Rename(m.ID, r.PostFormValue("name")); err != nil {
			m.Name = r.PostFormValue("name")
			st.renderAccount(w, accountView{Member: m, SignedIn: true,
				Problem: err.Error() + "."}, http.StatusUnprocessableEntity)
			return
		}
		back("renamed")
	case "passkey/remove":
		id, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("id"))
		if err == nil {
			err = store.RemovePasskey(m.ID, id)
		}
		if err != nil {
			st.renderAccount(w, accountView{Member: m, SignedIn: true,
				Problem: removeProblem(err)}, http.StatusUnprocessableEntity)
			return
		}
		st.audit("member.passkey-removed", m.ID, r, true)
		back("passkey-removed")
	case "codes":
		codes, err := store.NewRecoveryCodes(m.ID)
		if err != nil {
			http.Error(w, "new codes could not be made", http.StatusInternalServerError)
			return
		}
		st.audit("member.recovery-codes", m.ID, r, true)
		m, _ = store.Get(m.ID)
		// Shown in this response and never again, so not a redirect.
		st.renderAccount(w, accountView{Member: m, SignedIn: true, Codes: codes}, http.StatusOK)
	case "delete":
		if strings.TrimSpace(strings.ToLower(r.PostFormValue("confirm"))) != "delete" {
			st.renderAccount(w, accountView{Member: m, SignedIn: true,
				Problem: "Type delete to confirm. Nothing was deleted."}, http.StatusUnprocessableEntity)
			return
		}
		if err := store.Delete(m.ID); err != nil {
			http.Error(w, "the account could not be deleted", http.StatusInternalServerError)
			return
		}
		clearSession(w)
		st.audit("member.deleted", m.ID, r, true)
		back("deleted")
	default:
		http.NotFound(w, r)
	}
}

func removeProblem(err error) string {
	if errors.Is(err, member.ErrNotFound) {
		return "That passkey is not on this account."
	}
	return err.Error() + "."
}

func (st *Site) siteName() string {
	if st.Name != "" {
		return st.Name
	}
	return "this site"
}

// -- the page ---------------------------------------------------------------

type accountView struct {
	Member   member.Member
	SignedIn bool
	Done     string
	Problem  string
	Codes    []string
	// Filled in by renderAccount.
	Site, Invite, Nonce, Message string
	MemberPages                  []memberPage
	Passkeys                     []passkeyRow
}

type memberPage struct{ Title, Href string }

type passkeyRow struct{ ID, Label, Added, Used string }

// doneMessages are the only things a redirect can make the page say, so the
// address cannot be used to put words on it.
var doneMessages = map[string]string{
	"recovered":       "Signed in with a recovery code, which will not work again. Add a new passkey now.",
	"signed-out":      "You are signed out.",
	"renamed":         "Your name is changed.",
	"passkey-added":   "The passkey is added.",
	"passkey-removed": "The passkey is removed.",
	"deleted":         "Your account is deleted, with its passkeys, recovery codes and sessions. Nothing about it is kept.",
}

func (st *Site) renderAccount(w http.ResponseWriter, v accountView, status int) {
	v.Site = st.siteName()
	v.Message = doneMessages[v.Done]
	if st.Members.Mode == "invite" {
		v.Invite = "yes"
	}
	if v.SignedIn {
		v.MemberPages = st.memberPages()
		for _, c := range v.Member.Passkeys {
			row := passkeyRow{ID: b64(c.ID), Label: c.Label,
				Added: time.Unix(c.CreatedAt, 0).UTC().Format("2 January 2006")}
			if c.LastUsed > 0 {
				row.Used = time.Unix(c.LastUsed, 0).UTC().Format("2 January 2006")
			}
			v.Passkeys = append(v.Passkeys, row)
		}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Referrer-Policy", "same-origin")
	if n, err := newNonce(); err == nil {
		v.Nonce = n
		allowScript(h, "'nonce-"+n+"'")
	}
	w.WriteHeader(status)
	_ = accountTemplate.Execute(w, map[string]any{"V": v,
		"Icon": template.HTML(st.iconLink())})
}

// memberPages are the pages for members, by title, for the account page:
// the navigation is built for everybody and leaves them out.
func (st *Site) memberPages() []memberPage {
	pages, err := st.membersOnlyPages()
	if err != nil {
		return nil
	}
	var out []memberPage
	for name, body := range pages {
		title := name
		if m, ok := body.(map[string]any); ok {
			if t, ok := m["title"].(string); ok && strings.TrimSpace(t) != "" {
				title = t
			}
		}
		out = append(out, memberPage{Title: title, Href: "/" + name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

func (st *Site) accountScript(w http.ResponseWriter, r *http.Request) {
	if !st.membersOn() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(accountJS))
}

// membersOnlyGate answers a members-only page for somebody not signed in.
func (st *Site) membersOnlyGate(w http.ResponseWriter, path string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusForbidden)
	_ = gateTemplate.Execute(w, map[string]any{"Site": st.siteName(), "Next": path,
		"Icon": template.HTML(st.iconLink())})
}

var accountTemplate = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .V.SignedIn}}Your account{{else}}Sign in{{end}} — {{.V.Site}}</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
{{.Icon}}</head>
<body class="qz-ask qz-account" data-account="/account"><main>
<p class="qz-home"><a href="/">{{.V.Site}}</a></p>
{{if .V.Message}}<p class="qz-notice" role="status">{{.V.Message}}</p>{{end}}
{{if .V.Problem}}<p class="qz-problem" role="alert">{{.V.Problem}}</p>{{end}}
<p id="account-msg" class="qz-status" role="status"></p>
{{if .V.Codes}}
<section class="qz-turn" aria-labelledby="codes-h">
  <h2 id="codes-h" tabindex="-1">Your new recovery codes</h2>
  <p>Each one signs you in once if you lose your passkeys. Keep them somewhere safe; they are not shown again, and the old ones no longer work.</p>
  <ol class="qz-codes">{{range .V.Codes}}<li>{{.}}</li>{{end}}</ol>
</section>
{{end}}
{{if .V.SignedIn}}
<h1>Hello, {{.V.Member.Name}}</h1>
{{if .V.MemberPages}}<section class="qz-turn" aria-labelledby="pages-h">
  <h2 id="pages-h">For members</h2>
  <ul>{{range .V.MemberPages}}<li><a href="{{.Href}}">{{.Title}}</a></li>{{end}}</ul>
</section>{{end}}
<section class="qz-turn" aria-labelledby="keys-h">
  <h2 id="keys-h">Your passkeys</h2>
  <ul class="qz-keys">{{range .V.Passkeys}}<li><strong>{{.Label}}</strong> <span class="qz-small">added {{.Added}}{{if .Used}}, last used {{.Used}}{{end}}</span>
    <form method="post" action="/account/passkey/remove"><input type="hidden" name="id" value="{{.ID}}"><button type="submit" class="qz-button-quiet">Remove<span class="qz-sr"> {{.Label}}</span></button></form></li>{{end}}</ul>
  <p><label for="passkey-label">Name for a new passkey</label><br>
  <input id="passkey-label" maxlength="40" placeholder="My laptop"></p>
  <p><button type="button" id="add-passkey" class="qz-button">Add a passkey</button></p>
</section>
<section class="qz-turn" aria-labelledby="rec-h">
  <h2 id="rec-h">Recovery codes</h2>
  <p>{{.V.Member.Recovery}} unused. Making new ones replaces them all.</p>
  <form method="post" action="/account/codes"><button type="submit" class="qz-button-quiet">Make new recovery codes</button></form>
</section>
<section class="qz-turn" aria-labelledby="name-h">
  <h2 id="name-h">Your name</h2>
  <form method="post" action="/account/name"><label for="name">Shown as</label><br>
    <input id="name" name="name" value="{{.V.Member.Name}}" maxlength="40" required>
    <button type="submit" class="qz-button-quiet">Save</button></form>
</section>
<section class="qz-turn" aria-labelledby="out-h">
  <h2 id="out-h">Signing out</h2>
  <form method="post" action="/account/signout" class="qz-inline"><button type="submit" class="qz-button">Sign out</button></form>
  <form method="post" action="/account/signout-all" class="qz-inline"><button type="submit" class="qz-button-quiet">Sign out everywhere</button></form>
</section>
<section class="qz-turn qz-danger" aria-labelledby="del-h">
  <h2 id="del-h">Delete your account</h2>
  <p>Deletes your account, its passkeys, recovery codes and sessions, now and for good.</p>
  <form method="post" action="/account/delete"><label for="confirm">Type <strong>delete</strong> to confirm</label><br>
    <input id="confirm" name="confirm" autocomplete="off" required>
    <button type="submit" class="qz-button-quiet">Delete my account</button></form>
</section>
{{else}}
<h1 id="account-h">Sign in to {{.V.Site}}</h1>
<section class="qz-turn" aria-labelledby="in-h">
  <h2 id="in-h">With a passkey</h2>
  <p>Your device signs you in with your fingerprint, face or screen lock. There is no password.</p>
  <p><button type="button" id="signin-button" class="qz-button">Sign in with a passkey</button></p>
</section>
<section class="qz-turn" aria-labelledby="up-h">
  <h2 id="up-h">New here?</h2>
  <form id="signup-form" method="get" action="/account">
    <p><label for="signup-name">The name others will see</label><br>
    <input id="signup-name" name="name" maxlength="40" required autocomplete="nickname"></p>
    {{if .V.Invite}}<p><label for="signup-invite">Invitation code</label><br>
    <input id="signup-invite" name="invite" required autocomplete="off" spellcheck="false"></p>{{end}}
    <p><button type="submit" class="qz-button">Create an account with a passkey</button></p>
  </form>
</section>
<section id="account-codes" class="qz-turn" aria-labelledby="new-codes-h" hidden>
  <h2 id="new-codes-h" tabindex="-1">Save your recovery codes</h2>
  <p>Each one signs you in once if you lose your passkeys. Keep them somewhere safe; they are not shown again.</p>
  <ol id="account-code-list" class="qz-codes"></ol>
  <p><a class="qz-button" href="/account">I have saved them</a></p>
</section>
<section class="qz-turn" aria-labelledby="rc-h">
  <h2 id="rc-h">Lost your passkey?</h2>
  <form method="post" action="/account/recover"><label for="code">A recovery code</label><br>
    <input id="code" name="code" autocomplete="off" spellcheck="false" required>
    <button type="submit" class="qz-button-quiet">Sign in with it</button></form>
</section>
<noscript><p class="qz-problem">Passkeys are a feature of your browser that a page reaches with JavaScript, so signing in here needs it switched on.</p></noscript>
{{end}}
<p class="qz-small">An account here is a name and the passkeys that sign you in. Nothing else is kept, and deleting it deletes all of it.</p>
</main>
<script src="/account.js" nonce="{{.V.Nonce}}" defer></script>
</body></html>`))

var gateTemplate = template.Must(template.New("gate").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>For members — {{.Site}}</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/site.css">
<link rel="stylesheet" href="/ask.css">
{{.Icon}}</head>
<body class="qz-ask"><main>
<p class="qz-home"><a href="/">{{.Site}}</a></p>
<h1>This page is for members</h1>
<p><a class="qz-button" href="/account?next={{.Next}}">Sign in</a></p>
</main></body></html>`))
