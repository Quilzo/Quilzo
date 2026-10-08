// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/member"
	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/webauthn"
)

const memberOrigin = "https://example.org"

// device is a passkey authenticator, as a browser would drive one.
type device struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newDevice(t *testing.T) *device {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &device{key: k, id: id, count: 1}
}

func (d *device) authData() []byte {
	sum := sha256.Sum256([]byte("example.org"))
	out := append(append([]byte{}, sum[:]...), 0x05)
	return binary.BigEndian.AppendUint32(out, d.count)
}

func clientData(kind, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge,
		"origin": memberOrigin, "crossOrigin": false})
	return b
}

func (d *device) registration(t *testing.T, challenge string) map[string]any {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(d.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"challenge": challenge, "id": enc(d.id),
		"clientDataJSON":    enc(clientData("webauthn.create", challenge)),
		"authenticatorData": enc(d.authData()), "publicKey": enc(spki),
		"algorithm": webauthn.AlgES256}
}

func (d *device) assertion(t *testing.T, challenge string) map[string]any {
	t.Helper()
	d.count++
	cd := clientData("webauthn.get", challenge)
	ad := d.authData()
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"challenge": challenge, "id": enc(d.id),
		"clientDataJSON": enc(cd), "authenticatorData": enc(ad), "signature": enc(sig)}
}

// visitor is a browser: it keeps its cookies and says where it came from.
type visitor struct {
	t      *testing.T
	st     *Site
	cookie string
	// site is what the browser reports in Sec-Fetch-Site.
	site string
}

func (v *visitor) do(method, path string, body []byte, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:4000"
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if v.site != "" {
		req.Header.Set("Sec-Fetch-Site", v.site)
	}
	if v.cookie != "" {
		req.AddCookie(&http.Cookie{Name: MemberCookie, Value: v.cookie})
	}
	w := httptest.NewRecorder()
	v.st.Handler().ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.Name == MemberCookie {
			v.cookie = c.Value
			if c.MaxAge < 0 {
				v.cookie = ""
			}
		}
	}
	return w
}

func (v *visitor) json(path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	b, _ := json.Marshal(body)
	w := v.do(http.MethodPost, path, b, "application/json")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func (v *visitor) form(path string, values url.Values) *httptest.ResponseRecorder {
	return v.do(http.MethodPost, path, []byte(values.Encode()), "application/x-www-form-urlencoded")
}

var memberSiteParty = webauthn.Party{ID: "example.org", Origin: memberOrigin}

// memberID is the account the visitor is signed in to.
func (v *visitor) memberID(t *testing.T) string {
	t.Helper()
	m, err := v.st.Members.Store.SessionMember(v.cookie)
	if err != nil {
		t.Fatalf("the visitor is not signed in: %v", err)
	}
	return m.ID
}

func memberSite(t *testing.T, mode string) (*Site, *member.Store) {
	t.Helper()
	st := published(t, map[string]any{
		"index":  map[string]any{"title": "Home", "body": "Welcome to the club."},
		"lounge": map[string]any{"title": "The lounge", "body": "Members talk about the secret recipe here.", MembersOnlyField: true},
	})
	store, err := member.Open(filepath.Join(t.TempDir(), "members"))
	if err != nil {
		t.Fatal(err)
	}
	st.Members = &Members{Store: store, Mode: mode,
		Party: webauthn.Party{ID: "example.org", Origin: memberOrigin}}
	return st, store
}

func signUp(t *testing.T, v *visitor, d *device, name, invite string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	w, start := v.json("/account/signup/start", map[string]string{"name": name, "invite": invite})
	if w.Code != 200 {
		return w, start
	}
	ch, _ := start["challenge"].(string)
	return v.json("/account/signup/finish", d.registration(t, ch))
}

func signIn(t *testing.T, v *visitor, d *device) *httptest.ResponseRecorder {
	t.Helper()
	_, start := v.json("/account/signin/start", nil)
	ch, _ := start["challenge"].(string)
	w, _ := v.json("/account/signin/finish", d.assertion(t, ch))
	return w
}

func TestAVisitorMakesAnAccountAndSignsIn(t *testing.T) {
	st, store := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	d := newDevice(t)

	w, out := signUp(t, v, d, "Ada", "")
	if w.Code != 200 {
		t.Fatalf("signing up: %d %v", w.Code, out)
	}
	codes, _ := out["codes"].([]any)
	if len(codes) != member.RecoveryCodes || v.cookie == "" {
		t.Fatalf("signed up with %d codes and cookie %q", len(codes), v.cookie)
	}
	// The cookie is the kind a browser keeps to this host, over HTTPS, away
	// from scripts.
	cookie := w.Header().Get("Set-Cookie")
	for _, part := range []string{MemberCookie + "=", "Path=/", "Secure", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(cookie, part) {
			t.Errorf("the session cookie lacks %s: %s", part, cookie)
		}
	}
	if strings.Contains(cookie, "Domain=") {
		t.Errorf("the session cookie is shared with other hosts: %s", cookie)
	}
	if body := v.do(http.MethodGet, "/account", nil, "").Body.String(); !strings.Contains(body, "Hello, Ada") {
		t.Error("the account page does not know who is signed in")
	}

	// Signed out, then in again with the passkey.
	v.form("/account/signout", nil)
	if v.cookie != "" {
		t.Fatal("signing out left the cookie")
	}
	if w := signIn(t, v, d); w.Code != 200 || v.cookie == "" {
		t.Fatalf("signing in: %d", w.Code)
	}
	list, _ := store.List()
	if len(list) != 1 || list[0].Name != "Ada" {
		t.Errorf("the store holds %v", list)
	}
}

// A members' page is for members, and nothing public mentions it.
func TestAMembersPageIsForMembersOnly(t *testing.T) {
	st, _ := memberSite(t, "open")
	st.Assistants = &Assistants{Set: func() (*assistant.Set, error) {
		set := &assistant.Set{}
		_ = set.Put(assistant.Assistant{Name: "help", Title: "Help", Public: true, Static: true})
		return set, nil
	}}
	anon := &visitor{t: t, st: st, site: "same-origin"}

	w := anon.do(http.MethodGet, "/lounge", nil, "")
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "secret recipe") ||
		strings.Contains(w.Body.String(), "The lounge") {
		t.Fatalf("a stranger asking for the lounge got %d", w.Code)
	}
	for _, path := range []string{"/sitemap.xml", "/llms.txt", "/search.json?q=recipe",
		"/ask/help/knowledge.json", "/ask/help?q=what+do+members+talk+about"} {
		if body := anon.do(http.MethodGet, path, nil, "").Body.String(); strings.Contains(body, "secret recipe") ||
			strings.Contains(body, "/lounge") {
			t.Errorf("%s mentions the members' page", path)
		}
	}
	files, err := st.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if strings.Contains(string(b), "secret recipe") {
			t.Errorf("the static copy carries the members' page in %s", name)
		}
	}

	m := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, m, newDevice(t), "Ada", "")
	w = m.do(http.MethodGet, "/lounge", nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "The lounge") {
		t.Fatalf("a member asking for the lounge got %d:\n%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "Cookie" {
		t.Errorf("a members' page is cacheable: %q %q",
			w.Header().Get("Cache-Control"), w.Header().Get("Vary"))
	}
	if !strings.Contains(m.do(http.MethodGet, "/account", nil, "").Body.String(), `href="/lounge"`) {
		t.Error("the account page does not list the pages for members")
	}
}

// Every change has to come from this site's own pages.
func TestAnotherSiteCannotActForAMember(t *testing.T) {
	st, store := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, v, newDevice(t), "Ada", "")
	m, _ := store.List()

	for _, from := range []string{"cross-site", "same-site", "none"} {
		evil := &visitor{t: t, st: st, cookie: v.cookie, site: from}
		w := evil.form("/account/delete", url.Values{"confirm": {"delete"}})
		if w.Code != http.StatusForbidden {
			t.Errorf("a delete sent with Sec-Fetch-Site %s answered %d", from, w.Code)
		}
	}
	// No Sec-Fetch-Site: then Origin decides, and a missing one is refused.
	noHeaders := &visitor{t: t, st: st, cookie: v.cookie}
	if w := noHeaders.form("/account/delete", url.Values{"confirm": {"delete"}}); w.Code != http.StatusForbidden {
		t.Errorf("a delete with neither header answered %d", w.Code)
	}
	if _, err := store.Get(m[0].ID); err != nil {
		t.Fatal("a cross-site request deleted the account")
	}
}

func TestAnInvitationIsNeededWhenSignUpIsByInvitation(t *testing.T) {
	st, store := memberSite(t, "invite")
	v := &visitor{t: t, st: st, site: "same-origin"}
	if w, _ := signUp(t, v, newDevice(t), "Ada", ""); w.Code == 200 {
		t.Fatal("an account was made with no invitation")
	}
	if w, _ := signUp(t, v, newDevice(t), "Ada", "0000-0000-0000-0000"); w.Code == 200 {
		t.Fatal("an account was made with a made-up invitation")
	}
	code, _, _ := store.NewInvite("staff", "")
	if w, out := signUp(t, v, newDevice(t), "Ada", code); w.Code != 200 {
		t.Fatalf("a real invitation: %d %v", w.Code, out)
	}
	other := &visitor{t: t, st: st, site: "same-origin"}
	if w, _ := signUp(t, other, newDevice(t), "Bo", code); w.Code == 200 {
		t.Error("one invitation made two accounts")
	}
}

func TestARecoveryCodeSignsInOnce(t *testing.T) {
	st, _ := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	_, out := signUp(t, v, newDevice(t), "Ada", "")
	code := out["codes"].([]any)[0].(string)
	v.form("/account/signout", nil)

	if w := v.form("/account/recover", url.Values{"code": {code}}); w.Code != http.StatusSeeOther || v.cookie == "" {
		t.Fatalf("recovering: %d", w.Code)
	}
	v.form("/account/signout", nil)
	if w := v.form("/account/recover", url.Values{"code": {code}}); w.Code == http.StatusSeeOther || v.cookie != "" {
		t.Error("a recovery code worked twice")
	}
}

// A challenge answers once, for the ceremony it was issued for.
func TestAPasskeyAnswerCannotBeReplayed(t *testing.T) {
	st, _ := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	d := newDevice(t)
	signUp(t, v, d, "Ada", "")
	v.form("/account/signout", nil)

	_, start := v.json("/account/signin/start", nil)
	ch := start["challenge"].(string)
	answer := d.assertion(t, ch)
	if w, _ := v.json("/account/signin/finish", answer); w.Code != 200 {
		t.Fatalf("the first answer: %d", w.Code)
	}
	v.form("/account/signout", nil)
	if w, _ := v.json("/account/signin/finish", answer); w.Code == 200 || v.cookie != "" {
		t.Error("the same signed answer signed in twice")
	}
	// A sign-up challenge is not a sign-in one.
	_, up := v.json("/account/signup/start", map[string]string{"name": "Eve"})
	if w, _ := v.json("/account/signin/finish", d.assertion(t, up["challenge"].(string))); w.Code == 200 {
		t.Error("a sign-up challenge was used to sign in")
	}
}

func TestDeletingAnAccountEndsItEverywhere(t *testing.T) {
	st, store := memberSite(t, "open")
	a := &visitor{t: t, st: st, site: "same-origin"}
	d := newDevice(t)
	signUp(t, a, d, "Ada", "")
	b := &visitor{t: t, st: st, site: "same-origin"}
	signIn(t, b, d)

	if w := a.form("/account/delete", url.Values{"confirm": {"nope"}}); w.Code == http.StatusSeeOther {
		t.Fatal("an account was deleted without the confirmation")
	}
	if w := a.form("/account/delete", url.Values{"confirm": {"delete"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("deleting: %d", w.Code)
	}
	if list, _ := store.List(); len(list) != 0 {
		t.Error("the account is still stored")
	}
	if w := b.do(http.MethodGet, "/lounge", nil, ""); w.Code != http.StatusForbidden {
		t.Error("another browser of the deleted account still reads members' pages")
	}
	if w := signIn(t, a, d); w.Code == 200 {
		t.Error("the deleted account's passkey still signs in")
	}
}

// With accounts off, nothing about them exists.
func TestWithAccountsOffThereAreNone(t *testing.T) {
	st, _ := memberSite(t, "off")
	v := &visitor{t: t, st: st, site: "same-origin"}
	if w := v.do(http.MethodGet, "/account", nil, ""); w.Code != 404 {
		t.Errorf("/account with accounts off: %d", w.Code)
	}
	if w, _ := v.json("/account/signup/start", map[string]string{"name": "Ada"}); w.Code != 404 {
		t.Errorf("signing up with accounts off: %d", w.Code)
	}
	if w := v.do(http.MethodGet, "/lounge", nil, ""); w.Code != 404 ||
		strings.Contains(w.Body.String(), "secret recipe") {
		t.Errorf("a members' page with accounts off: %d", w.Code)
	}
}

// The account page runs its one script by nonce, and says nothing a
// redirect could put words into.
func TestTheAccountPageRunsOnlyItsOwnScript(t *testing.T) {
	st, _ := memberSite(t, "open")
	v := &visitor{t: t, st: st}
	w := v.do(http.MethodGet, "/account?done=%3Cscript%3Ealert(1)%3C/script%3E", nil, "")
	body := w.Body.String()
	if strings.Contains(body, "alert(1)") {
		t.Error("the address put words on the page")
	}
	csp := w.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if m == nil || !strings.Contains(body, `nonce="`+m[1]+`"`) {
		t.Errorf("the page's script and its policy disagree:\n  %s", csp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the account page is cacheable")
	}
}

// Search answers only from pages a visitor may read.
//
// The index holds every published page, and both the search page and the
// API answered from it unfiltered: searching for a word on a members' page,
// or on one whose publish window had not opened, returned its title and
// address to anybody.
func TestSearchDoesNotNameAPageAVisitorCannotRead(t *testing.T) {
	st, _ := memberSite(t, "open")
	all := map[string]any{
		"index":  map[string]any{"title": "Home", "body": "Welcome to the club."},
		"lounge": map[string]any{"title": "The lounge", "body": "the secret recipe", MembersOnlyField: true},
		"later":  map[string]any{"title": "Coming soon", "body": "the secret launch", "starts": "2099-01-01"},
	}
	idx := search.Build("", all)
	st.Search = idx
	v := &visitor{t: t, st: st}
	for _, q := range []string{"secret", "recipe", "launch"} {
		body := v.do(http.MethodGet, "/search.json?q="+q, nil, "").Body.String()
		if strings.Contains(body, "lounge") || strings.Contains(body, "later") {
			t.Errorf("searching %q named a page nobody may read: %s", q, body)
		}
	}
}
