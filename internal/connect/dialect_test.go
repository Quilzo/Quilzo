// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// asked is one request a provider was sent: its form, or its query for a
// GET.
type asked struct {
	method, path string
	values       url.Values
}

// platform is a social platform's endpoints over TLS: each answers what
// it was set to, by method and path, and every request is remembered.
type platform struct {
	mu      sync.Mutex
	answers map[string]string
	asked   []asked
}

func (pf *platform) answer(route, body string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.answers[route] = body
}

func (pf *platform) last() asked {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if len(pf.asked) == 0 {
		return asked{}
	}
	return pf.asked[len(pf.asked)-1]
}

func (pf *platform) all() []asked {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	return append([]asked(nil), pf.asked...)
}

func (pf *platform) count() int {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	return len(pf.asked)
}

// serve starts the platform, and returns what this package is given to
// reach it with: a form poster and a getter over the test server's own
// certificate.
func (pf *platform) serve(t *testing.T) (*httptest.Server, Poster, Getter) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		values := r.PostForm
		if r.Method == http.MethodGet {
			values = r.URL.Query()
		}
		pf.mu.Lock()
		pf.asked = append(pf.asked, asked{r.Method, r.URL.Path, values})
		body, ok := pf.answers[r.Method+" "+r.URL.Path]
		pf.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	read := func(resp *http.Response, err error) (int, http.Header, []byte, error) {
		if err != nil {
			return 0, nil, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, b, err
	}
	post := func(ctx context.Context, to string, form url.Values) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, to, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _, b, err := read(srv.Client().Do(req))
		return b, err
	}
	get := func(ctx context.Context, to string) (int, http.Header, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, to, nil)
		if err != nil {
			return 0, nil, nil, err
		}
		return read(srv.Client().Do(req))
	}
	return srv, post, get
}

const callback = "https://cms.example/connections/callback"

func authorizeQuery(t *testing.T, to string) url.Values {
	t.Helper()
	u, err := url.Parse(to)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// TikTok's Login Kit is asked in its own words at every step: client_key,
// never client_id, and its scopes separated by commas. Asked as plain
// OAuth 2, it refused the request. Its web flow is sent no PKCE challenge,
// which it does not take; the refresh token lives as long as TikTok says,
// and once that has passed the person is told so, with the date, without
// TikTok being asked.
func TestTikTokIsAskedInItsDialect(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pf := &platform{answers: map[string]string{
		"POST /v2/oauth/token/": `{"access_token":"act.1","expires_in":86400,"open_id":"o-1","refresh_expires_in":31536000,` +
			`"refresh_token":"rft.1","scope":"user.info.basic,video.upload,video.publish","token_type":"Bearer"}`,
		"POST /v2/oauth/revoke/": `{}`,
	}}
	srv, post, get := pf.serve(t)
	p := Templates["tiktok"]
	p.ClientID, p.Secret = "aw-key", "tiktok-oauth"
	p.AuthURL, p.TokenURL, p.RevokeURL = srv.URL+"/v2/auth/authorize/", srv.URL+"/v2/oauth/token/", srv.URL+"/v2/oauth/revoke/"

	pd, to, err := Begin(p, callback, "dana", now)
	if err != nil {
		t.Fatal(err)
	}
	q := authorizeQuery(t, to)
	if q.Get("client_key") != "aw-key" || q.Has("client_id") || q.Get("scope") != "user.info.basic,video.upload,video.publish" ||
		q.Get("response_type") != "code" || q.Get("redirect_uri") != callback || q.Get("state") != pd.State ||
		q.Has("code_challenge") || q.Has("code_challenge_method") {
		t.Fatalf("TikTok was asked %s", to)
	}

	tok, err := Exchange(context.Background(), post, get, p, "app-secret", pd, "the-code", now)
	if err != nil {
		t.Fatal(err)
	}
	sent := pf.last()
	if sent.method != http.MethodPost || sent.values.Get("client_key") != "aw-key" || sent.values.Has("client_id") ||
		sent.values.Get("client_secret") != "app-secret" || sent.values.Get("grant_type") != "authorization_code" ||
		sent.values.Get("code") != "the-code" || sent.values.Has("code_verifier") {
		t.Fatalf("TikTok's token endpoint was sent %v", sent.values)
	}
	if tok.Access != "act.1" || tok.Refresh != "rft.1" || !tok.Expiry.Equal(now.Add(24*time.Hour)) ||
		!tok.RefreshExpiry.Equal(now.Add(365*24*time.Hour)) || !tok.Renew.IsZero() {
		t.Fatalf("%+v", tok)
	}

	// A refresh rotates the refresh token, and TikTok says how long the
	// new one lives.
	pf.answer("POST /v2/oauth/token/", `{"access_token":"act.2","expires_in":86400,"refresh_expires_in":31449600,`+
		`"refresh_token":"rft.2","token_type":"Bearer"}`)
	at := now.Add(7 * 24 * time.Hour)
	again, err := Refresh(context.Background(), post, get, p, "app-secret", tok, at)
	if err != nil {
		t.Fatal(err)
	}
	sent = pf.last()
	if sent.values.Get("grant_type") != "refresh_token" || sent.values.Get("refresh_token") != "rft.1" ||
		sent.values.Get("client_key") != "aw-key" || sent.values.Has("client_id") || sent.values.Get("client_secret") != "app-secret" {
		t.Fatalf("TikTok's refresh was sent %v", sent.values)
	}
	if again.Access != "act.2" || again.Refresh != "rft.2" || !again.RefreshExpiry.Equal(at.Add(31449600*time.Second)) {
		t.Fatalf("%+v", again)
	}

	n := pf.count()
	if _, err := Refresh(context.Background(), post, get, p, "app-secret", again, again.RefreshExpiry); err == nil ||
		!strings.Contains(err.Error(), "connect again") || !strings.Contains(err.Error(), again.RefreshExpiry.Format("2 Jan 2006")) {
		t.Fatalf("a lapsed refresh token: %v", err)
	}
	if pf.count() != n {
		t.Fatal("TikTok was asked to refresh with a refresh token it had said was lapsed")
	}

	if err := Revoke(context.Background(), post, p, "app-secret", "act.2"); err != nil {
		t.Fatal(err)
	}
	if sent = pf.last(); sent.path != "/v2/oauth/revoke/" || sent.values.Get("client_key") != "aw-key" ||
		sent.values.Has("client_id") || sent.values.Get("token") != "act.2" {
		t.Fatalf("TikTok's revocation was sent %v", sent.values)
	}
}

// Instagram issues no refresh token: the token a code buys lasts an hour,
// and is exchanged at once for one that lasts sixty days, renewed by
// exchanging it once it is a day old. Kept as it came, with a refresh
// demanded of it, every Instagram connection lapsed within the hour and
// said "connect again".
func TestInstagramTokensAreExchangedAndRenewed(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	const granted = "instagram_business_basic,instagram_business_content_publish"
	pf := &platform{answers: map[string]string{
		"POST /oauth/access_token":  `{"data":[{"access_token":"ig-short","user_id":"17841","permissions":"` + granted + `"}]}`,
		"GET /access_token":         `{"access_token":"ig-long-1","token_type":"bearer","expires_in":5184000}`,
		"GET /refresh_access_token": `{"access_token":"ig-long-2","token_type":"bearer","expires_in":5184000}`,
	}}
	srv, post, get := pf.serve(t)
	p := Templates["instagram"]
	p.ClientID, p.Secret = "ig-app", "instagram-oauth"
	p.AuthURL, p.TokenURL = srv.URL+"/oauth/authorize", srv.URL+"/oauth/access_token"
	p.ExchangeURL, p.RenewURL = srv.URL+"/access_token", srv.URL+"/refresh_access_token"

	pd, to, err := Begin(p, callback, "dana", now)
	if err != nil {
		t.Fatal(err)
	}
	if q := authorizeQuery(t, to); q.Get("client_id") != "ig-app" || q.Get("scope") != granted || q.Get("code_challenge") == "" {
		t.Fatalf("Instagram was asked %s", to)
	}

	tok, err := Exchange(context.Background(), post, get, p, "app-secret", pd, "the-code", now)
	if err != nil {
		t.Fatal(err)
	}
	all := pf.all()
	if len(all) != 2 {
		t.Fatalf("asked %+v", all)
	}
	code, swap := all[0], all[1]
	if code.method != http.MethodPost || code.values.Get("grant_type") != "authorization_code" ||
		code.values.Get("client_secret") != "app-secret" || code.values.Get("client_id") != "ig-app" {
		t.Fatalf("Instagram's token endpoint was sent %v", code.values)
	}
	if swap.method != http.MethodGet || swap.path != "/access_token" || swap.values.Get("grant_type") != "ig_exchange_token" ||
		swap.values.Get("access_token") != "ig-short" || swap.values.Get("client_secret") != "app-secret" {
		t.Fatalf("the exchange was %+v", swap)
	}
	if tok.Access != "ig-long-1" || tok.Refresh != "" || !tok.Expiry.Equal(now.Add(60*24*time.Hour)) ||
		tok.Scope != granted || !tok.Renew.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("%+v", tok)
	}
	if tok.Due(now.Add(23*time.Hour)) || !tok.Due(now.Add(24*time.Hour)) || tok.Lapsing(now.Add(24*time.Hour)) {
		t.Fatal("a long-lived token is renewed once it is a day old, and works until then and after")
	}

	at := now.Add(25 * time.Hour)
	again, err := Refresh(context.Background(), post, get, p, "app-secret", tok, at)
	if err != nil {
		t.Fatal(err)
	}
	if renewed := pf.last(); renewed.method != http.MethodGet || renewed.path != "/refresh_access_token" ||
		renewed.values.Get("grant_type") != "ig_refresh_token" || renewed.values.Get("access_token") != "ig-long-1" ||
		renewed.values.Has("client_secret") {
		t.Fatalf("the renewal was %+v", renewed)
	}
	if again.Access != "ig-long-2" || !again.Expiry.Equal(at.Add(60*24*time.Hour)) || !again.Renew.Equal(at.Add(24*time.Hour)) ||
		again.Scope != granted {
		t.Fatalf("%+v", again)
	}

	// Meta renews a token only before it expires: past that, the person
	// is told, with the date, and Meta is not asked.
	n := pf.count()
	if _, err := Refresh(context.Background(), post, get, p, "app-secret", again, again.Expiry); err == nil ||
		!strings.Contains(err.Error(), "connect again") || pf.count() != n {
		t.Fatalf("an expired token: %v", err)
	}

	// Refusals in either of Meta's shapes are said, not taken for an
	// answer in no JSON.
	pf.answer("GET /refresh_access_token", `{"error":{"message":"Error validating access token","type":"OAuthException","code":190}}`)
	if _, err := Refresh(context.Background(), post, get, p, "app-secret", tok, at); err == nil ||
		!strings.Contains(err.Error(), "Error validating access token") {
		t.Fatalf("a Graph API refusal: %v", err)
	}
	pf.answer("POST /oauth/access_token", `{"error_type":"OAuthException","code":400,"error_message":"Invalid authorization code"}`)
	pd, _, _ = Begin(p, callback, "dana", now)
	if _, err := Exchange(context.Background(), post, get, p, "app-secret", pd, "used", now); err == nil ||
		!strings.Contains(err.Error(), "Invalid authorization code") {
		t.Fatalf("an Instagram login refusal: %v", err)
	}
}

// The exchange's address carries the client secret and the token, and an
// error quoting it would carry them into the audit log and onto the
// screen; it is said without them.
func TestAnExchangeThatFailsDoesNotSayTheSecret(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pf := &platform{answers: map[string]string{
		"POST /oauth/access_token": `{"access_token":"fb-short+/=","token_type":"bearer","expires_in":5400}`,
	}}
	srv, post, _ := pf.serve(t)
	p := Templates["facebook"]
	p.ClientID, p.Secret = "fb-app", "facebook-oauth"
	p.AuthURL, p.TokenURL = srv.URL+"/dialog/oauth", srv.URL+"/oauth/access_token"
	failing := func(_ context.Context, u string) (int, http.Header, []byte, error) {
		return 0, nil, nil, fmt.Errorf("Get %q: connection reset by peer", u)
	}
	pd, _, _ := Begin(p, callback, "dana", now)
	_, err := Exchange(context.Background(), post, failing, p, "app secret&=", pd, "the-code", now)
	if err == nil {
		t.Fatal("an exchange that failed connected")
	}
	for _, secret := range []string{"app secret&=", url.QueryEscape("app secret&="), "fb-short+/=", url.QueryEscape("fb-short+/=")} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error says %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "connection reset by peer") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

// Facebook Login is exchanged and renewed the same way, with
// fb_exchange_token, at its token endpoint.
func TestFacebookTokensAreExchangedAndRenewed(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pf := &platform{answers: map[string]string{
		"POST /oauth/access_token": `{"access_token":"fb-short","token_type":"bearer","expires_in":5400}`,
		"GET /oauth/access_token":  `{"access_token":"fb-long-1","token_type":"bearer","expires_in":5183944}`,
	}}
	srv, post, get := pf.serve(t)
	p := Templates["facebook"]
	p.ClientID, p.Secret = "fb-app", "facebook-oauth"
	p.AuthURL, p.TokenURL = srv.URL+"/dialog/oauth", srv.URL+"/oauth/access_token"

	pd, to, err := Begin(p, callback, "dana", now)
	if err != nil {
		t.Fatal(err)
	}
	if q := authorizeQuery(t, to); q.Get("client_id") != "fb-app" ||
		q.Get("scope") != "pages_show_list,pages_read_engagement,pages_manage_posts" || q.Get("code_challenge") == "" {
		t.Fatalf("Facebook was asked %s", to)
	}
	tok, err := Exchange(context.Background(), post, get, p, "app-secret", pd, "the-code", now)
	if err != nil {
		t.Fatal(err)
	}
	if swap := pf.last(); swap.method != http.MethodGet || swap.values.Get("grant_type") != "fb_exchange_token" ||
		swap.values.Get("fb_exchange_token") != "fb-short" || swap.values.Get("client_id") != "fb-app" ||
		swap.values.Get("client_secret") != "app-secret" {
		t.Fatalf("the exchange was %+v", swap)
	}
	if tok.Access != "fb-long-1" || !tok.Expiry.Equal(now.Add(5183944*time.Second)) || !tok.Renew.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("%+v", tok)
	}
	pf.answer("GET /oauth/access_token", `{"access_token":"fb-long-2","token_type":"bearer","expires_in":5183944}`)
	at := now.Add(48 * time.Hour)
	again, err := Refresh(context.Background(), post, get, p, "app-secret", tok, at)
	if err != nil {
		t.Fatal(err)
	}
	if renewed := pf.last(); renewed.values.Get("grant_type") != "fb_exchange_token" ||
		renewed.values.Get("fb_exchange_token") != "fb-long-1" || renewed.values.Get("client_secret") != "app-secret" {
		t.Fatalf("the renewal was %+v", renewed)
	}
	if again.Access != "fb-long-2" || !again.Renew.Equal(at.Add(24*time.Hour)) {
		t.Fatalf("%+v", again)
	}
}

// LinkedIn's refresh token lapses 365 days after it was first issued,
// however often it is used: the date is kept from the first issue, a
// refresh never moves it later, and past it the person is told to connect
// again rather than LinkedIn being asked. Without one, which LinkedIn
// gives only to the apps it has approved, the refusal says so.
func TestLinkedInsRefreshTokenLapsesAYearFromFirstIssue(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pf := &platform{answers: map[string]string{
		"POST /oauth/v2/accessToken": `{"access_token":"li-1","expires_in":5184000,"refresh_token":"li-r",` +
			`"refresh_token_expires_in":31536000,"scope":"openid,profile,w_member_social"}`,
	}}
	srv, post, get := pf.serve(t)
	p := Templates["linkedin"]
	p.ClientID, p.Secret = "li-app", "linkedin-oauth"
	p.AuthURL, p.TokenURL = srv.URL+"/oauth/v2/authorization", srv.URL+"/oauth/v2/accessToken"

	pd, to, err := Begin(p, callback, "dana", now)
	if err != nil {
		t.Fatal(err)
	}
	if q := authorizeQuery(t, to); q.Get("client_id") != "li-app" || q.Get("scope") != "openid profile w_member_social" ||
		q.Get("code_challenge") == "" {
		t.Fatalf("LinkedIn was asked %s", to)
	}
	tok, err := Exchange(context.Background(), post, get, p, "app-secret", pd, "the-code", now)
	if err != nil {
		t.Fatal(err)
	}
	year := now.Add(365 * 24 * time.Hour)
	if tok.Refresh != "li-r" || !tok.RefreshExpiry.Equal(year) {
		t.Fatalf("%+v", tok)
	}

	// LinkedIn counts down from the first issue: 65 days left, 300 days on.
	pf.answer("POST /oauth/v2/accessToken", `{"access_token":"li-2","expires_in":5184000,"refresh_token":"li-r",`+
		`"refresh_token_expires_in":5616000}`)
	again, err := Refresh(context.Background(), post, get, p, "app-secret", tok, now.Add(300*24*time.Hour))
	if err != nil || again.Access != "li-2" || !again.RefreshExpiry.Equal(year) {
		t.Fatalf("%+v %v", again, err)
	}
	// An answer that says nothing of it, or says a later date, does not
	// start the year again.
	for _, body := range []string{`{"access_token":"li-3","expires_in":5184000,"refresh_token":"li-r"}`,
		`{"access_token":"li-3","expires_in":5184000,"refresh_token":"li-r","refresh_token_expires_in":31536000}`} {
		pf.answer("POST /oauth/v2/accessToken", body)
		later, err := Refresh(context.Background(), post, get, p, "app-secret", again, now.Add(330*24*time.Hour))
		if err != nil || !later.RefreshExpiry.Equal(year) {
			t.Fatalf("%s: %+v %v", body, later, err)
		}
	}
	n := pf.count()
	if _, err := Refresh(context.Background(), post, get, p, "app-secret", again, year); err == nil ||
		!strings.Contains(err.Error(), year.Format("2 Jan 2006")) || pf.count() != n {
		t.Fatalf("a lapsed refresh token: %v", err)
	}

	pf.answer("POST /oauth/v2/accessToken", `{"access_token":"li-1","expires_in":5184000}`)
	pd, _, _ = Begin(p, callback, "dana", now)
	plain, err := Exchange(context.Background(), post, get, p, "app-secret", pd, "the-code", now)
	if err != nil || plain.Refresh != "" || !plain.RefreshExpiry.IsZero() {
		t.Fatalf("%+v %v", plain, err)
	}
	if _, err := Refresh(context.Background(), post, get, p, "app-secret", plain, now.Add(61*24*time.Hour)); err == nil ||
		!strings.Contains(err.Error(), "approved") {
		t.Fatalf("no refresh token: %v", err)
	}
}

// Every provider declared before there were dialects speaks the standard
// still: a declaration naming none reads, checks, asks and is written back
// as it was, and naming oauth2 is the same as naming none. A dialect is
// one of the list, and what it departs in cannot be stretched by a
// declaration.
func TestADeclarationWithoutADialectIsUnchanged(t *testing.T) {
	const declared = `{"name":"acme","title":"Acme","auth_url":"https://id.acme.example/authorize",` +
		`"token_url":"https://id.acme.example/token","client_id":"quilzo","secret":"acme-oauth",` +
		`"scopes":["calendar.read","calendar.write"],"hosts":["api.acme.example"]}`
	var p Provider
	if err := json.Unmarshal([]byte(declared), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(p); string(b) != declared {
		t.Fatalf("written back as %s", b)
	}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	named := p
	named.Dialect = OAuth2
	for _, d := range []Provider{p, named} {
		pd, to, err := Begin(d, callback, "dana", now)
		if err != nil {
			t.Fatal(err)
		}
		q := authorizeQuery(t, to)
		if q.Get("client_id") != "quilzo" || q.Has("client_key") || q.Get("scope") != "calendar.read calendar.write" ||
			q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") != pd.State {
			t.Fatalf("%q: %s", d.Dialect, to)
		}
	}

	for name, edit := range map[string]func(*Provider){
		"no such dialect":          func(p *Provider) { p.Dialect = "tiktok2" },
		"a dialect without secret": func(p *Provider) { p.Dialect, p.Secret = TikTok, "" },
		"two scopes as one":        func(p *Provider) { p.Dialect, p.Scopes = TikTok, []string{"video.upload,video.publish"} },
		"client_key as a param":    func(p *Provider) { p.Dialect, p.Params = TikTok, map[string]string{"client_key": "other"} },
		"an exchange not Meta's":   func(p *Provider) { p.ExchangeURL = "https://id.acme.example/exchange" },
		"an exchange over http": func(p *Provider) {
			p.Dialect, p.ExchangeURL = MetaFacebook, "http://graph.facebook.example/oauth/access_token"
		},
	} {
		d := p
		edit(&d)
		if d.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A provider declared by hand at a social platform's site speaks that
// platform's dialect, whatever its address there; one on any other site,
// a look-alike's included, speaks the standard.
func TestAPlatformsSiteSaysItsDialect(t *testing.T) {
	for raw, want := range map[string]Dialect{
		"https://www.tiktok.com/v2/auth/authorize/":          TikTok,
		"https://tiktok.com/v2/auth/authorize/":              TikTok,
		"https://www.instagram.com/oauth/authorize":          MetaInstagram,
		"https://api.instagram.com/oauth/authorize":          MetaInstagram,
		"https://m.facebook.com/dialog/oauth":                MetaFacebook,
		"https://WWW.LINKEDIN.COM./oauth/v2/authorization":   LinkedIn,
		"https://accounts.google.com/o/oauth2/v2/auth":       "",
		"https://id.acme.example/authorize":                  "",
		"https://eviltiktok.com/v2/auth/authorize/":          "",
		"https://www.tiktok.com.acme.example/oauth/v2/authz": "",
		"not an address": "",
	} {
		if got := PlatformDialect(raw); got != want {
			t.Errorf("%s: %q, not %q", raw, got, want)
		}
	}
}
