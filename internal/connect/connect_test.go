// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

var calendar = Provider{Name: "acme", Title: "Acme", AuthURL: "https://id.acme.example/authorize",
	TokenURL: "https://id.acme.example/token", RevokeURL: "https://id.acme.example/revoke", ClientID: "quilzo",
	Secret: "acme-oauth", Scopes: []string{"calendar.read", "calendar.write"}, Hosts: []string{"api.acme.example"},
	Params: map[string]string{"access_type": "offline"}}

// The person's browser is sent with a fresh state and an S256 challenge of
// a verifier kept here, the exact redirect address, and the declaration's
// own parameters; never the verifier itself.
func TestConnectingStartsWithPKCE(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pd, to, err := Begin(calendar, "https://cms.example/connections/callback", "dana", now)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	q := u.Query()
	sum := sha256.Sum256([]byte(pd.Verifier))
	if u.Host != "id.acme.example" || q.Get("response_type") != "code" || q.Get("client_id") != "quilzo" ||
		q.Get("redirect_uri") != "https://cms.example/connections/callback" || q.Get("state") != pd.State ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) ||
		q.Get("scope") != "calendar.read calendar.write" || q.Get("access_type") != "offline" {
		t.Fatalf("%s", to)
	}
	if strings.Contains(to, pd.Verifier) || !ValidState(pd.State) || pd.Person != "dana" {
		t.Fatalf("%+v", pd)
	}
	other, _, _ := Begin(calendar, "https://cms.example/connections/callback", "dana", now)
	if other.State == pd.State || other.Verifier == pd.Verifier {
		t.Fatal("two connections share a secret")
	}
	if !pd.Expired(now.Add(MaxPending+time.Second)) || pd.Expired(now.Add(time.Minute)) {
		t.Fatal("expiry")
	}
	if _, _, err := Begin(calendar, "http://cms.example/callback", "dana", now); err == nil {
		t.Error("a code sent back over plain http")
	}
}

// The code goes back with the verifier and the secret; what comes back is
// a bearer token with its expiry; a refusal says why; a refresh keeps the
// refresh token a provider did not rotate, and takes the one it did.
func TestTokensAreExchangedAndRefreshed(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pd, _, _ := Begin(calendar, "https://cms.example/connections/callback", "dana", now)
	var sent url.Values
	answer := `{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-1","scope":"calendar.read"}`
	post := func(_ context.Context, to string, form url.Values) ([]byte, error) {
		if to != calendar.TokenURL && to != calendar.RevokeURL {
			t.Errorf("posted to %s", to)
		}
		sent = form
		return []byte(answer), nil
	}
	tok, err := Exchange(context.Background(), post, calendar, "s3cret", pd, "the-code", now)
	if err != nil {
		t.Fatal(err)
	}
	if sent.Get("code_verifier") != pd.Verifier || sent.Get("grant_type") != "authorization_code" ||
		sent.Get("client_secret") != "s3cret" || sent.Get("redirect_uri") != pd.Redirect || sent.Get("code") != "the-code" {
		t.Errorf("%v", sent)
	}
	if tok.Access != "at-1" || tok.Refresh != "rt-1" || !tok.Expiry.Equal(now.Add(time.Hour)) || tok.Due(now) || !tok.Due(now.Add(time.Hour)) {
		t.Fatalf("%+v", tok)
	}
	answer = `{"access_token":"at-2","expires_in":3600}`
	again, err := Refresh(context.Background(), post, calendar, "s3cret", tok.Refresh, now.Add(time.Hour))
	if err != nil || again.Access != "at-2" || again.Refresh != "rt-1" || sent.Get("grant_type") != "refresh_token" {
		t.Fatalf("%+v %v %v", again, err, sent)
	}
	answer = `{"access_token":"at-3","refresh_token":"rt-2"}`
	if rotated, _ := Refresh(context.Background(), post, calendar, "", "rt-1", now); rotated.Refresh != "rt-2" || !rotated.Expiry.IsZero() {
		t.Fatalf("%+v", rotated)
	}
	for _, bad := range []string{`{"error":"invalid_grant","error_description":"code used"}`, `{"token_type":"bearer"}`,
		`{"access_token":"x","token_type":"mac"}`, `not json`} {
		answer = bad
		if _, err := Exchange(context.Background(), post, calendar, "", pd, "c", now); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := Exchange(context.Background(), post, calendar, "", pd, "c", now.Add(MaxPending+time.Second)); err == nil {
		t.Error("an expired connection finished")
	}
	answer = `{}`
	if err := Revoke(context.Background(), post, calendar, "", "at-1"); err != nil || sent.Get("token") != "at-1" {
		t.Fatalf("%v %v", err, sent)
	}
}

// A declaration that could send a code, a secret or a token somewhere it
// should not is refused; the templates are whole once given a client id;
// a token goes only to the hosts its provider names.
func TestADeclarationIsChecked(t *testing.T) {
	for name, edit := range map[string]func(*Provider){
		"plain http":     func(p *Provider) { p.TokenURL = "http://id.acme.example/token" },
		"no hosts":       func(p *Provider) { p.Hosts = nil },
		"wildcard host":  func(p *Provider) { p.Hosts = []string{"*.acme.example"} },
		"reserved param": func(p *Provider) { p.Params = map[string]string{"redirect_uri": "https://evil.example"} },
		"secret value":   func(p *Provider) { p.Secret = "sk live value with spaces" },
		"no client":      func(p *Provider) { p.ClientID = "" },
		"bad name":       func(p *Provider) { p.Name = "Acme Corp" },
	} {
		p := calendar
		p.Params = map[string]string{"access_type": "offline"}
		edit(&p)
		if p.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, name := range TemplateNames() {
		p := Templates[name]
		p.ClientID = "id"
		if err := p.Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !calendar.Allows("API.acme.example.") || calendar.Allows("evil.example") || calendar.Allows("acme.example") {
		t.Error("a token's hosts")
	}
}

// When a connection's tokens end is kept, refresh token included where the
// provider says (LinkedIn's refresh_token_expires_in, TikTok's
// refresh_expires_in), and when the connection stops working follows from
// it: the refresh token's end when it renews, the access token's when it
// cannot. Kept without it, a LinkedIn connection a year old or an
// Instagram token sixty days old stopped one day with nothing said before.
func TestWhenAConnectionsTokensEndIsKept(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	pd, _, _ := Begin(calendar, "https://cms.example/connections/callback", "dana", now)
	day := 24 * time.Hour
	answer := ""
	post := func(context.Context, string, url.Values) ([]byte, error) { return []byte(answer), nil }
	for _, field := range []string{"refresh_token_expires_in", "refresh_expires_in"} {
		answer = `{"access_token":"at","token_type":"Bearer","expires_in":5184000,"refresh_token":"rt","` + field + `":31536000}`
		tok, err := Exchange(context.Background(), post, calendar, "", pd, "c", now)
		if err != nil {
			t.Fatal(err)
		}
		ends := tok.Ends()
		if !tok.RefreshExpiry.Equal(now.Add(365*day)) || !ends.Access.Equal(now.Add(60*day)) || !ends.Renews ||
			!ends.Lapses().Equal(now.Add(365*day)) || ends.LapsesSoon(now.Add(300*day)) || !ends.LapsesSoon(now.Add(359*day)) {
			t.Fatalf("%s: %+v %+v", field, tok, ends)
		}
	}
	// No refresh token: the access token's end is the connection's.
	answer = `{"access_token":"at","token_type":"Bearer","expires_in":5184000}`
	tok, _ := Exchange(context.Background(), post, calendar, "", pd, "c", now)
	if ends := tok.Ends(); ends.Renews || !ends.Lapses().Equal(now.Add(60*day)) || ends.LapsesSoon(now.Add(50*day)) ||
		!ends.LapsesSoon(now.Add(54*day)) || !ends.LapsesSoon(now.Add(61*day)) {
		t.Fatalf("%+v", ends)
	}
	if said := tok.Ends().Said(time.UTC); !strings.Contains(said, "10 Jan 2027") || !strings.Contains(said, "no refresh token") {
		t.Errorf("said %q", said)
	}
	// A token kept before its ends were: not known, so never said to be soon.
	var old Token
	_ = json.Unmarshal([]byte(`{"access":"at","refresh":"rt"}`), &old)
	if ends := old.Ends(); !ends.Lapses().IsZero() || ends.LapsesSoon(now) || !strings.Contains(ends.Said(time.UTC), "not known") {
		t.Fatalf("%+v %q", ends, ends.Said(time.UTC))
	}
	if said := (Ends{}).Said(time.UTC); strings.Contains(said, "0001") || !strings.Contains(said, "not known") {
		t.Errorf("an unknown end said as %q", said)
	}
}
