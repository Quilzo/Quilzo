// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dpop"
	"github.com/quilzo/quilzo/internal/federate"
	"github.com/quilzo/quilzo/internal/oidc"
)

func programKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := dpop.PublicJWK(&k.PublicKey)
	thumb, _ := dpop.Thumbprint(pub)
	return k, thumb
}

func proved(t *testing.T, key *ecdsa.PrivateKey, method, url, token string) string {
	t.Helper()
	p, err := dpop.Prove(key, method, url, token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A token bound to a key works at the agent interface only with a fresh
// proof by that key, once, and nowhere as a bearer token.
func TestABoundTokenNeedsAProofByItsKey(t *testing.T) {
	r := newIfaceRig(t)
	key, thumb := programKey(t)
	secret, tok, err := r.srv.Tokens.Issue("program", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.srv.Tokens.BindKey(tok.ID, thumb); err != nil {
		t.Fatal(err)
	}
	if w := r.mcpCall(t, secret); w.Code != http.StatusUnauthorized ||
		!strings.Contains(strings.Join(w.Header().Values("WWW-Authenticate"), " "), "DPoP") {
		t.Fatalf("a bound token worked as a bearer token: %d %v", w.Code, w.Header())
	}
	call := func(proof string) *httptest.ResponseRecorder {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quilzo_read","arguments":{"operation":"whoami"},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "quilzo_read")
		req.Header.Set("Authorization", "DPoP "+secret)
		req.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(w, req)
		return w
	}
	good := proved(t, key, "POST", "http://example.com/mcp", secret)
	if w := call(good); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "you are editor") {
		t.Fatalf("a bound token with its proof was refused: %d %s", w.Code, w.Body)
	}
	if w := call(good); w.Code != http.StatusUnauthorized {
		t.Error("a proof was used twice")
	}
	other, _ := programKey(t)
	if w := call(proved(t, other, "POST", "http://example.com/mcp", secret)); w.Code != http.StatusUnauthorized {
		t.Error("another key's proof was accepted")
	}
	if w := call(proved(t, key, "POST", "http://example.com/a2a", secret)); w.Code != http.StatusUnauthorized {
		t.Error("a proof for another address was accepted")
	}
	if w := get(t, r.srv, "/today", secret); w.Code == http.StatusOK {
		t.Error("a bound token opened the admin")
	}
}

func exchange(t *testing.T, srv *Server, form url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/token/exchange", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// A token is exchanged for a narrower one that lasts minutes, bound to the
// key that proved when one did; it never widens.
func TestATokenIsExchangedForANarrowerShortOne(t *testing.T) {
	srv, token := setup(t)
	form := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {token},
		"subject_token_type": {typeAccessToken}, "scope": {"reader"}, "resource": {"/about"}}
	w := exchange(t, srv, form, "")
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got.TokenType != "Bearer" || got.ExpiresIn > int64(auth.DefaultSessionTTL/time.Second) || got.IssuedTokenType != typeAccessToken {
		t.Errorf("%+v", got)
	}
	short, err := srv.Tokens.Authenticate(got.AccessToken, time.Now())
	if err != nil || short.Role != auth.RoleReader || short.Resource != "/about" {
		t.Fatalf("%+v %v", short, err)
	}
	key, thumb := programKey(t)
	w = exchange(t, srv, form, proved(t, key, "POST", "http://example.com/token/exchange", ""))
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got.TokenType != "DPoP" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, err := srv.Tokens.Authenticate(got.AccessToken, time.Now()); !errors.Is(err, auth.ErrKeyBound) {
		t.Errorf("the bound session worked as a bearer token: %v", err)
	}
	if _, err := srv.Tokens.AuthenticateProved(got.AccessToken, "", thumb, time.Now()); err != nil {
		t.Errorf("the bound session does not answer to its key: %v", err)
	}
	form.Set("scope", "admin")
	reader := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {short.ID}, "subject_token_type": {typeAccessToken}}
	if w := exchange(t, srv, reader, ""); w.Code == http.StatusOK {
		t.Error("something that is not a token was exchanged")
	}
	if w := exchange(t, srv, url.Values{"grant_type": {"password"}}, ""); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "unsupported_grant_type") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

type oneRSA struct{ k crypto.PublicKey }

func (k oneRSA) Key(string) (crypto.PublicKey, error) { return k.k, nil }

// A CI job's identity token, from an issuer and repository a trust names,
// is exchanged for a token the trust says it may have, once.
func TestACIJobExchangesItsIdentityToken(t *testing.T) {
	srv, _ := setup(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv.Federation = &Federation{
		Trusts: func() ([]federate.Trust, error) {
			return []federate.Trust{{Name: "docs-ci", Issuer: federate.GitHub, Audience: "https://admin.example",
				Claims: map[string]string{"repository": "octo/docs"}, Principal: "ci:docs", Role: auth.RoleAuthor,
				Resource: "/docs", TTL: "15m"}}, nil
		},
		Keys: func(context.Context, string) (oidc.KeySource, []oidc.Algorithm, error) {
			return oneRSA{&key.PublicKey}, []oidc.Algorithm{oidc.RS256}, nil
		},
	}
	now := time.Now()
	n := 0
	sign := func(repo string) string {
		n++
		h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
		c, _ := json.Marshal(map[string]any{"iss": federate.GitHub, "aud": "https://admin.example",
			"repository": repo, "ref": "refs/heads/main", "run_id": "42", "jti": "j-" + repo + string(rune('a'+n)),
			"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()})
		in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
		sum := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		return in + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	form := func(assertion string) url.Values {
		return url.Values{"grant_type": {grantTokenExchange}, "subject_token": {assertion}, "subject_token_type": {typeIDToken}}
	}
	job := sign("octo/docs")
	w := exchange(t, srv, form(job), "")
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	tok, err := srv.Tokens.Authenticate(got.AccessToken, time.Now())
	if err != nil || tok.Principal != "ci:docs" || tok.Role != auth.RoleAuthor || tok.Resource != "/docs" ||
		got.ExpiresIn > 15*60 || !strings.Contains(tok.Name, "run 42") {
		t.Fatalf("%+v %+v %v", got, tok, err)
	}
	if w := exchange(t, srv, form(job), ""); w.Code != http.StatusBadRequest {
		t.Error("a job's token was exchanged twice")
	}
	if w := exchange(t, srv, form(sign("octo/payroll")), ""); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "invalid_grant") {
		t.Errorf("another repository's job was admitted: %d %s", w.Code, w.Body)
	}
	wide := form(sign("octo/docs-wide"))
	wide.Set("subject_token", sign("octo/docs"))
	wide.Set("resource", "/legal")
	if w := exchange(t, srv, wide, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_target") {
		t.Errorf("a job reached outside its trust: %d %s", w.Code, w.Body)
	}
}
