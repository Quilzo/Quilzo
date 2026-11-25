// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tokens a connector signs for itself.
//
// Two of the tools Quilzo reads do not hand out a client secret to trade for
// a token. A GitHub App holds a private key, signs a JWT that lasts minutes,
// and trades that for an installation token that lasts an hour. A Google
// service account holds a private key too, and signs an assertion that it
// acts as one administrator (RFC 7523). Either way the long-lived secret is
// a key that never leaves this process: what crosses the network is a
// signature over a few claims and the clock.
//
// Signed here, with the standard library, in RS256 (RSASSA-PKCS1-v1_5 with
// SHA-256), which is what both accept. The private key is read from the
// credential the manifest names, PEM in either PKCS #1 or PKCS #8 form for
// a GitHub App, and inside the JSON key file Google hands out for a service
// account; nothing else in that file is believed, the token address it
// names included, because the declared token host is the only place the
// assertion goes.

// GitHub's limits on the JWT a GitHub App signs: issued at most a minute in
// the past to allow for clock drift, and valid for at most ten minutes.
const (
	appJWTBackdate = 60 * time.Second
	appJWTLife     = 9 * time.Minute
	// assertionLife is how long a service account's assertion is valid:
	// Google takes at most an hour.
	assertionLife = time.Hour
)

// AppJWT is the JWT a GitHub App signs to ask for an installation token:
// issued a minute ago, expiring in nine, issued by the App.
func AppJWT(key *rsa.PrivateKey, app string, now time.Time) (string, error) {
	return signRS256(key, map[string]any{
		"iat": now.Add(-appJWTBackdate).Unix(),
		"exp": now.Add(appJWTLife).Unix(),
		"iss": app,
	})
}

// signRS256 is a compact JWT over claims, signed with key.
func signRS256(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	head, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ParseRSAKey reads an RSA private key from PEM, in PKCS #1 (BEGIN RSA
// PRIVATE KEY, as GitHub writes it) or PKCS #8 (BEGIN PRIVATE KEY, as
// Google does). Nothing of the key is repeated in an error.
func ParseRSAKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, errors.New("the private key is neither PKCS #1 nor PKCS #8")
		}
		var ok bool
		if k, ok = parsed.(*rsa.PrivateKey); !ok {
			return nil, errors.New("the private key is not an RSA key, and RS256 is what is asked for")
		}
	}
	if k.N.BitLen() < 2048 {
		return nil, errors.New("the private key is shorter than 2048 bits")
	}
	return k, nil
}

// serviceAccount is the part of a Google service account's key file this
// reads.
type serviceAccount struct {
	Type       string `json:"type"`
	Email      string `json:"client_email"`
	PrivateKey string `json:"private_key"`
}

// signedExchange is exchange for the kinds that sign their request.
func (x *Session) signedExchange(ctx context.Context) (string, error) {
	t := x.m.Auth.Token
	keyText, err := x.secret(x.m.Auth.Secret)
	if err != nil {
		return "", err
	}
	who, err := x.secret(t.Client)
	if err != nil {
		return "", err
	}
	now := x.now()
	target := (&url.URL{Scheme: "https", Host: t.Host, Path: t.Path}).String()
	var body []byte
	headers := map[string]string{}
	switch x.m.Auth.Kind {
	case GitHubApp:
		key, kerr := ParseRSAKey(keyText)
		if kerr != nil {
			return "", fmt.Errorf("%s: the credential %s: %w", x.m.Name, x.m.Auth.Secret, kerr)
		}
		if _, nerr := strconv.ParseUint(strings.TrimSpace(who), 10, 64); nerr != nil {
			return "", fmt.Errorf("%s: the credential %s is not a GitHub App's ID, which is a number", x.m.Name, t.Client)
		}
		signed, serr := AppJWT(key, strings.TrimSpace(who), now)
		if serr != nil {
			return "", serr
		}
		// The installation token is asked for with the declared
		// permissions only, so GitHub narrows it to them even where the
		// App was installed with more.
		perms := map[string]string{}
		for _, sc := range t.Scopes {
			name, level, _ := strings.Cut(sc, ":")
			perms[name] = level
		}
		body, err = json.Marshal(map[string]any{"permissions": perms})
		if err != nil {
			return "", err
		}
		headers["Authorization"] = "Bearer " + signed
		headers["Accept"] = "application/vnd.github+json"
		headers["Content-Type"] = "application/json"
	case JWTBearer:
		var sa serviceAccount
		if json.Unmarshal([]byte(keyText), &sa) != nil || sa.Type != "service_account" || sa.Email == "" {
			return "", fmt.Errorf("%s: the credential %s is not a service account's key file", x.m.Name, x.m.Auth.Secret)
		}
		key, kerr := ParseRSAKey(sa.PrivateKey)
		if kerr != nil {
			return "", fmt.Errorf("%s: the credential %s: %w", x.m.Name, x.m.Auth.Secret, kerr)
		}
		assertion, serr := signRS256(key, map[string]any{
			"iss": sa.Email, "sub": strings.TrimSpace(who), "aud": target,
			"scope": strings.Join(t.Scopes, " "),
			"iat":   now.Unix(), "exp": now.Add(assertionLife).Unix(),
		})
		if serr != nil {
			return "", serr
		}
		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		form.Set("assertion", assertion)
		body = []byte(form.Encode())
		headers["Accept"] = "application/json"
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	default:
		return "", fmt.Errorf("%s: %s does not sign its own token", x.m.Name, x.m.Auth.Kind)
	}

	if err := x.spend(ctx, nil); err != nil {
		return "", err
	}
	_, _, timeout := x.m.Limits()
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "quilzo-connector")
	res, err := x.c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s token endpoint: %w", x.m.Name, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxTokenBody+1))
	if err != nil {
		return "", err
	}
	if len(raw) > MaxTokenBody {
		return "", fmt.Errorf("%s token endpoint returned more than %d bytes, which is not a token", x.m.Name, MaxTokenBody)
	}
	var got struct {
		AccessToken string            `json:"access_token"`
		Token       string            `json:"token"`
		ExpiresIn   json.RawMessage   `json:"expires_in"`
		ExpiresAt   string            `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
		Scope       string            `json:"scope"`
		Error       string            `json:"error"`
	}
	_ = json.Unmarshal(raw, &got)
	code := oauthCode(got.Error)
	if res.StatusCode < 200 || res.StatusCode > 299 || code != "" {
		why := fmt.Sprintf("answered %d", res.StatusCode)
		if code != "" {
			why += " (" + code + ")"
		}
		return "", fmt.Errorf("%s token endpoint %s. The key, the identifier it was signed for or the account it "+
			"acts as was refused, or it was not granted the declared permissions", x.m.Name, why)
	}
	token := got.AccessToken
	if x.m.Auth.Kind == GitHubApp {
		token = got.Token
		if err := checkPermissions(got.Permissions, t.Scopes); err != nil {
			return "", fmt.Errorf("%s: %w", x.m.Name, err)
		}
	}
	if got.Scope != "" {
		if err := checkScopes(got.Scope, t.Scopes); err != nil {
			return "", fmt.Errorf("%s: %w", x.m.Name, err)
		}
	}
	if !usableToken(token) {
		return "", fmt.Errorf("%s token endpoint answered without a usable access token", x.m.Name)
	}
	life := time.Hour
	if secs, ok := seconds(got.ExpiresIn); ok && secs > 0 {
		life = time.Duration(secs) * time.Second
	}
	if at, err := time.Parse(time.RFC3339, got.ExpiresAt); err == nil && at.After(now) {
		life = at.Sub(now)
	}
	margin := time.Minute
	if margin > life/2 {
		margin = life / 2
	}
	x.token, x.expires = token, now.Add(life-margin)
	return x.token, nil
}

// checkPermissions refuses an installation token whose permissions reach
// further than the manifest declared: a permission it did not ask for, or
// any level but read. GitHub says what the token holds in the answer that
// carries it, so the check is of the provider's own word, before the token
// is used once; an answer that says nothing is refused, because the check
// is the reason a key that can mint tokens is trusted at all.
func checkPermissions(got map[string]string, declared []string) error {
	if len(got) == 0 {
		return errors.New("the installation token came with no permissions, so what it could do is unknown")
	}
	want := map[string]bool{}
	for _, sc := range declared {
		name, _, _ := strings.Cut(sc, ":")
		want[name] = true
	}
	var extra []string
	for name, level := range got {
		if !want[name] || level != "read" {
			extra = append(extra, name+":"+level)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("the installation token holds %s, which this connector does not declare. Change the App's "+
			"permissions to read the declared ones only: a reader holding a token that can change things is a "+
			"reader in name only", strings.Join(extra, ", "))
	}
	return nil
}

// checkScopes refuses a token whose granted scopes, where the provider
// names them, include one that was not asked for.
func checkScopes(granted string, declared []string) error {
	want := map[string]bool{}
	for _, sc := range declared {
		want[strings.ToLower(sc)] = true
	}
	var extra []string
	for _, sc := range strings.Fields(granted) {
		if !want[strings.ToLower(sc)] {
			extra = append(extra, sc)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("the token was granted %s as well, which this connector does not declare",
			strings.Join(extra, ", "))
	}
	return nil
}
