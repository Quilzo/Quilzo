// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Who a visitor is, as the site that embeds a chatbot says, never as they
// say.
//
// A chatbot cannot know who it is talking to: what a visitor types about
// themselves is a claim anybody can make. A shop that has signed its
// customer in can say who they are, though, by signing it: it gives the
// chatbot a token, HMAC-SHA256 over a few claims with a key the two share,
// and an agent action that needs to know who it acts for (an order, a
// booking) is given those claims and nothing the visitor typed about
// themselves.
//
// The token is base64url(JSON claims) "." base64url(HMAC-SHA256(key,
// first part)). The claims are a flat object of short strings, and "exp",
// a Unix time no more than a day ahead, is required: a token is for a
// visit, not for ever.

// Bounds on a visitor's token.
const (
	MaxVisitorClaims = 8
	MaxVisitorToken  = 2048
	MaxVisitorLife   = 24 * time.Hour
)

var reClaim = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// VerifyVisitor is what a token says about a visitor, when it is signed
// with key and has not expired.
func VerifyVisitor(token string, key []byte, now time.Time) (map[string]string, error) {
	if len(key) < 16 {
		return nil, errors.New("the site's signing key is shorter than 16 bytes")
	}
	if token == "" || len(token) > MaxVisitorToken {
		return nil, errors.New("no token, or one too long to be one")
	}
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return nil, errors.New("not a token")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return nil, errors.New("the token is not signed by the site")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, errors.New("not a token")
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, errors.New("the token's claims are not an object")
	}
	if len(claims) > MaxVisitorClaims+1 {
		return nil, fmt.Errorf("the token says more than %d things", MaxVisitorClaims)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("the token does not say when it expires")
	}
	at := time.Unix(int64(exp), 0)
	switch {
	case !now.Before(at):
		return nil, errors.New("the token has expired")
	case at.Sub(now) > MaxVisitorLife:
		return nil, errors.New("the token lasts more than a day")
	}
	out := map[string]string{}
	for k, v := range claims {
		if k == "exp" {
			continue
		}
		if !reClaim.MatchString(k) {
			return nil, fmt.Errorf("%q is not a claim's name", k)
		}
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case float64:
			s = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			s = strconv.FormatBool(t)
		default:
			return nil, fmt.Errorf("the claim %s is not a short value", k)
		}
		if len(s) > 200 || strings.ContainsAny(s, "\r\n") {
			return nil, fmt.Errorf("the claim %s is not a short value", k)
		}
		out[k] = s
	}
	return out, nil
}

// SignVisitor makes a token, as a host site would: for tests and for the
// owner trying an action out.
func SignVisitor(claims map[string]string, key []byte, exp time.Time) string {
	m := map[string]any{"exp": exp.Unix()}
	for k, v := range claims {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	body := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
