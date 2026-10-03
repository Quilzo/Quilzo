// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package inbound is what arrives on its own: events another system pushes the
// moment they happen, rather than events Quilzo goes and reads.
//
// # Three ways in, each proving where it came from
//
// Okta event hooks. Okta sends a fixed secret in a header of the operator's
// choosing, verifies the endpoint once by echoing a challenge, and batches
// System Log events into each POST. It signs nothing; the secret is the
// whole of the proof, so it is compared in constant time against a stored
// digest and never kept in the clear here.
//
// Signed webhooks. Anything else that can send a webhook, verified the way
// the Standard Webhooks specification does it (HMAC-SHA256 over id,
// timestamp and body, a secret written whsec_…), or the way GitHub does
// (X-Hub-Signature-256). A timestamp outside five minutes is refused, and an
// id seen before is refused, so a captured delivery cannot be sent again.
//
// Shared signals. See internal/ssf: signed tokens, verified against keys the
// transmitter publishes.
//
// # What is refused, and how loudly
//
// A delivery that does not prove itself gets 401 and nothing else: no hint
// which part failed, because the only party who needs to know is the one
// holding the secret, and they can read the reason in the audit log here.
package inbound

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kinds of feed.
const (
	Okta    = "okta"
	Webhook = "webhook"
	GitHub  = "github"
	SSF     = "ssf"
)

// Feed is one way in.
type Feed struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Mapping is the source mapping records are read through
	// ("okta/system", or one added with quilzo source add).
	Mapping string `json:"mapping,omitempty"`
	// TokenHash is the SHA-256 of the static secret Okta or a transmitter
	// sends in a header, hex. The secret itself is shown once and kept
	// nowhere here.
	TokenHash string `json:"token_hash,omitempty"`
	// Secret names the sealed secret an HMAC is checked with.
	Secret string `json:"secret,omitempty"`
	// Shared signals.
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	JWKSURI  string `json:"jwks_uri,omitempty"`
	StreamID string `json:"stream_id,omitempty"`
	// Alias is the identity namespace a transmitter's own user ids belong
	// to — "okta" — so an iss_sub subject resolves through the identity
	// links collection already learned.
	Alias string `json:"alias,omitempty"`
	// State is the digest of the verification state last asked for.
	State    string    `json:"state,omitempty"`
	Verified time.Time `json:"verified,omitempty"`
	// Status is what the transmitter last said of the stream.
	Status  string    `json:"status,omitempty"`
	Off     bool      `json:"off,omitempty"`
	Created time.Time `json:"created"`
	By      string    `json:"by,omitempty"`
}

// ValidName keeps feed names to what can sit in a URL path and a file name.
func ValidName(s string) bool {
	if len(s) < 2 || len(s) > 40 {
		return false
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0) {
			return false
		}
	}
	return true
}

// NewSecret makes a secret to give the sender, and its stored digest.
func NewSecret() (secret, digest string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, Digest(secret), nil
}

// NewWebhookSecret makes a Standard Webhooks secret: whsec_ and base64.
func NewWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b), nil
}

// Digest is how a static secret is kept.
func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// StaticMatches compares a presented secret with a stored digest, in
// constant time. An empty digest matches nothing.
func StaticMatches(presented, digest string) bool {
	if digest == "" || presented == "" {
		return false
	}
	got := Digest(presented)
	return subtle.ConstantTimeCompare([]byte(got), []byte(digest)) == 1
}

// BearerOrRaw is the secret in an Authorization header, which Okta sends
// as the bare value and a transmitter as "Bearer value".
func BearerOrRaw(h string) string {
	h = strings.TrimSpace(h)
	if v, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return h
}

// ErrRefused is a delivery that did not prove where it came from.
var ErrRefused = errors.New("the delivery did not prove where it came from")

// Tolerance is how far a signed delivery's timestamp may be from now.
const Tolerance = 5 * time.Minute

// VerifyStandard checks a delivery signed the Standard Webhooks way and
// returns its id. secret is whsec_ and base64, or the raw key.
func VerifyStandard(h http.Header, body []byte, secret string, now time.Time) (string, error) {
	id, ts, sigs := h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature")
	if id == "" || ts == "" || sigs == "" || len(id) > 256 {
		return "", fmt.Errorf("%w: the webhook-id, webhook-timestamp or webhook-signature header is missing", ErrRefused)
	}
	sec, err := webhookKey(secret)
	if err != nil {
		return "", err
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: the timestamp is not a number", ErrRefused)
	}
	if d := now.Sub(time.Unix(n, 0)); d > Tolerance || d < -Tolerance {
		return "", fmt.Errorf("%w: the timestamp is %s from now", ErrRefused, d.Round(time.Second))
	}
	mac := hmac.New(sha256.New, sec)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	// Several signatures, space-separated, while a key is being rotated.
	for _, s := range strings.Fields(sigs) {
		v, b64, ok := strings.Cut(s, ",")
		if !ok || v != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(b64)
		if err == nil && hmac.Equal(got, want) {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: no signature matches", ErrRefused)
}

func webhookKey(secret string) ([]byte, error) {
	if v, ok := strings.CutPrefix(secret, "whsec_"); ok {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(b) < 24 || len(b) > 64 {
			return nil, fmt.Errorf("the stored webhook secret is not a whsec_ key of 24 to 64 bytes")
		}
		return b, nil
	}
	if len(secret) < 24 {
		return nil, fmt.Errorf("the stored webhook secret is too short")
	}
	return []byte(secret), nil
}

// VerifyGitHub checks a delivery signed the way GitHub signs, and returns
// its delivery id. GitHub sends no timestamp, so the id is the only defence
// against a delivery sent again, and the caller must refuse one it has seen.
func VerifyGitHub(h http.Header, body []byte, secret string) (string, error) {
	id, sig := h.Get("X-GitHub-Delivery"), h.Get("X-Hub-Signature-256")
	if id == "" || sig == "" || len(id) > 256 {
		return "", fmt.Errorf("%w: the X-GitHub-Delivery or X-Hub-Signature-256 header is missing", ErrRefused)
	}
	hexSig, ok := strings.CutPrefix(sig, "sha256=")
	if !ok {
		return "", fmt.Errorf("%w: the signature is not sha256", ErrRefused)
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return "", fmt.Errorf("%w: the signature is not hex", ErrRefused)
	}
	if len(secret) < 16 {
		return "", fmt.Errorf("the stored webhook secret is too short")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return "", fmt.Errorf("%w: the signature does not match", ErrRefused)
	}
	return id, nil
}

// Seen remembers delivery ids for a while, so the same one is taken once.
type Seen struct {
	mu   sync.Mutex
	ids  map[string]time.Time
	Keep time.Duration
	Max  int
}

// First records id and reports whether it is new. An id is remembered for
// Keep (a day by default), at most Max of them (100,000), oldest dropped first.
func (s *Seen) First(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ids == nil {
		s.ids = map[string]time.Time{}
	}
	keep, max := s.Keep, s.Max
	if keep <= 0 {
		keep = 24 * time.Hour
	}
	if max <= 0 {
		max = 100_000
	}
	if at, ok := s.ids[id]; ok && now.Sub(at) < keep {
		return false
	}
	if len(s.ids) >= max {
		for k, at := range s.ids {
			if now.Sub(at) >= keep {
				delete(s.ids, k)
			}
		}
		for len(s.ids) >= max {
			var oldest string
			var t time.Time
			for k, at := range s.ids {
				if oldest == "" || at.Before(t) {
					oldest, t = k, at
				}
			}
			delete(s.ids, oldest)
		}
	}
	s.ids[id] = now
	return true
}

// OktaChallenge is the one-time verification Okta makes when a hook is
// added: the value of the challenge header, echoed back as JSON.
//
// The challenge is a token: letters, digits and the characters of base64.
// Anything else is refused rather than escaped, so what is echoed into the
// JSON can never close the string it sits in.
func OktaChallenge(r *http.Request) ([]byte, bool) {
	v := r.Header.Get("X-Okta-Verification-Challenge")
	if v == "" || len(v) > 256 {
		return nil, false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '+' || c == '/' || c == '=' || c == '.') {
			return nil, false
		}
	}
	// Escaping changes none of those characters; it is here so that a
	// later edit to the check above cannot turn the echo into markup.
	return []byte(`{"verification":"` + html.EscapeString(v) + `"}`), true
}

// OktaDelivery is an event hook's body.
type OktaDelivery struct {
	EventType string `json:"eventType"`
	EventID   string `json:"eventId"`
	Data      struct {
		Events []map[string]any `json:"events"`
	} `json:"data"`
}

// ParseOkta reads an event hook delivery.
func ParseOkta(body []byte) (*OktaDelivery, error) {
	var d OktaDelivery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("the delivery is not JSON: %w", err)
	}
	if d.EventType != "com.okta.event_hook" {
		return nil, fmt.Errorf("this is not an Okta event hook delivery (%q)", d.EventType)
	}
	if len(d.Data.Events) > 1000 {
		return nil, fmt.Errorf("a delivery of %d events is not one Okta sends", len(d.Data.Events))
	}
	return &d, nil
}

// Records is a webhook body as records for a mapping: the body itself, the
// array it is, or the array under "data" or "events".
func Records(body []byte) ([]any, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("the body is not JSON: %w", err)
	}
	switch x := v.(type) {
	case []any:
		return x, nil
	case map[string]any:
		for _, k := range []string{"events", "data"} {
			if arr, ok := x[k].([]any); ok {
				return arr, nil
			}
		}
		return []any{x}, nil
	}
	return nil, fmt.Errorf("the body is neither an object nor a list")
}
