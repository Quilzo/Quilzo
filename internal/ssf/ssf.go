// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package ssf receives security events from other systems under OpenID
// Shared Signals: the Shared Signals Framework 1.0, CAEP 1.0 and RISC 1.0,
// final since August 2025, and the CAEP Interoperability Profile.
//
// # What arrives, and what it means
//
// A transmitter — Okta, Google, Jamf, an identity platform — sends one
// security event token (RFC 8417) per event: a JWT, signed with a key it
// publishes, saying one thing about one subject. "This session was ended."
// "This person's password changed." "This laptop stopped being compliant."
// "This account was taken over." Pushed (RFC 8935) as the body of a POST.
//
// # Every token is an attacker's until it verifies
//
// The endpoint is on the internet, so whatever it is sent is somebody's
// attempt until proven otherwise, and a forged "credential compromised" is
// a way to have a person signed out of everything. So:
//
//   - the signature is checked by the same code that checks ID tokens
//     (internal/oidc): the algorithm comes from an agreed list and never from
//     the token, alg:none and HMAC confusion are refused, a crit header is
//     refused, and the key comes from the transmitter's own published set;
//   - the issuer must be the configured one exactly, and this receiver must
//     be among the audiences, so a token minted for somebody else cannot be
//     replayed here;
//   - the header must say secevent+jwt, so an ID token from the same issuer
//     cannot be presented as an event;
//   - a token must carry exactly one event (SSF 1.0 and the interoperability
//     profile both say so), an id (jti) for the caller to refuse twice, and
//     the time it was issued, which must be neither in the future nor old.
//
// What a verified token says is still the transmitter's word: it decides
// what a rule may do, and the rules that act on it are people's choice.
package ssf

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/oidc"
)

// Event type URIs.
const (
	Verification  = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	StreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"

	caepPrefix = "https://schemas.openid.net/secevent/caep/event-type/"
	riscPrefix = "https://schemas.openid.net/secevent/risc/event-type/"
)

// Requested is every event this receiver asks a transmitter for: what CAEP
// and RISC define that a rule here can act on.
var Requested = []string{
	caepPrefix + "session-revoked",
	caepPrefix + "credential-change",
	caepPrefix + "device-compliance-change",
	caepPrefix + "assurance-level-change",
	caepPrefix + "risk-level-change",
	caepPrefix + "token-claims-change",
	riscPrefix + "account-disabled",
	riscPrefix + "account-enabled",
	riscPrefix + "account-purged",
	riscPrefix + "account-credential-change-required",
	riscPrefix + "credential-compromise",
	riscPrefix + "identifier-changed",
	riscPrefix + "recovery-activated",
	riscPrefix + "recovery-information-changed",
	riscPrefix + "sessions-revoked",
}

// Error is a refusal in RFC 8935's terms, which a transmitter can act on.
type Error struct {
	// Code is one of invalid_request, invalid_key, invalid_issuer,
	// invalid_audience, authentication_failed, access_denied.
	Code        string `json:"err"`
	Description string `json:"description"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func refuse(code, format string, args ...any) *Error {
	return &Error{Code: code, Description: fmt.Sprintf(format, args...)}
}

// Receiver is what a stream was agreed to be, and checks what arrives on it.
type Receiver struct {
	// Issuer is the transmitter's issuer, compared exactly.
	Issuer string
	// Audience is this receiver as the transmitter knows it.
	Audience string
	// Algorithms are the ones agreed; the interoperability profile signs
	// with RS256 and nothing weaker is accepted.
	Algorithms []oidc.Algorithm
	Keys       oidc.KeySource
	// MaxAge is how old an event may be when it arrives. Transmitters retry
	// for a while; older than this is a replay or a backlog nobody should
	// act on now.
	MaxAge time.Duration
	// Skew forgives this clock and the transmitter's disagreeing.
	Skew time.Duration
	Now  func() time.Time
}

// DefaultMaxAge is how old an event may be by default.
const DefaultMaxAge = 72 * time.Hour

// MaxToken is the largest token accepted. A security event is a few hundred
// bytes; anything near this is not one.
const MaxToken = 64 << 10

// SET is a verified security event token.
type SET struct {
	JTI      string
	Issuer   string
	IssuedAt time.Time
	Txn      string
	// Type is the event's URI and Short the last part of it: "session-revoked".
	Type, Short string
	// Family is "caep", "risc" or "ssf".
	Family  string
	Subject Subject
	// Claims are the event's own members.
	Claims map[string]any
}

// Verify checks a token and returns what it says. The error is an *Error.
func (r *Receiver) Verify(token string) (*SET, error) {
	if r.Issuer == "" || r.Audience == "" || r.Keys == nil || len(r.Algorithms) == 0 {
		return nil, refuse("access_denied", "this stream is not set up to receive")
	}
	token = strings.TrimSpace(token)
	if len(token) > MaxToken {
		return nil, refuse("invalid_request", "the token is %d bytes; a security event is a few hundred", len(token))
	}
	payload, err := oidc.VerifyJWS(token, r.Algorithms, r.Keys, r.Issuer, "a security event token",
		func(typ string) bool {
			t := strings.ToLower(typ)
			return t == "secevent+jwt" || t == "application/secevent+jwt"
		})
	if err != nil {
		code := "invalid_key"
		if strings.Contains(err.Error(), "segments") || strings.Contains(err.Error(), "not JSON") ||
			strings.Contains(err.Error(), "base64url") || strings.Contains(err.Error(), "token type") {
			code = "invalid_request"
		}
		return nil, refuse(code, "%v", err)
	}
	var c struct {
		Iss    string                     `json:"iss"`
		Aud    any                        `json:"aud"`
		Iat    *json.Number               `json:"iat"`
		Exp    *json.Number               `json:"exp"`
		JTI    string                     `json:"jti"`
		Txn    string                     `json:"txn"`
		SubID  map[string]any             `json:"sub_id"`
		Events map[string]json.RawMessage `json:"events"`
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, refuse("invalid_request", "the claims are not JSON: %v", err)
	}
	if c.Iss != r.Issuer {
		return nil, refuse("invalid_issuer", "the token says it is from %q and this stream is from %q", c.Iss, r.Issuer)
	}
	if !audienceHas(c.Aud, r.Audience) {
		return nil, refuse("invalid_audience", "the token is not addressed to this receiver")
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	skew, maxAge := r.Skew, r.MaxAge
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if c.Iat == nil {
		return nil, refuse("invalid_request", "the token does not say when it was issued")
	}
	iatN, err := c.Iat.Int64()
	if err != nil {
		return nil, refuse("invalid_request", "the issue time is not a whole number of seconds")
	}
	iat := time.Unix(iatN, 0)
	if iat.After(now.Add(skew)) {
		return nil, refuse("invalid_request", "the token was issued in the future")
	}
	if now.Sub(iat) > maxAge {
		return nil, refuse("invalid_request", "the token was issued %s ago, older than this stream accepts", now.Sub(iat).Round(time.Minute))
	}
	// SETs carry no expiry; one that does and has passed is not acted on.
	if c.Exp != nil {
		if exp, err := c.Exp.Int64(); err != nil || time.Unix(exp, 0).Before(now.Add(-skew)) {
			return nil, refuse("invalid_request", "the token has expired")
		}
	}
	if c.JTI == "" || len(c.JTI) > 256 {
		return nil, refuse("invalid_request", "the token has no usable id (jti)")
	}
	if len(c.Events) != 1 {
		return nil, refuse("invalid_request", "a token carries exactly one event and this carries %d", len(c.Events))
	}
	set := &SET{JTI: c.JTI, Issuer: c.Iss, IssuedAt: iat, Txn: c.Txn}
	for uri, raw := range c.Events {
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil || claims == nil {
			return nil, refuse("invalid_request", "the event is not an object")
		}
		set.Type, set.Claims = uri, claims
	}
	set.Family, set.Short = family(set.Type)
	if set.Family == "" {
		return nil, refuse("invalid_request", "%q is not an event type this receiver knows", set.Type)
	}
	// The subject is the top-level sub_id under SSF 1.0; transmitters built
	// on the earlier drafts put it inside the event as "subject".
	sub := c.SubID
	if sub == nil {
		if s, ok := set.Claims["subject"].(map[string]any); ok {
			sub = s
		}
	}
	if sub == nil {
		return nil, refuse("invalid_request", "the event names no subject")
	}
	s, err := parseSubject(sub, 0)
	if err != nil {
		return nil, refuse("invalid_request", "%v", err)
	}
	set.Subject = s
	return set, nil
}

func audienceHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func family(uri string) (string, string) {
	switch {
	case uri == Verification:
		return "ssf", "verification"
	case uri == StreamUpdated:
		return "ssf", "stream-updated"
	case strings.HasPrefix(uri, caepPrefix):
		return "caep", short(strings.TrimPrefix(uri, caepPrefix))
	case strings.HasPrefix(uri, riscPrefix):
		return "risc", short(strings.TrimPrefix(uri, riscPrefix))
	}
	return "", ""
}

// short keeps an event's name only when it looks like one.
func short(s string) string {
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '-') {
			return ""
		}
	}
	return s
}

// Subject is who or what an event is about (RFC 9493 and SSF 1.0).
type Subject struct {
	Format string `json:"format"`
	Email  string `json:"email,omitempty"`
	Phone  string `json:"phone_number,omitempty"`
	Iss    string `json:"iss,omitempty"`
	Sub    string `json:"sub,omitempty"`
	ID     string `json:"id,omitempty"`
	URI    string `json:"uri,omitempty"`
	// Complex subjects: each member is itself a subject.
	User, Device, Session, Tenant *Subject `json:"-"`
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	if len(s) > 512 {
		return ""
	}
	return s
}

func parseSubject(m map[string]any, depth int) (Subject, error) {
	if depth > 1 {
		return Subject{}, fmt.Errorf("the subject is nested too deeply")
	}
	s := Subject{Format: str(m, "format")}
	switch s.Format {
	case "email":
		s.Email = strings.ToLower(strings.TrimSpace(str(m, "email")))
		if !strings.Contains(s.Email, "@") {
			return s, fmt.Errorf("an email subject without an address")
		}
	case "phone_number":
		s.Phone = str(m, "phone_number")
	case "iss_sub":
		s.Iss, s.Sub = str(m, "iss"), str(m, "sub")
		if s.Iss == "" || s.Sub == "" {
			return s, fmt.Errorf("an iss_sub subject needs both")
		}
	case "opaque":
		s.ID = str(m, "id")
	case "account", "uri", "did":
		s.URI = firstNonEmpty(str(m, "uri"), str(m, "url"))
		if s.Format == "account" {
			if addr, ok := strings.CutPrefix(s.URI, "acct:"); ok {
				s.Email = strings.ToLower(addr)
			}
		}
	case "aliases":
		ids, _ := m["identifiers"].([]any)
		for _, v := range ids {
			if mm, ok := v.(map[string]any); ok {
				if inner, err := parseSubject(mm, depth+1); err == nil && inner.Person() != "" {
					return inner, nil
				}
			}
		}
	case "complex":
		for k, dst := range map[string]**Subject{"user": &s.User, "device": &s.Device, "session": &s.Session, "tenant": &s.Tenant} {
			if mm, ok := m[k].(map[string]any); ok {
				inner, err := parseSubject(mm, depth+1)
				if err != nil {
					return s, fmt.Errorf("%s: %w", k, err)
				}
				*dst = &inner
			}
		}
		if s.User == nil && s.Device == nil && s.Session == nil && s.Tenant == nil {
			return s, fmt.Errorf("a complex subject with no members")
		}
	default:
		return s, fmt.Errorf("the subject format %q is not one this receiver reads", s.Format)
	}
	return s, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Person is the subject's email address, when it has one: the name a person
// signs in here with. A subject known only by the transmitter's own id has
// none; Ref gives that, for an identity link to resolve.
func (s Subject) Person() string {
	if s.User != nil {
		return s.User.Person()
	}
	return s.Email
}

// Ref is the transmitter's own identifier for the subject's user, when it
// gives one: "sub" of an iss_sub subject.
func (s Subject) Ref() string {
	if s.User != nil {
		return s.User.Ref()
	}
	if s.Format == "iss_sub" {
		return s.Sub
	}
	return ""
}

// Signal is a verified event, as a rule reads it.
type Signal struct {
	// Type is the event's short name: "session-revoked", "credential-compromise".
	Type     string
	Severity string // "high", "medium" or "low"
	Fields   map[string]string
	// Reason is the transmitter's explanation for an administrator, when it
	// gives one. Its words, never instructions to anybody.
	Reason string
}

// Signal says what the event means for the rules.
func (s *SET) Signal() Signal {
	out := Signal{Type: s.Short, Fields: map[string]string{}}
	for _, k := range []string{"credential_type", "change_type", "namespace", "change_direction",
		"current_status", "previous_status", "principal", "risk_reason", "initiating_entity", "reason", "friendly_name"} {
		if v := str(s.Claims, k); v != "" {
			out.Fields[k] = strings.ToLower(v)
		}
	}
	for _, k := range []string{"current_level", "previous_level"} {
		if v, ok := s.Claims[k]; ok {
			out.Fields[k] = strings.ToLower(fmt.Sprint(v))
		}
	}
	if s.Short == "sessions-revoked" {
		// RISC's older name for CAEP's event: one name for the rules.
		out.Type = "session-revoked"
	}
	out.Reason = reasonText(s.Claims["reason_admin"])
	out.Severity = severity(out.Type, out.Fields)
	return out
}

// reasonText takes the English text of a reason, or the first there is.
func reasonText(v any) string {
	var s string
	switch r := v.(type) {
	case string:
		s = r
	case map[string]any:
		if en, ok := r["en"].(string); ok {
			s = en
		} else {
			for _, x := range r {
				if t, ok := x.(string); ok {
					s = t
					break
				}
			}
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func severity(typ string, f map[string]string) string {
	switch typ {
	case "credential-compromise", "account-credential-change-required":
		return "high"
	case "account-disabled":
		if f["reason"] == "hijacking" {
			return "high"
		}
		return "medium"
	case "risk-level-change":
		switch f["current_level"] {
		case "high":
			return "high"
		case "medium":
			return "medium"
		}
		return "low"
	case "device-compliance-change":
		if f["current_status"] == "not-compliant" {
			return "medium"
		}
		return "low"
	case "assurance-level-change":
		if f["change_direction"] == "decrease" {
			return "medium"
		}
		return "low"
	case "session-revoked", "credential-change", "identifier-changed", "account-purged",
		"recovery-activated", "recovery-information-changed":
		return "medium"
	}
	return "low"
}
