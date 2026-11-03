// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package ssf receives security events from the identity provider under
// OpenID Shared Signals: the Shared Signals Framework 1.0, CAEP 1.0 and
// RISC 1.0, final since August 2025, and the CAEP Interoperability Profile.
//
// # Why Quilzo listens
//
// A session here is this program's own: the provider vouches once, at
// sign-in, and the eight hours after that are local. So when the provider
// ends somebody's session, disables their account or learns their password
// was stolen, nothing reached the session already open here. SCIM ends
// access only when it deactivates somebody, and only where it is set up.
// This is the other half: the provider says what happened, and Quilzo ends
// what it gave on the provider's word, for that provider's sign-ins.
//
// # What arrives
//
// A transmitter (Okta, Google, Microsoft, an identity platform) sends one
// security event token (RFC 8417) per event: a JWT, signed with a key it
// publishes, saying one thing about one subject. "This session was ended."
// "This person's password changed." "This account was disabled." Pushed
// (RFC 8935) as the body of a POST.
//
// # Every token is an attacker's until it verifies
//
// The endpoint is on the internet, so whatever it is sent is somebody's
// attempt until proven otherwise, and a forged "account disabled" is a way
// to have a person shut out. So:
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
//     profile both say so), of a type this receiver asked for, an id (jti)
//     for the caller to refuse twice, and the time it was issued, which must
//     be neither in the future nor old.
//
// What a verified token says is still the transmitter's word. Nothing it
// says is ever kept as text: its reason for an administrator is free text a
// transmitter chose, and is not stored.
package ssf

import (
	"encoding/json"
	"fmt"
	"slices"
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

// Requested is every event this receiver asks a transmitter for, and the
// only ones it accepts: what Quilzo does something fixed about, on its own
// sessions and grants, and the stream's own housekeeping.
//
// Narrower than what CAEP and RISC define on purpose. Device compliance,
// risk and assurance levels, changed claims and identifiers, and account
// recovery are an organisation's judgement to act on across its estate;
// a session here has no device or level to compare, and an event this
// receiver cannot act on is one it has no reason to be sent.
var Requested = []string{
	caepPrefix + "session-revoked",
	caepPrefix + "credential-change",
	riscPrefix + "sessions-revoked",
	riscPrefix + "account-disabled",
	riscPrefix + "account-enabled",
	riscPrefix + "account-purged",
	riscPrefix + "credential-compromise",
	riscPrefix + "account-credential-change-required",
	Verification,
	StreamUpdated,
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

// DefaultSkew is how far this clock and the transmitter's may disagree.
const DefaultSkew = 2 * time.Minute

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

// Until is how long a token's id has to be remembered: after this, Verify
// refuses the token as too old, so a replay of it needs no memory to stop.
func (r *Receiver) Until(set *SET) time.Time {
	return set.IssuedAt.Add(r.maxAge() + r.skew())
}

func (r *Receiver) maxAge() time.Duration {
	if r.MaxAge > 0 {
		return r.MaxAge
	}
	return DefaultMaxAge
}

func (r *Receiver) skew() time.Duration {
	if r.Skew > 0 {
		return r.Skew
	}
	return DefaultSkew
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
		// What cannot be read as a signed token is a malformed request; a
		// signature, algorithm or key this stream does not accept is a key
		// it refuses. A crit header is the first: nothing here understands
		// the extension it names, so the token cannot be read at all.
		code := "invalid_key"
		for _, malformed := range []string{"segments", "not JSON", "base64url", "token type",
			"critical", "encrypted", "enc header"} {
			if strings.Contains(err.Error(), malformed) {
				code = "invalid_request"
			}
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
	skew, maxAge := r.skew(), r.maxAge()
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
	if set.Family == "" || !slices.Contains(Requested, set.Type) {
		return nil, refuse("invalid_request", "%q is not an event type this receiver asked for", set.Type)
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

// Text is one of the event's own members, when it is a short string: what
// a fixed action reads, such as credential-change's change_type, and
// nothing longer, since nothing here keeps a transmitter's free text.
func (s *SET) Text(name string) string {
	return strings.ToLower(str(s.Claims, name))
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
	// Aliases are the identifiers an aliases subject gives, each a way of
	// naming the same one.
	Aliases []Subject `json:"-"`
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
				if inner, err := parseSubject(mm, depth+1); err == nil {
					s.Aliases = append(s.Aliases, inner)
				}
			}
		}
		if len(s.Aliases) == 0 {
			return s, fmt.Errorf("an aliases subject with no identifier this receiver reads")
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
// none; Ref gives that.
//
// An aliases subject names somebody when every address among its
// identifiers is the same one. Two different addresses are two people as
// far as this can tell, and choosing either would be guessing whose access
// to take away.
func (s Subject) Person() string {
	if s.User != nil {
		return s.User.Person()
	}
	if s.Format == "aliases" {
		one := ""
		for _, a := range s.Aliases {
			if p := a.Person(); p != "" {
				if one != "" && p != one {
					return ""
				}
				one = p
			}
		}
		return one
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

// IssSub is the issuer and subject of an iss_sub subject, and nothing for
// any other format: who the issuer says the user is, in its own terms.
//
// Only the plain format, not the user member of a complex subject or one
// of several aliases. A principal named by sub is matched on that value
// alone, so the subject has to say it and say nothing else; a complex
// subject's user is read through Person, where an address can be checked
// against what the policy knows.
func (s Subject) IssSub() (string, string) {
	if s.Format == "iss_sub" {
		return s.Iss, s.Sub
	}
	return "", ""
}
