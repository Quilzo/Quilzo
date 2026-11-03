// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/oidc"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

const (
	iss = "https://acme.okta.com"
	aud = "https://quilzo.acme.example/sso/signals"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type key struct{ k *rsa.PrivateKey }

func newKey(t *testing.T) *key {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &key{k}
}

func (k *key) jwks() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "use": "sig",
		"n": b64(k.k.PublicKey.N.Bytes()), "e": b64(big.NewInt(int64(k.k.PublicKey.E)).Bytes()),
	}}})
	return b
}

func (k *key) sign(t *testing.T, h map[string]any, claims map[string]any) string {
	t.Helper()
	if h == nil {
		h = map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	d := sha256.Sum256([]byte(in))
	var sig []byte
	switch h["alg"] {
	case "RS256":
		s, err := rsa.SignPKCS1v15(rand.Reader, k.k, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	case "HS256":
		m := hmac.New(sha256.New, k.k.PublicKey.N.Bytes())
		m.Write([]byte(in))
		sig = m.Sum(nil)
	}
	return in + "." + b64(sig)
}

func receiver(t *testing.T, k *key) *Receiver {
	t.Helper()
	ks, err := oidc.NewKeySet("https://acme.okta.com/oauth2/v1/keys", func(context.Context, string) ([]byte, error) {
		return k.jwks(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Receiver{Issuer: iss, Audience: aud, Algorithms: []oidc.Algorithm{oidc.RS256}, Keys: ks,
		Now: func() time.Time { return now }}
}

func revoked() map[string]any {
	return map[string]any{
		"iss": iss, "aud": aud, "jti": "24c63fb56e5a2d77a6b512616ca9fa24", "iat": now.Add(-time.Minute).Unix(),
		"sub_id": map[string]any{"format": "email", "email": "Ada.Okafor@northwind.example"},
		"events": map[string]any{caepPrefix + "session-revoked": map[string]any{
			"initiating_entity": "policy", "reason_admin": map[string]any{"en": "Landspeed policy violation"},
			"event_timestamp": now.Unix()}},
	}
}

func TestAGoodEventIsReadForWhatItSays(t *testing.T) {
	k := newKey(t)
	set, err := receiver(t, k).Verify(k.sign(t, nil, revoked()))
	if err != nil {
		t.Fatal(err)
	}
	if set.Short != "session-revoked" || set.Family != "caep" || set.Subject.Person() != "ada.okafor@northwind.example" {
		t.Errorf("read as %+v", set)
	}
	if set.Text("initiating_entity") != "policy" || set.JTI == "" || !set.IssuedAt.Equal(now.Add(-time.Minute)) {
		t.Errorf("the event's own members were not read: %+v", set)
	}
	// The administrator's reason is the transmitter's free text, and nothing
	// here keeps it as one of the event's words.
	if set.Text("reason_admin") != "" {
		t.Error("the free-text reason was read as text")
	}
}

// Every way a token can be wrong, refused with the code RFC 8935 gives it.
func TestWhatIsNotAGoodEventIsRefused(t *testing.T) {
	k, other := newKey(t), newKey(t)
	r := receiver(t, k)
	with := func(f func(c map[string]any)) map[string]any { c := revoked(); f(c); return c }
	cases := map[string]struct {
		token string
		code  string
	}{
		"another issuer":        {k.sign(t, nil, with(func(c map[string]any) { c["iss"] = "https://acme.okta.com.evil.example" })), "invalid_issuer"},
		"a trailing slash":      {k.sign(t, nil, with(func(c map[string]any) { c["iss"] = iss + "/" })), "invalid_issuer"},
		"another audience":      {k.sign(t, nil, with(func(c map[string]any) { c["aud"] = "https://elsewhere.example" })), "invalid_audience"},
		"no audience":           {k.sign(t, nil, with(func(c map[string]any) { delete(c, "aud") })), "invalid_audience"},
		"signed by another key": {other.sign(t, nil, revoked()), "invalid_key"},
		"alg none":              {k.sign(t, map[string]any{"alg": "none", "kid": "k1", "typ": "secevent+jwt"}, revoked()), "invalid_key"},
		"hmac with the key":     {k.sign(t, map[string]any{"alg": "HS256", "kid": "k1", "typ": "secevent+jwt"}, revoked()), "invalid_key"},
		"an ID token":           {k.sign(t, map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"}, revoked()), "invalid_request"},
		"no type":               {k.sign(t, map[string]any{"alg": "RS256", "kid": "k1"}, revoked()), "invalid_request"},
		"two events":            {k.sign(t, nil, with(func(c map[string]any) { c["events"].(map[string]any)[riscPrefix+"account-disabled"] = map[string]any{} })), "invalid_request"},
		"no event":              {k.sign(t, nil, with(func(c map[string]any) { c["events"] = map[string]any{} })), "invalid_request"},
		"an unknown event":      {k.sign(t, nil, with(func(c map[string]any) { c["events"] = map[string]any{"https://evil.example/x": map[string]any{}} })), "invalid_request"},
		"issued in the future":  {k.sign(t, nil, with(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() })), "invalid_request"},
		"issued long ago":       {k.sign(t, nil, with(func(c map[string]any) { c["iat"] = now.Add(-10 * 24 * time.Hour).Unix() })), "invalid_request"},
		"no issue time":         {k.sign(t, nil, with(func(c map[string]any) { delete(c, "iat") })), "invalid_request"},
		"expired":               {k.sign(t, nil, with(func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() })), "invalid_request"},
		"no id":                 {k.sign(t, nil, with(func(c map[string]any) { delete(c, "jti") })), "invalid_request"},
		"no subject":            {k.sign(t, nil, with(func(c map[string]any) { delete(c, "sub_id") })), "invalid_request"},
		"an unreadable subject": {k.sign(t, nil, with(func(c map[string]any) { c["sub_id"] = map[string]any{"format": "spaceship"} })), "invalid_request"},
		"a crit header":         {k.sign(t, map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt", "crit": []string{"exp"}}, revoked()), "invalid_request"},
		"an id over 256 bytes":  {k.sign(t, nil, with(func(c map[string]any) { c["jti"] = strings.Repeat("j", 257) })), "invalid_request"},
		"a type not asked for": {k.sign(t, nil, with(func(c map[string]any) {
			c["events"] = map[string]any{caepPrefix + "device-compliance-change": map[string]any{"current_status": "not-compliant"}}
		})), "invalid_request"},
		"nested too deeply": {k.sign(t, nil, with(func(c map[string]any) {
			c["sub_id"] = map[string]any{"format": "complex", "user": map[string]any{"format": "complex",
				"user": map[string]any{"format": "email", "email": "ada@x.example"}}}
		})), "invalid_request"},
		"three segments missing": {"abc.def", "invalid_request"},
		"oversized":              {strings.Repeat("a", MaxToken+1), "invalid_request"},
	}
	for name, c := range cases {
		_, err := r.Verify(c.token)
		e, ok := err.(*Error)
		if !ok || e.Code != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
}

func TestSubjectsInEveryFormAreRead(t *testing.T) {
	k := newKey(t)
	r := receiver(t, k)
	for _, c := range []struct {
		sub          map[string]any
		person, ref  string
		inEventToken bool
	}{
		{sub: map[string]any{"format": "iss_sub", "iss": iss, "sub": "00u1a2b3"}, ref: "00u1a2b3"},
		{sub: map[string]any{"format": "complex", "user": map[string]any{"format": "email", "email": "nia@x.example"},
			"device": map[string]any{"format": "opaque", "id": "d1"}}, person: "nia@x.example"},
		{sub: map[string]any{"format": "account", "uri": "acct:Chen@X.example"}, person: "chen@x.example"},
		{sub: map[string]any{"format": "aliases", "identifiers": []any{
			map[string]any{"format": "phone_number", "phone_number": "+1"},
			map[string]any{"format": "email", "email": "gus@x.example"}}}, person: "gus@x.example"},
		// The formats that name no person are read, and name nobody.
		{sub: map[string]any{"format": "opaque", "id": "s-1"}},
		{sub: map[string]any{"format": "phone_number", "phone_number": "+15555550100"}},
		{sub: map[string]any{"format": "uri", "uri": "https://x.example/people/7"}},
		{sub: map[string]any{"format": "did", "url": "did:example:123"}},
		// The drafts before 1.0 put the subject inside the event.
		{sub: map[string]any{"format": "email", "email": "lena@x.example"}, person: "lena@x.example", inEventToken: true},
	} {
		claims := revoked()
		if c.inEventToken {
			delete(claims, "sub_id")
			claims["events"].(map[string]any)[caepPrefix+"session-revoked"].(map[string]any)["subject"] = c.sub
		} else {
			claims["sub_id"] = c.sub
		}
		set, err := r.Verify(k.sign(t, nil, claims))
		if err != nil {
			t.Errorf("%v: %v", c.sub, err)
			continue
		}
		if set.Subject.Person() != c.person || set.Subject.Ref() != c.ref {
			t.Errorf("%v read as person %q ref %q", c.sub, set.Subject.Person(), set.Subject.Ref())
		}
	}
}

// An aliases subject names a person only when its addresses agree, and
// iss_sub is read from the plain format alone: a principal named by sub is
// matched on that value, so the subject must say it and nothing else.
func TestASubjectIsReadOnlyForWhatItSaysUnambiguously(t *testing.T) {
	k := newKey(t)
	r := receiver(t, k)
	read := func(sub map[string]any) Subject {
		t.Helper()
		claims := revoked()
		claims["sub_id"] = sub
		set, err := r.Verify(k.sign(t, nil, claims))
		if err != nil {
			t.Fatalf("%v: %v", sub, err)
		}
		return set.Subject
	}
	two := read(map[string]any{"format": "aliases", "identifiers": []any{
		map[string]any{"format": "email", "email": "gus@x.example"},
		map[string]any{"format": "email", "email": "lee@x.example"}}})
	if two.Person() != "" {
		t.Errorf("two different addresses were read as %q", two.Person())
	}
	same := read(map[string]any{"format": "aliases", "identifiers": []any{
		map[string]any{"format": "email", "email": "Gus@x.example"},
		map[string]any{"format": "account", "uri": "acct:gus@x.example"}}})
	if same.Person() != "gus@x.example" {
		t.Errorf("one address said twice was read as %q", same.Person())
	}
	if iss, sub := read(map[string]any{"format": "iss_sub", "iss": iss, "sub": "00u1"}).IssSub(); iss == "" || sub != "00u1" {
		t.Errorf("a plain iss_sub was read as %q %q", iss, sub)
	}
	nested := read(map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": iss, "sub": "00u1"}})
	if _, sub := nested.IssSub(); sub != "" {
		t.Error("the user of a complex subject was read as a plain iss_sub")
	}
	if nested.Ref() != "00u1" {
		t.Errorf("the user's own identifier is lost: %q", nested.Ref())
	}
}

// -- the transmitter ----------------------------------------------------------

type fakeHTTP struct {
	answers map[string]*fetch.Result // "METHOD url" -> answer
	sent    []string
	bodies  map[string][]byte
	headers map[string]map[string]string
}

func (f *fakeHTTP) Do(_ context.Context, method, raw string, body []byte, h map[string]string) (*fetch.Result, error) {
	if _, err := fetch.ValidateURL(raw); err != nil {
		return nil, err
	}
	key := method + " " + raw
	f.sent = append(f.sent, key)
	if f.bodies == nil {
		f.bodies, f.headers = map[string][]byte{}, map[string]map[string]string{}
	}
	f.bodies[key], f.headers[key] = body, h
	if a, ok := f.answers[key]; ok {
		return a, nil
	}
	return &fetch.Result{Status: 404}, nil
}

func ok(status int, v any) *fetch.Result {
	b, _ := json.Marshal(v)
	return &fetch.Result{Status: status, Body: b}
}

func oktaConfig() map[string]any {
	return map[string]any{"issuer": iss, "jwks_uri": iss + "/oauth2/v1/keys",
		"delivery_methods_supported": []string{PushMethod},
		"configuration_endpoint":     iss + "/api/v1/ssf/stream",
		"status_endpoint":            iss + "/api/v1/ssf/stream/status",
		"verification_endpoint":      iss + "/api/v1/ssf/stream/verification"}
}

func TestATransmitterIsDiscoveredAndChecked(t *testing.T) {
	f := &fakeHTTP{answers: map[string]*fetch.Result{
		"GET " + iss + "/.well-known/ssf-configuration": ok(200, oktaConfig()),
	}}
	tr, err := Discover(context.Background(), f, iss)
	if err != nil || tr.JWKSURI != iss+"/oauth2/v1/keys" {
		t.Fatalf("%+v %v", tr, err)
	}
	if w, _ := WellKnown("https://idp.example/tenant/7"); w != "https://idp.example/.well-known/ssf-configuration/tenant/7" {
		t.Errorf("an issuer with a path is looked for at %s", w)
	}
	for name, cfg := range map[string]map[string]any{
		"another issuer": func() map[string]any { c := oktaConfig(); c["issuer"] = "https://evil.example"; return c }(),
		"no keys":        func() map[string]any { c := oktaConfig(); delete(c, "jwks_uri"); return c }(),
		"keys inward":    func() map[string]any { c := oktaConfig(); c["jwks_uri"] = "https://169.254.169.254/keys"; return c }(),
		"an endpoint inward": func() map[string]any {
			c := oktaConfig()
			c["verification_endpoint"] = "https://10.0.0.7/ssf/verify"
			return c
		}(),
		"poll only": func() map[string]any {
			c := oktaConfig()
			c["delivery_methods_supported"] = []string{"urn:ietf:rfc:8936"}
			return c
		}(),
	} {
		f := &fakeHTTP{answers: map[string]*fetch.Result{"GET " + iss + "/.well-known/ssf-configuration": ok(200, cfg)}}
		if _, err := Discover(context.Background(), f, iss); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAStreamIsAskedForAndVerified(t *testing.T) {
	var tr Transmitter
	b, _ := json.Marshal(oktaConfig())
	_ = json.Unmarshal(b, &tr)
	f := &fakeHTTP{answers: map[string]*fetch.Result{
		"POST " + iss + "/oauth2/v1/token": ok(200, map[string]any{"access_token": "at-1", "token_type": "Bearer"}),
		"POST " + iss + "/api/v1/ssf/stream": ok(201, map[string]any{"stream_id": "s-1", "iss": iss, "aud": aud,
			"events_delivered": []string{caepPrefix + "session-revoked"}}),
		"POST " + iss + "/api/v1/ssf/stream/verification": {Status: 204},
	}}
	tok, err := ClientCredentials(context.Background(), f, iss+"/oauth2/v1/token", "client", "s3cr3t", []string{"ssf.manage", "ssf.read"})
	if err != nil || tok != "at-1" {
		t.Fatalf("%q %v", tok, err)
	}
	s, err := tr.CreateStream(context.Background(), f, tok, aud, "Bearer push-secret", "Quilzo", Requested)
	if err != nil || s.ID != "s-1" || s.Audiences()[0] != aud {
		t.Fatalf("%+v %v", s, err)
	}
	var sent map[string]any
	_ = json.Unmarshal(f.bodies["POST "+iss+"/api/v1/ssf/stream"], &sent)
	d := sent["delivery"].(map[string]any)
	if d["method"] != PushMethod || d["endpoint_url"] != aud || d["authorization_header"] != "Bearer push-secret" {
		t.Errorf("asked for %v", sent)
	}
	if f.headers["POST "+iss+"/api/v1/ssf/stream"]["Authorization"] != "Bearer at-1" {
		t.Error("the stream was asked for without the access token")
	}
	if err := tr.RequestVerification(context.Background(), f, tok, "s-1", "st"); err != nil {
		t.Error(err)
	}
	if _, err := tr.CreateStream(context.Background(), f, tok, "http://quilzo.example/x", "", "", nil); err == nil {
		t.Error("a stream to a plain-http endpoint was asked for")
	}
}

// A refusal from the token endpoint never repeats the secret.
func TestATokenRefusalDoesNotCarryTheSecret(t *testing.T) {
	f := &fakeHTTP{answers: map[string]*fetch.Result{
		"POST " + iss + "/oauth2/v1/token": ok(401, map[string]any{"error": "invalid_client", "error_description": "client authentication failed"}),
	}}
	_, err := ClientCredentials(context.Background(), f, iss+"/oauth2/v1/token", "client", "s3cr3t-value", []string{"ssf.manage"})
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("%v", err)
	}
}
