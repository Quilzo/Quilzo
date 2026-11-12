// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"strings"
	"testing"
)

// No address a record carries is written with the credentials it can
// hold: a password in it, its query or its fragment. Whatever wrote the
// record, from whichever surface, and wherever in the record the address
// stands: a detail of its own, a sentence, an error, the resource.
//
// Values were written as given, and the only guard was on the names of
// details, so an address with a password, a ?token= or an #access_token=
// went into the log in clear, for the auditor who reads it and every copy
// of it forwarded to a SIEM: `quilzo config set site.base_url` with a
// staging site's password, a card registered by an address with its key,
// and every error that quotes the address it could not reach.
func TestAnAddressIsWrittenWithoutItsCredentials(t *testing.T) {
	for _, key := range [][]byte{nil, []byte("0123456789abcdef0123456789abcdef")} {
		l, path := newLog(t, key)
		e := ok(t, l, Record{
			Action: "config.set", Resource: "https://site.example/feed?key=r3s0urceSECRET", Outcome: Failure,
			Principal: "dana", Kind: KindHuman, Verified: true,
			Detail: map[string]string{
				"to":     "https://staging:pa55wordSECRET@staging.example.com",
				"card":   "https://agents.example/card.json?token=t0kenSECRET&v=2",
				"reason": `Post "https://hooks.example/in?sig=s1gSECRET": dial tcp: refused`,
				"from":   "redis://:redisSECRET@cache.internal:6379/0 and postgres://app:pgSECRET@db/app",
				"back":   "https://app.example/done#access_token=fr4gSECRET",
				"plain":  "https://example.com/about",
				"words":  "nothing in here is an address: a://b is not one of ours? it is",
			},
		})
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"r3s0urceSECRET", "pa55wordSECRET", "t0kenSECRET", "s1gSECRET",
			"redisSECRET", "pgSECRET", "fr4gSECRET", "staging:", "app:pg"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("the log holds %q (key %v)", secret, key != nil)
			}
		}
		for k, want := range map[string]string{
			"to":     "https://…@staging.example.com",
			"card":   "https://agents.example/card.json?…",
			"reason": `Post "https://hooks.example/in?…": dial tcp: refused`,
			"from":   "redis://…@cache.internal:6379/0 and postgres://…@db/app",
			"back":   "https://app.example/done#…",
			"plain":  "https://example.com/about",
			"words":  "nothing in here is an address: a://b is not one of ours? it is",
		} {
			if got := e.Detail[k]; got != want {
				t.Errorf("%s was written as %q, want %q", k, got, want)
			}
		}
		if e.Resource != "https://site.example/feed?…" {
			t.Errorf("the resource was written as %q", e.Resource)
		}
		events, err := Read(path)
		if err != nil {
			t.Fatal(err)
		}
		if ok, problems := Verify(events); !ok {
			t.Errorf("the chain does not verify: %v", problems)
		}
	}
}

// A password with a "/", a "?" or a "#" in it, typed into an address as it
// is, is not written either.
//
// The host was taken to end at the first of those, so the user and the
// password before it were read as a host and a port and written in clear,
// and with a "/" the rest of the password with them. Such an address does
// not parse, and the error that says so quotes it whole ("parse
// \"https://…\": invalid port"), so it reached the log in every error that
// recorded why an address could not be used, as well as wherever it was
// typed.
func TestAPasswordThatEndsTheHostEarlyIsNotWritten(t *testing.T) {
	l, path := newLog(t, nil)
	e := ok(t, l, Record{
		Action: "config.set", Resource: "/", Outcome: Success,
		Principal: "dana", Kind: KindHuman, Verified: true,
		Detail: map[string]string{
			"slash":    "https://staging:pa55/SECRETword@staging.example.com/feed",
			"question": "https://staging:pa55?SECRETword@staging.example.com/feed?v=1",
			"hash":     "https://staging:pa55#SECRETword@staging.example.com",
			"error":    `parse "postgres://app:abc/SECRETdef@db.internal/app": invalid port`,
			"port":     "https://staging.example.com:8443/feed",
			"ipv6":     "https://[2001:db8::1]:8443/feed",
			"handle":   "https://social.example/@dana",
		},
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET", "pa55", "staging:", "app:"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
	for k, want := range map[string]string{
		"slash":    "https://…@staging.example.com/feed",
		"question": "https://…@staging.example.com/feed?…",
		"hash":     "https://…@staging.example.com",
		"error":    `parse "postgres://…@db.internal/app": invalid port`,
		"port":     "https://staging.example.com:8443/feed",
		"ipv6":     "https://[2001:db8::1]:8443/feed",
		"handle":   "https://social.example/@dana",
	} {
		if got := e.Detail[k]; got != want {
			t.Errorf("%s was written as %q, want %q", k, got, want)
		}
	}
}

// What a record names as an address and does not hold a credential is
// written as it was given, and so is everything that is not an address.
func TestAnAddressWithoutCredentialsIsWrittenAsItIs(t *testing.T) {
	for _, s := range []string{
		"", "/blog/post", "publish 3 pages", "https://example.com", "https://example.com/a/b",
		"see https://example.com/a and https://other.example/b", "https://example.com/?", "mailto:dana@example.com",
	} {
		if got := WithoutCredentials(s); got != s {
			t.Errorf("WithoutCredentials(%q) = %q", s, got)
		}
	}
}
