// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/throttle"
)

// A passkey sign-in refused for trying too often is answered in JSON, with
// when to come back, as everything else the ceremony answers is.
//
// It was answered with the HTML sign-in page. The page's script reads every
// answer from /signin/passkey/verify as JSON, so the person was shown
// "Unexpected token '<', "<!doctype "... is not valid JSON" where the
// throttle's own words say how long to wait.
func TestAThrottledPasskeySignInIsAnsweredInJSON(t *testing.T) {
	srv := enrolling(t)
	link, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dana := newFake(t, "dana-key")
	if w := dana.enrol(t, srv, link); w.Code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", w.Code, w.Body)
	}
	stopped := time.Now()
	srv.Throttle = throttle.New(throttle.Default()).WithClock(func() time.Time { return stopped })
	guesser := newFake(t, "dana-key") // the same credential id, not the key
	for i := 0; i < 10; i++ {
		guesser.signInFrom(t, srv, "203.0.113.7:5000")
	}
	w := guesser.signInFrom(t, srv, "203.0.113.7:5000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("the guessing was not throttled: %d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("a throttled passkey sign-in was answered as %q, which the page's script cannot read", ct)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a throttled passkey sign-in does not say when to come back")
	}
	if why, _ := decodeBody(t, w)["error"].(string); !strings.Contains(why, "Try again in") {
		t.Errorf("the answer does not say how long to wait: %q", why)
	}
}

// A passkey sign-in that proves nobody is told to whatever counts failed
// sign-ins by where they come from (the shield's signin-attack playbook):
// a credential the store does not know, and one whose signature does not
// verify, from an address throttled or not. A sign-in that works is not,
// and nor is a key whose holder only has to be asked for their PIN.
//
// Only a guessed token reached the shield. Eighteen passkeys that proved
// nobody, from one address, were slowed by the throttle and blocked by
// nothing, so "Repeated failed sign-ins from one source" never saw the one
// door built for people.
func TestAPasskeySignInThatProvesNobodyIsCountedAgainstItsSource(t *testing.T) {
	srv := enrolling(t)
	link, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dana := newFake(t, "dana-key")
	if w := dana.enrol(t, srv, link); w.Code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", w.Code, w.Body)
	}
	stopped := time.Now()
	srv.Throttle = throttle.New(throttle.Default()).WithClock(func() time.Time { return stopped })
	var from []string
	srv.OnFailedSignIn = func(r *http.Request) { from = append(from, sourceOf(r)) }

	const away = "203.0.113.7:5000"
	if w := dana.signInFrom(t, srv, "192.0.2.10:5000"); w.Code != http.StatusOK {
		t.Fatalf("dana's own key: %d %s", w.Code, w.Body)
	}
	if len(from) != 0 {
		t.Fatalf("a sign-in that worked was counted as a failure: %v", from)
	}
	forged := newFake(t, "dana-key") // dana's credential id, somebody else's key
	stranger := newFake(t, "nobody-here")
	for i := 0; i < 9; i++ {
		forged.signInFrom(t, srv, away)
		stranger.signInFrom(t, srv, away)
	}
	if len(from) != 18 {
		t.Fatalf("%d of 18 passkey sign-ins that proved nobody were counted", len(from))
	}
	for _, src := range from {
		if src == "" || src != from[0] || !strings.HasPrefix(src, "203.0.113.") {
			t.Fatalf("counted against %q, not where they came from", src)
		}
	}

	// A key that verified and did not ask for its holder's PIN is its
	// holder, told to make it ask: not a guess.
	from = nil
	dana.flags = 0x01 // present, not verified
	if w := dana.signInFrom(t, srv, "192.0.2.10:5000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("a key that did not ask for its PIN: %d %s", w.Code, w.Body)
	}
	if len(from) != 0 {
		t.Errorf("a key's own holder, asked for a PIN, was counted as a guess")
	}
}

// Each page that speaks the passkey ceremony says what a refusal says,
// whether the admin wrote it ("error") or the shield did, which answers a
// blocked or slowed address in problem+json ("detail", with when to come
// back), before the admin sees the request.
//
// They read "error" alone, so once the failed passkeys from an address
// were counted and the address blocked, the person there was told "that
// did not work" and not when they could try again.
func TestTheCeremonyPagesSayTheShieldsRefusal(t *testing.T) {
	for _, page := range []string{"passkeysignin.html", "admin.js", "enrol.html", "passkeys.html"} {
		b, err := assets.ReadFile("assets/" + page)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(b); strings.Contains(s, `.error || "that did not work"`) ||
			!strings.Contains(s, `.detail || "that did not work"`) {
			t.Errorf("%s says the admin's refusal and not the shield's", page)
		}
	}
}
