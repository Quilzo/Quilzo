package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

const botToken = "123456:AAHfakeTokenForTestsOnly_not_a_real_one"

// signInitData builds a launch the way Telegram's client does, so the
// verification is tested against an independent implementation of the spec
// rather than against itself. A test that signs with the function it is testing
// proves only that the function is self-consistent.
func signInitData(t *testing.T, fields map[string]string, token string) string {
	t.Helper()
	pairs := make([]string, 0, len(fields))
	for k, v := range fields {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)

	secretMAC := hmac.New(sha256.New, []byte("WebAppData"))
	secretMAC.Write([]byte(token))
	checkMAC := hmac.New(sha256.New, secretMAC.Sum(nil))
	checkMAC.Write([]byte(strings.Join(pairs, "\n")))

	values := url.Values{}
	for k, v := range fields {
		values.Set(k, v)
	}
	values.Set("hash", hex.EncodeToString(checkMAC.Sum(nil)))
	return values.Encode()
}

func launch(t *testing.T, at time.Time, extra ...string) string {
	t.Helper()
	fields := map[string]string{
		"auth_date": fmt.Sprint(at.Unix()),
		"query_id":  "AAHdF6IQAAAAAN0XohDhrOrc",
		"user":      `{"id":279058397,"first_name":"Vladimir","username":"durov"}`,
	}
	for i := 0; i+1 < len(extra); i += 2 {
		fields[extra[i]] = extra[i+1]
	}
	return signInitData(t, fields, botToken)
}

// A launch signed by the right bot, recently, identifies its user.
func TestAGenuineLaunchIsAccepted(t *testing.T) {
	now := time.Now()
	user, err := VerifyInitData(launch(t, now.Add(-time.Minute)), botToken, now)
	if err != nil {
		t.Fatalf("a genuine launch was refused: %v", err)
	}
	if user.ID != 279058397 {
		t.Errorf("user id came back as %d", user.ID)
	}
	if user.Username != "durov" {
		t.Errorf("username came back as %q", user.Username)
	}
	if user.Label() != "@durov" {
		t.Errorf("label is %q", user.Label())
	}
	// Keyed on the id, because a username can be released and taken by somebody
	// else — and a store keyed on it would hand a stranger the previous owner's
	// pages the day they renamed.
	if user.Handle() != "tg279058397" {
		t.Errorf("handle is %q", user.Handle())
	}
}

// Every way a launch can be wrong has to be refused, and each of these is a way
// somebody actually tries.
func TestEveryForgedOrStaleLaunchIsRefused(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		data string
		tok  string
	}{
		{"signed by a different bot", launch(t, now, "auth_date", fmt.Sprint(now.Unix())), "999:otherbot"},
		{"no signature at all", "user=%7B%22id%22%3A1%7D&auth_date=" + fmt.Sprint(now.Unix()), botToken},
		{"empty", "", botToken},
		{"no user", signInitData(t, map[string]string{"auth_date": fmt.Sprint(now.Unix())}, botToken), botToken},
		{"no auth_date", signInitData(t, map[string]string{"user": `{"id":1}`}, botToken), botToken},
		{"a user with no id", signInitData(t, map[string]string{
			"auth_date": fmt.Sprint(now.Unix()), "user": `{"username":"x"}`}, botToken), botToken},
		{"user is not json", signInitData(t, map[string]string{
			"auth_date": fmt.Sprint(now.Unix()), "user": `not json`}, botToken), botToken},
		{"older than the maximum age", launch(t, now.Add(-MaxInitDataAge-time.Minute)), botToken},
		{"dated in the future", launch(t, now.Add(2*time.Hour)), botToken},
	}
	for _, c := range cases {
		if _, err := VerifyInitData(c.data, c.tok, now); err == nil {
			t.Errorf("%s was accepted", c.name)
		}
	}

	// A tampered field must invalidate the signature. This is the one that
	// matters most: it is how somebody would try to publish as another user.
	genuine := launch(t, now)
	values, _ := url.ParseQuery(genuine)
	values.Set("user", `{"id":1,"username":"attacker"}`)
	if _, err := VerifyInitData(values.Encode(), botToken, now); err == nil {
		t.Error("a launch with the user swapped out was accepted")
	}
}

// With no bot token there is no key, so there is no check. Refusing is the only
// safe reading of that state — accepting would make an unconfigured server an
// open door.
func TestWithNoBotTokenNothingIsAccepted(t *testing.T) {
	now := time.Now()
	if _, err := VerifyInitData(launch(t, now), "", now); err == nil {
		t.Error("a launch was accepted with no bot token configured")
	}
	if _, err := NewLink(User{ID: 1}, "", now); err == nil {
		t.Error("a link was minted with no bot token configured")
	}
}

// Telegram's newer clients add a `signature` field for their separate
// third-party Ed25519 scheme. Including it in the check string makes every
// launch from those clients fail, which is a bug that only appears against real
// traffic — so it is pinned here.
func TestASignatureFieldDoesNotBreakVerification(t *testing.T) {
	now := time.Now()
	genuine := launch(t, now)
	values, _ := url.ParseQuery(genuine)
	values.Set("signature", "3Dqlf1XmVh8ZQ_notARealEd25519Signature")
	if _, err := VerifyInitData(values.Encode(), botToken, now); err != nil {
		t.Errorf("a launch carrying Telegram's signature field was refused: %v", err)
	}
}

// -- the signed-link path --------------------------------------------------

func TestAMintedLinkWorksOnceAndOnlyOnce(t *testing.T) {
	now := time.Now()
	spender := NewMemory()
	spender.Now = func() time.Time { return now }

	raw, err := NewLink(User{ID: 42, Username: "someone"}, botToken, now)
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}

	user, err := VerifyLink(values, botToken, spender, now)
	if err != nil {
		t.Fatalf("a freshly minted link was refused: %v", err)
	}
	if user.ID != 42 || user.Username != "someone" {
		t.Errorf("the link identified %+v", user)
	}

	// The second attempt is the whole point: a link in a chat is a link that
	// gets forwarded.
	if _, err := VerifyLink(values, botToken, spender, now); err == nil {
		t.Error("the same link was accepted twice")
	}
}

func TestATamperedOrExpiredLinkIsRefused(t *testing.T) {
	now := time.Now()
	mint := func() url.Values {
		raw, err := NewLink(User{ID: 7, Username: "u"}, botToken, now)
		if err != nil {
			t.Fatal(err)
		}
		values, _ := url.ParseQuery(raw)
		return values
	}

	t.Run("the user id swapped", func(t *testing.T) {
		values := mint()
		values.Set("u", "8")
		if _, err := VerifyLink(values, botToken, NewMemory(), now); err == nil {
			t.Error("accepted a link with a different user id")
		}
	})
	t.Run("the expiry pushed out", func(t *testing.T) {
		values := mint()
		values.Set("e", fmt.Sprint(now.Add(100*time.Hour).Unix()))
		if _, err := VerifyLink(values, botToken, NewMemory(), now); err == nil {
			t.Error("accepted a link with an extended expiry")
		}
	})
	t.Run("past its expiry", func(t *testing.T) {
		values := mint()
		later := now.Add(LinkLifetime + time.Second)
		if _, err := VerifyLink(values, botToken, NewMemory(), later); err == nil {
			t.Error("accepted an expired link")
		}
	})
	t.Run("signed by a different bot", func(t *testing.T) {
		values := mint()
		if _, err := VerifyLink(values, "999:other", NewMemory(), now); err == nil {
			t.Error("accepted a link signed by another bot")
		}
	})
	t.Run("a different version", func(t *testing.T) {
		values := mint()
		values.Set("v", "q0")
		if _, err := VerifyLink(values, botToken, NewMemory(), now); err == nil {
			t.Error("accepted a link claiming another version")
		}
	})
	t.Run("with nowhere to record it", func(t *testing.T) {
		values := mint()
		if _, err := VerifyLink(values, botToken, nil, now); err == nil {
			t.Error("accepted a single-use link with no way to record it as spent")
		}
	})
}

// The order of the checks is load-bearing. If the nonce were spent before the
// signature was verified, anybody holding a URL could burn a legitimate user's
// link by requesting it with the signature edited.
func TestABadSignatureCannotBurnSomebodyElsesLink(t *testing.T) {
	now := time.Now()
	spender := NewMemory()
	spender.Now = func() time.Time { return now }

	raw, _ := NewLink(User{ID: 5}, botToken, now)
	genuine, _ := url.ParseQuery(raw)

	forged, _ := url.ParseQuery(raw)
	forged.Set("s", strings.Repeat("0", 64))
	if _, err := VerifyLink(forged, botToken, spender, now); err == nil {
		t.Fatal("a forged link was accepted")
	}

	if _, err := VerifyLink(genuine, botToken, spender, now); err != nil {
		t.Errorf("the genuine link stopped working after a forged attempt: %v", err)
	}
}

// Two links are two links. A nonce that repeated would make the second one
// unusable, which is the failure a fixed or badly seeded nonce produces.
func TestEveryLinkGetsItsOwnNonce(t *testing.T) {
	now := time.Now()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		raw, err := NewLink(User{ID: 1}, botToken, now)
		if err != nil {
			t.Fatal(err)
		}
		values, _ := url.ParseQuery(raw)
		nonce := values.Get("n")
		if nonce == "" {
			t.Fatal("a link was minted with no nonce")
		}
		if seen[nonce] {
			t.Fatalf("nonce %q was reused after %d links", nonce, i)
		}
		seen[nonce] = true
	}
}

// The spender forgets a nonce once its link would have expired anyway, or the
// map grows forever. And it refuses rather than evicting at the ceiling —
// evicting would let a flood of forged links push a real spent nonce out and
// make it replayable.
func TestTheSpenderForgetsExpiredNoncesAndRefusesRatherThanEvicting(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	m.Now = func() time.Time { return now }

	if !m.Spend("a", now.Add(time.Minute)) {
		t.Fatal("a fresh nonce was refused")
	}
	if m.Spend("a", now.Add(time.Minute)) {
		t.Fatal("a spent nonce was accepted again")
	}

	now = now.Add(2 * time.Minute)
	if !m.Spend("b", now.Add(time.Minute)) {
		t.Fatal("a fresh nonce was refused after the sweep")
	}
	if m.Len() != 1 {
		t.Errorf("the expired nonce was not swept; %d remembered", m.Len())
	}

	tight := &Memory{spent: map[string]time.Time{}, MaxEntries: 2,
		Now: func() time.Time { return now }}
	if !tight.Spend("one", now.Add(time.Hour)) || !tight.Spend("two", now.Add(time.Hour)) {
		t.Fatal("the first two nonces were refused")
	}
	if tight.Spend("three", now.Add(time.Hour)) {
		t.Error("a nonce was accepted past the ceiling; the map is unbounded")
	}
	// "one" must still be remembered: refusing at the ceiling rather than
	// evicting is what stops a flood making a real token replayable.
	if tight.Spend("one", now.Add(time.Hour)) {
		t.Error("a previously spent nonce became replayable at the ceiling")
	}
}
