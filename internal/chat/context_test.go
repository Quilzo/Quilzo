package chat

import (
	"net/url"
	"strconv"
	"testing"
	"time"
)

// The platform is separated twice: it is in the key derivation, and it is
// checked as data. Either alone refuses a foreign credential, which is why
// removing either one left every test in chat_test.go passing.
//
// That is good design and a bad test situation. Two defences that mask each
// other are two defences nobody notices losing: the first removal is silent,
// and the second is then the one that matters and has nothing watching it.
//
// These tests sit inside the package so they can sign with one context and
// claim another, which is the only way to exercise one half at a time.

const isolated = "a-signing-secret-for-tests"

func isolatedAt() time.Time { return time.Unix(1787000000, 0) }

// values builds a credential body claiming `claims`, signed under `keyedTo`.
func values(t *testing.T, claims, keyedTo Platform) url.Values {
	t.Helper()
	v := url.Values{}
	v.Set("v", version)
	v.Set("p", string(Arrival))
	v.Set("m", string(claims))
	v.Set("u", "42")
	v.Set("e", strconv.FormatInt(isolatedAt().Add(LinkLifetime).Unix(), 10))
	v.Set("n", "a-fixed-nonce-for-this-test")
	v.Set("s", sign(v, isolated, keyedTo))
	return v
}

func isolatedSpender() *Memory {
	m := NewMemory()
	m.Now = isolatedAt
	return m
}

// The key half, alone.
//
// The body honestly claims Slack, so the data check is satisfied and cannot be
// what refuses this. Only the derived key differs. If the platform were dropped
// from the signing context this would verify.
func TestThePlatformIsInTheKeyAndNotOnlyInTheData(t *testing.T) {
	v := values(t, Slack, Telegram)

	if a, err := VerifyLink(v, isolated, Slack, isolatedSpender(), isolatedAt()); err == nil {
		t.Fatalf("a credential signed under the Telegram context verified as "+
			"Slack. The data said Slack, so only the key could have refused "+
			"it, and it did not: %+v", a)
	}
}

// The data half, alone.
//
// Signed correctly for Slack, so the signature verifies and cannot be what
// refuses this. Only the claim inside says Telegram. If the claim were not
// checked this would be accepted as a Slack credential.
func TestThePlatformClaimIsCheckedAndNotOnlySigned(t *testing.T) {
	v := values(t, Telegram, Slack)

	// Guard the guard: confirm the signature really does verify under Slack,
	// so a failure below is the data check and not a broken fixture.
	if sign(v, isolated, Slack) != v.Get("s") {
		t.Fatal("the fixture is wrong: it is not correctly signed for Slack, " +
			"so this test would pass on the signature and prove nothing")
	}

	if a, err := VerifyLink(v, isolated, Slack, isolatedSpender(), isolatedAt()); err == nil {
		t.Fatalf("a credential claiming Telegram verified as Slack. It was "+
			"correctly signed for Slack, so only the claim could have refused "+
			"it, and it did not: %+v", a)
	}
}

// A platform name goes into a key context built by concatenation, so a name
// containing the separator could make two different platforms derive the same
// key.
//
// No caller passes an attacker-controlled platform today — they are constants
// in this package. This guards the future caller who derives one from a
// configuration file, at which point the ambiguity becomes reachable and the
// symptom is two messengers silently sharing a key.
func TestAPlatformNameCannotContainTheContextSeparator(t *testing.T) {
	for _, bad := range []Platform{"", "   ", "a/b", "a:b", "a b", "a\tb", "a\nb"} {
		if bad.Valid() {
			t.Errorf("%q is accepted as a platform name, and it can collide "+
				"with another inside the key context", string(bad))
		}
	}
	for _, good := range []Platform{Telegram, Slack, "matrix", "discord"} {
		if !good.Valid() {
			t.Errorf("%q was refused as a platform name", string(good))
		}
	}
}

// And the concatenation itself: two platforms must never derive one key.
func TestTwoPlatformsNeverDeriveTheSameKey(t *testing.T) {
	v := url.Values{}
	v.Set("u", "42")

	seen := map[string]Platform{}
	for _, p := range []Platform{Telegram, Slack, "matrix", "discord"} {
		s := sign(v, isolated, p)
		if other, clash := seen[s]; clash {
			t.Fatalf("%q and %q sign identically", p, other)
		}
		seen[s] = p
	}
}
