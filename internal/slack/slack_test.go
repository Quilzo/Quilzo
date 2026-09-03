package slack_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
	"github.com/quilzo/quilzo/internal/slack"
)

const secret = "8f742231b10e8888abcd99yyyzzz85a5"

func at() time.Time { return time.Unix(1787000000, 0) }

func body() string {
	v := url.Values{}
	v.Set("command", "/publish")
	v.Set("text", "the new pricing page")
	v.Set("user_id", "U024BE7LH")
	v.Set("user_name", "dana")
	v.Set("team_id", "T0001")
	return v.Encode()
}

// signed builds a request the way Slack would.
//
// The signing is written out here rather than calling the package's own helper.
// A test that signs with the function it is testing proves only that the
// function agrees with itself, and this is the one check standing between a
// Slack workspace and anyone who can reach the URL.
func signed(t *testing.T, raw string, stamp int64) *http.Request {
	t.Helper()
	ts := fmt.Sprintf("%d", stamp)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":" + raw))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	r := httptest.NewRequest("POST", "/slack/command", strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", sig)
	return r
}

// The control. Without it every refusal below proves only that Verify refuses.
func TestAGenuineRequestIsAccepted(t *testing.T) {
	got, err := slack.Verify(signed(t, body(), at().Unix()), secret, at())
	if err != nil {
		t.Fatalf("a correctly signed request was refused: %v", err)
	}
	if got.Command() != "publish" {
		t.Errorf("command is %q, want publish", got.Command())
	}
	if got.Text() != "the new pricing page" {
		t.Errorf("text is %q", got.Text())
	}
	if got.Account.Platform != chat.Slack {
		t.Errorf("platform is %q", got.Account.Platform)
	}
	if got.Account.Username != "dana" {
		t.Errorf("username is %q", got.Account.Username)
	}
}

// Changing the body must break the signature. This is the attack that matters:
// making the bot publish something nobody asked for.
func TestATamperedBodyIsRefused(t *testing.T) {
	r := signed(t, body(), at().Unix())
	// Same headers, different body.
	r.Body = httptest.NewRequest("POST", "/", strings.NewReader(
		strings.Replace(body(), "pricing", "wiretap", 1))).Body

	if got, err := slack.Verify(r, secret, at()); err == nil {
		t.Fatalf("a request whose body was changed after signing verified: %+v", got)
	}
}

// A different workspace's secret must not verify here.
func TestAnotherWorkspacesSignatureIsRefused(t *testing.T) {
	r := signed(t, body(), at().Unix())
	if _, err := slack.Verify(r, "a-completely-different-secret", at()); err == nil {
		t.Fatal("a request signed with another secret verified")
	}
}

// Slack recommends refusing anything older than five minutes. Without it a
// request captured from a proxy log authenticates forever, because the bytes
// do not change.
func TestAnOldRequestIsRefused(t *testing.T) {
	old := at().Add(-10 * time.Minute)
	if _, err := slack.Verify(signed(t, body(), old.Unix()), secret, at()); err == nil {
		t.Fatal("a ten-minute-old request verified")
	}
	// And the boundary holds in the useful direction.
	recent := at().Add(-4 * time.Minute)
	if _, err := slack.Verify(signed(t, body(), recent.Unix()), secret, at()); err != nil {
		t.Errorf("a four-minute-old request was refused: %v", err)
	}
}

// Moving the timestamp to defeat the age check must break the signature,
// because the timestamp is inside the signed string.
func TestTheTimestampCannotBeMovedToDefeatTheAgeCheck(t *testing.T) {
	old := at().Add(-10 * time.Minute)
	r := signed(t, body(), old.Unix())
	// Freshen the header, keeping the signature made over the old timestamp.
	r.Header.Set("X-Slack-Request-Timestamp", fmt.Sprintf("%d", at().Unix()))

	if _, err := slack.Verify(r, secret, at()); err == nil {
		t.Fatal("re-dating a captured request let it through, so the " +
			"timestamp is not covered by the signature")
	}
}

func TestAnUnsignedRequestIsRefused(t *testing.T) {
	for _, drop := range []string{"X-Slack-Signature", "X-Slack-Request-Timestamp"} {
		r := signed(t, body(), at().Unix())
		r.Header.Del(drop)
		if _, err := slack.Verify(r, secret, at()); err == nil {
			t.Errorf("a request with no %s verified", drop)
		}
	}
}

// No secret configured must refuse everything. "Nothing configured" reading as
// "everything is signed" is the worst version of this bug, because it appears
// the moment somebody forgets an environment variable.
func TestNoConfiguredSecretRefusesEverything(t *testing.T) {
	for _, s := range []string{"", "   "} {
		if _, err := slack.Verify(signed(t, body(), at().Unix()), s, at()); err == nil {
			t.Errorf("verified with secret %q", s)
		}
	}
}

// Two people in two workspaces can hold the same Slack user id. Without the
// workspace in the identity they would be one account holding one set of pages.
func TestTheSameUserIDInTwoWorkspacesIsTwoAccounts(t *testing.T) {
	one := body()
	two := strings.Replace(body(), "team_id=T0001", "team_id=T0002", 1)

	a, err := slack.Verify(signed(t, one, at().Unix()), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	b, err := slack.Verify(signed(t, two, at().Unix()), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	if a.Account.Handle() == b.Account.Handle() {
		t.Fatalf("the same user id in two workspaces produced one handle: %s",
			a.Account.Handle())
	}
}

// The handle must follow the id, never the display name, or a rename orphans
// somebody's pages.
func TestRenamingDoesNotMoveTheHandle(t *testing.T) {
	before, err := slack.Verify(signed(t, body(), at().Unix()), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	renamed := strings.Replace(body(), "user_name=dana", "user_name=dana2", 1)
	after, err := slack.Verify(signed(t, renamed, at().Unix()), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	if before.Account.Handle() != after.Account.Handle() {
		t.Errorf("a rename moved the handle: %s became %s",
			before.Account.Handle(), after.Account.Handle())
	}
}

// The derived id must be positive and stable, because chat.Account refuses a
// non-positive one — and a failure that depended on which user arrived would
// be the worst kind.
func TestDerivedIDsArePositiveAndStable(t *testing.T) {
	seen := map[int64]string{}
	for i := 0; i < 500; i++ {
		raw := strings.Replace(body(), "user_id=U024BE7LH",
			fmt.Sprintf("user_id=U%06d", i), 1)
		got, err := slack.Verify(signed(t, raw, at().Unix()), secret, at())
		if err != nil {
			t.Fatalf("user %d: %v", i, err)
		}
		id := got.Account.ID
		if id <= 0 {
			t.Fatalf("user %d derived a non-positive id: %d", i, id)
		}
		if other, clash := seen[id]; clash {
			t.Fatalf("two users derived the same id %d: %s and U%06d",
				id, other, i)
		}
		seen[id] = fmt.Sprintf("U%06d", i)
	}
	if len(seen) != 500 {
		t.Fatalf("checked %d ids, expected 500", len(seen))
	}
}

// A request naming no user or no workspace is not something to publish as.
func TestARequestWithNoIdentityIsRefused(t *testing.T) {
	for _, drop := range []string{"user_id", "team_id"} {
		v, _ := url.ParseQuery(body())
		v.Del(drop)
		if _, err := slack.Verify(signed(t, v.Encode(), at().Unix()), secret, at()); err == nil {
			t.Errorf("a request with no %s verified", drop)
		}
	}
}

// The body is read before anything is known about the sender, which makes it
// the one place an unauthenticated caller decides how much memory to use.
//
// The reason is asserted, not just the refusal. An oversized body is truncated
// by the LimitReader before it is hashed, so the signature fails too — and a
// test checking only "was it refused" passes with the size check deleted,
// which is what happened. The error has to say it was the size.
func TestAnOversizedBodyIsRefusedForBeingOversized(t *testing.T) {
	huge := "text=" + strings.Repeat("x", slack.MaxBody+10)
	_, err := slack.Verify(signed(t, huge, at().Unix()), secret, at())
	if err == nil {
		t.Fatal("a body over the ceiling was accepted")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("refused for the wrong reason: %v\n"+
			"  An oversized body should be turned away by the size check, "+
			"before the signature, so the bound on memory is real rather than "+
			"an accident of the hash not matching a truncated body.", err)
	}
}
