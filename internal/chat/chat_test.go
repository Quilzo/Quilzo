package chat_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
)

const secret = "a-signing-secret-for-tests"

func at() time.Time { return time.Unix(1787000000, 0) }

// spender returns a Memory on the same clock as the credentials.
//
// Memory sweeps expired nonces using time.Now unless told otherwise, and these
// tests mint credentials on a fixed clock in the past. Mixing the two makes the
// sweep delete a nonce between two calls, so a single-use link is accepted
// twice — which is what happened, and it looked exactly like a broken
// single-use check rather than like two clocks disagreeing.
func spender() *chat.Memory {
	m := chat.NewMemory()
	m.Now = at
	return m
}

func dana(p chat.Platform) chat.Account {
	return chat.Account{Platform: p, ID: 42, Username: "dana", FirstName: "Dana"}
}

func linkValues(t *testing.T, a chat.Account) url.Values {
	t.Helper()
	raw, err := chat.NewLink(a, secret, at())
	if err != nil {
		t.Fatal(err)
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The control. Without it every refusal below proves only that the function
// refuses things.
func TestAGenuineLinkIsAccepted(t *testing.T) {
	got, err := chat.VerifyLink(linkValues(t, dana(chat.Telegram)), secret,
		chat.Telegram, spender(), at())
	if err != nil {
		t.Fatalf("a link this package minted was refused: %v", err)
	}
	if got.ID != 42 || got.Username != "dana" {
		t.Fatalf("wrong account: %+v", got)
	}
}

// The risk multi-platform support introduces, and the reason the platform is in
// the signing context.
//
// One messenger has one key and one credential shape. Several messengers have
// several, and an operator who configures the same secret for two integrations
// is doing the obvious wrong thing. The design has to survive it: a credential
// minted for one platform must not verify at another even then.
func TestACredentialForOnePlatformDoesNotVerifyAtAnother(t *testing.T) {
	fromTelegram := linkValues(t, dana(chat.Telegram))

	// Same secret, different platform. This is the case an operator creates by
	// reusing a signing secret, which is exactly what people do.
	if a, err := chat.VerifyLink(fromTelegram, secret, chat.Slack,
		spender(), at()); err == nil {
		t.Fatalf("a Telegram link verified as a Slack link: %+v", a)
	}

	// And the other direction, because the two branches are the same code but
	// the assumption is worth pinning both ways.
	fromSlack := linkValues(t, dana(chat.Slack))
	if a, err := chat.VerifyLink(fromSlack, secret, chat.Telegram,
		spender(), at()); err == nil {
		t.Fatalf("a Slack link verified as a Telegram link: %+v", a)
	}
}

// Rewriting the platform claim must break the signature, or the field is a
// label an attacker edits rather than a fact the key covers.
func TestThePlatformIsSignedAndNotJustStated(t *testing.T) {
	v := linkValues(t, dana(chat.Telegram))
	v.Set("m", string(chat.Slack))

	if _, err := chat.VerifyLink(v, secret, chat.Slack, spender(), at()); err == nil {
		t.Fatal("rewriting the platform field produced a link that verified, " +
			"so the platform is not covered by the signature")
	}
}

// Two people with the same numeric id on different messengers are two people.
// Without the prefix the second to arrive inherits the first one's pages.
func TestTheHandleSeparatesPlatforms(t *testing.T) {
	if a, b := dana(chat.Telegram).Handle(), dana(chat.Slack).Handle(); a == b {
		t.Fatalf("the same id on two platforms produced one handle: %s", a)
	}
	// And a rename does not move it.
	renamed := dana(chat.Telegram)
	renamed.Username = "someone-else"
	if renamed.Handle() != dana(chat.Telegram).Handle() {
		t.Error("renaming changed the handle, so a rename would orphan the pages")
	}
}

// An empty platform would be a signing context every platform shares, which is
// the cross-replay this whole design exists to prevent.
func TestAnEmptyPlatformIsRefusedRatherThanDefaulted(t *testing.T) {
	if _, err := chat.NewLink(chat.Account{ID: 42}, secret, at()); err == nil {
		t.Fatal("minted a credential with no platform")
	}
	v := linkValues(t, dana(chat.Telegram))
	if _, err := chat.VerifyLink(v, secret, "", spender(), at()); err == nil {
		t.Fatal("verified against an empty platform")
	}
}

// A link and a grant are the same bytes under the same key. Only the purpose
// separates them, so it is checked rather than merely present.
func TestALinkCannotBeSubmittedAsAGrant(t *testing.T) {
	raw, err := chat.NewLink(dana(chat.Telegram), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	if a, err := chat.VerifyGrant(raw, secret, chat.Telegram, at()); err == nil {
		t.Fatalf("a link verified as a grant, so single-use can be bypassed "+
			"by submitting it to the other verifier: %+v", a)
	}
}

// And the other direction, which must not depend on the grant happening to
// lack a nonce.
func TestAGrantCannotBeUsedAsAnArrivalLink(t *testing.T) {
	raw, err := chat.NewGrant(dana(chat.Telegram), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := chat.VerifyLink(v, secret, chat.Telegram, spender(), at()); err == nil {
		t.Fatalf("a grant verified as an arrival link: %+v", a)
	}
}

// Single-use means once.
func TestALinkWorksOnceAndOnlyOnce(t *testing.T) {
	v := linkValues(t, dana(chat.Telegram))
	sp := spender()

	if _, err := chat.VerifyLink(v, secret, chat.Telegram, sp, at()); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}
	if _, err := chat.VerifyLink(v, secret, chat.Telegram, sp, at()); err == nil {
		t.Fatal("the same link was accepted twice")
	}
}

// A broken signature must not burn a legitimate nonce. Spending before
// checking would let anybody with a URL deny somebody else their link.
func TestABadSignatureCannotBurnSomebodyElsesLink(t *testing.T) {
	v := linkValues(t, dana(chat.Telegram))
	sp := spender()

	tampered := url.Values{}
	for k, vs := range v {
		tampered[k] = append([]string(nil), vs...)
	}
	tampered.Set("s", strings.Repeat("0", 64))
	if _, err := chat.VerifyLink(tampered, secret, chat.Telegram, sp, at()); err == nil {
		t.Fatal("a forged link verified")
	}

	// The real one still works.
	if _, err := chat.VerifyLink(v, secret, chat.Telegram, sp, at()); err != nil {
		t.Fatalf("the forgery burned the genuine link's nonce: %v", err)
	}
}

// Without a spender there is nothing enforcing single-use, and accepting is
// worse than refusing.
func TestNoSpenderRefusesRatherThanAcceptingForever(t *testing.T) {
	v := linkValues(t, dana(chat.Telegram))
	if _, err := chat.VerifyLink(v, secret, chat.Telegram, nil, at()); err == nil {
		t.Fatal("verified a single-use link with nothing to spend the nonce")
	}
}

// A grant is multi-use within its window on purpose: a form somebody mistypes
// has to be submittable twice.
func TestAGrantIsUsableMoreThanOnceWithinItsWindow(t *testing.T) {
	raw, err := chat.NewGrant(dana(chat.Telegram), secret, at())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := chat.VerifyGrant(raw, secret, chat.Telegram, at()); err != nil {
			t.Fatalf("submission %d was refused: %v", i+1, err)
		}
	}
	// But not forever.
	late := at().Add(chat.GrantLifetime + time.Minute)
	if _, err := chat.VerifyGrant(raw, secret, chat.Telegram, late); err == nil {
		t.Error("an expired grant was accepted")
	}
}

func TestAnExpiredLinkIsRefused(t *testing.T) {
	v := linkValues(t, dana(chat.Telegram))
	late := at().Add(chat.LinkLifetime + time.Minute)
	if _, err := chat.VerifyLink(v, secret, chat.Telegram, spender(), late); err == nil {
		t.Fatal("an expired link verified")
	}
}

func TestNoSecretRefusesEverything(t *testing.T) {
	v := linkValues(t, dana(chat.Telegram))
	for _, s := range []string{"", "   "} {
		if _, err := chat.VerifyLink(v, s, chat.Telegram, spender(), at()); err == nil {
			t.Errorf("verified with secret %q", s)
		}
	}
}

// Every link gets its own nonce, or single-use is a property of one link
// rather than of the scheme.
func TestEveryLinkGetsItsOwnNonce(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 25; i++ {
		n := linkValues(t, dana(chat.Telegram)).Get("n")
		if n == "" {
			t.Fatal("a link was minted with no nonce")
		}
		if seen[n] {
			t.Fatalf("nonce %q was issued twice", n)
		}
		seen[n] = true
	}
}
