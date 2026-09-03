package telegram

import (
	"fmt"
	"github.com/quilzo/quilzo/internal/chat"
	"net/url"
	"strings"
	"testing"
	"time"
)

const probeToken = "123456:AAExampleBotTokenForTestingOnly"

// probeSign signs through the package's existing independent helper.
//
// signInitData implements the spec from scratch rather than calling this
// package's mac(), which is the property that matters: a test signing with the
// function it is testing proves only that the function agrees with itself.
func probeSign(t *testing.T, fields map[string]string) string {
	t.Helper()
	return signInitData(t, fields, probeToken)
}

func nowish() time.Time { return time.Unix(1787000000, 0) }

func validFields() map[string]string {
	return map[string]string{
		"auth_date": fmt.Sprintf("%d", nowish().Unix()),
		"user":      `{"id":42,"username":"dana","first_name":"Dana"}`,
		"query_id":  "AAaBbCc",
	}
}

// The control: a correctly signed launch is accepted. Without this the
// refusals below prove only that the function refuses things.
func TestProbeAGenuineLaunchIsAccepted(t *testing.T) {
	u, err := VerifyInitData(probeSign(t, validFields()), probeToken, nowish())
	if err != nil {
		t.Fatalf("a correctly signed launch was refused: %v", err)
	}
	if u.ID != 42 || u.Username != "dana" {
		t.Fatalf("wrong user: %+v", u)
	}
}

// Change any signed field and the signature must fail. This is the attack that
// matters: impersonating another Telegram account.
func TestProbeChangingTheUserIsRefused(t *testing.T) {
	f := validFields()
	blob := probeSign(t, f)

	// Swap the user for somebody else, keeping the original hash.
	tampered := strings.Replace(blob,
		url.QueryEscape(f["user"]),
		url.QueryEscape(`{"id":1,"username":"admin","first_name":"Admin"}`), 1)
	if tampered == blob {
		t.Fatal("the probe did not actually change anything")
	}
	if u, err := VerifyInitData(tampered, probeToken, nowish()); err == nil {
		t.Fatalf("accepted a launch with a swapped user: became %+v", u)
	}
}

// A blob signed by a different bot must not verify. Otherwise anyone who can
// stand up their own bot can impersonate any user of this one.
func TestProbeAnotherBotsSignatureIsRefused(t *testing.T) {
	blob := signInitData(t, validFields(), "999:SomeOtherBotToken")
	if _, err := VerifyInitData(blob, probeToken, nowish()); err == nil {
		t.Fatal("a launch signed by a different bot verified")
	}
}

// The classic bug: an attacker adds `signature` (or any excluded key) carrying
// content that the check string ignores. Excluding a key from the check string
// is correct for Telegram's Ed25519 scheme, and it must not become a place to
// smuggle a value that anything downstream reads.
func TestProbeExcludedKeysCannotCarryAnythingSigned(t *testing.T) {
	f := validFields()
	blob := probeSign(t, f)

	// Adding `signature` must not break a valid launch...
	withSig := blob + "&signature=" + url.QueryEscape("anything-at-all")
	if _, err := VerifyInitData(withSig, probeToken, nowish()); err != nil {
		t.Errorf("adding a signature field broke a valid launch: %v", err)
	}

	// ...and `hash` itself must still be the thing checked.
	swapped := probeSign(t, f)
	swapped = strings.Replace(swapped, "hash=", "hash="+
		strings.Repeat("0", 4), 1)
	if _, err := VerifyInitData(swapped, probeToken, nowish()); err == nil {
		t.Error("a corrupted hash verified")
	}
}

// An empty or absent hash must never verify. A check that treats "no signature"
// as "nothing to disagree with" is the way this class of bug usually appears.
func TestProbeAnUnsignedLaunchIsRefused(t *testing.T) {
	v := url.Values{}
	for k, val := range validFields() {
		v.Set(k, val)
	}
	for _, blob := range []string{v.Encode(), v.Encode() + "&hash="} {
		if _, err := VerifyInitData(blob, probeToken, nowish()); err == nil {
			t.Errorf("an unsigned launch verified: %q", blob)
		}
	}
}

// A launch signed a year ago must not still authenticate. Telegram sets no
// expiry, so a blob lifted from a URL or a screenshot would work forever.
func TestProbeAnOldLaunchIsRefused(t *testing.T) {
	f := validFields()
	f["auth_date"] = fmt.Sprintf("%d", nowish().Add(-365*24*time.Hour).Unix())
	if _, err := VerifyInitData(probeSign(t, f), probeToken, nowish()); err == nil {
		t.Fatal("a year-old launch verified")
	}
	// And the boundary holds in the useful direction.
	f["auth_date"] = fmt.Sprintf("%d", nowish().Add(-23*time.Hour).Unix())
	if _, err := VerifyInitData(probeSign(t, f), probeToken, nowish()); err != nil {
		t.Errorf("a launch from 23 hours ago was refused: %v", err)
	}
}

// An empty bot token must refuse rather than verify against an empty key.
// "No key configured" reading as "everything is signed" is the worst version
// of this bug, because it appears the moment somebody forgets to set an
// environment variable.
func TestProbeNoConfiguredTokenRefusesEverything(t *testing.T) {
	blob := probeSign(t, validFields())
	for _, tok := range []string{"", "   "} {
		if _, err := VerifyInitData(blob, tok, nowish()); err == nil {
			t.Errorf("verified a launch with bot token %q", tok)
		}
	}
}

// The handle a store is keyed on must follow the numeric id, never the
// username: usernames are released and re-registered, and a store keyed on one
// hands a stranger the previous owner's pages.
func TestProbeTheHandleFollowsTheIDNotTheUsername(t *testing.T) {
	a := User{ID: 42, Username: "dana"}
	b := User{ID: 42, Username: "someone_else"}
	if a.Handle() != b.Handle() {
		t.Errorf("renaming changed the handle: %s vs %s", a.Handle(), b.Handle())
	}
	c := User{ID: 43, Username: "dana"}
	if a.Handle() == c.Handle() {
		t.Error("two different accounts share a handle")
	}
	if !strings.Contains(a.Handle(), "42") {
		t.Errorf("the handle does not derive from the id: %s", a.Handle())
	}
}

// Duplicate keys must not let an attacker append a second value that a later
// reader picks up while the check string used the first.
func TestProbeADuplicatedKeyDoesNotChangeTheUser(t *testing.T) {
	f := validFields()
	blob := probeSign(t, f)
	doubled := blob + "&user=" + url.QueryEscape(`{"id":1,"username":"admin"}`)

	u, err := VerifyInitData(doubled, probeToken, nowish())
	if err != nil {
		return // Refusing outright is a fine answer.
	}
	if u.ID != 42 {
		t.Fatalf("a duplicated key changed who the launch is from: got id %d, "+
			"want 42", u.ID)
	}
}

// -- the two credentials share a key, so each must refuse the other ----------

// A link and a grant are signed with the same key and the same construction.
// The only thing separating them is what they say they are, which is why
// VerifyGrant checks the purpose field rather than merely reading it.
//
// miniapp_test.go already covers this through the HTTP handler. This calls
// VerifyGrant directly, which is where the check lives: a handler test proves
// the wiring as well as the rule, and if the wiring later changes the rule
// should still have a test of its own.
func TestProbeACapturedLinkCannotBeSubmittedAsAGrant(t *testing.T) {
	link, err := NewLink(User{ID: 42, Username: "dana"}, probeToken, nowish())
	if err != nil {
		t.Fatal(err)
	}

	// The whole link, exactly as it arrived, offered as a form grant. If this
	// were accepted the single-use check would be skipped entirely: a link
	// captured from a URL could be replayed as often as its expiry allowed.
	if u, err := VerifyGrant(link, probeToken, nowish()); err == nil {
		t.Fatalf("a link verified as a grant, so single-use can be bypassed "+
			"by submitting it to the other verifier: got %+v", u)
	}
}

// And the other direction. This one is refused, but not by a purpose check:
// VerifyLink never reads the purpose field, and a grant is turned away because
// it carries no nonce.
//
// That is a real defence and it is load-bearing in a place the comments do not
// point at. Anybody making the nonce optional — to support a link that does
// not need to be single-use, say — would open this path without touching
// anything that looks like authentication. So it is pinned here.
func TestProbeAGrantCannotBeUsedAsAnArrivalLink(t *testing.T) {
	grant, err := NewGrant(User{ID: 42, Username: "dana"}, probeToken, nowish())
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(grant)
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("n") != "" {
		t.Fatal("a grant carries a nonce; this test assumes it does not")
	}

	spender := chat.NewMemory()
	if u, err := VerifyLink(values, probeToken, spender, nowish()); err == nil {
		t.Fatalf("a form grant verified as an arrival link: %+v", u)
	}
}

// Changing the purpose breaks the signature, which is the property that makes
// the check meaningful. A purpose field outside the signature would be a label
// an attacker rewrites.
func TestProbeThePurposeFieldIsSigned(t *testing.T) {
	grant, err := NewGrant(User{ID: 42}, probeToken, nowish())
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(grant)
	if err != nil {
		t.Fatal(err)
	}
	values.Set("p", "link")

	if _, err := VerifyGrant(values.Encode(), probeToken, nowish()); err == nil {
		t.Fatal("rewriting the purpose left the grant verifying, so the " +
			"purpose is not covered by the signature")
	}
}

// The context separation between initData and the link scheme now lives in
// internal/chat, which owns the link scheme and tests each half of it in
// isolation. What remains worth asserting here is the part that is still this
// package's: an initData blob is not a link and is not a grant.
func TestProbeInitDataIsNotALinkOrAGrant(t *testing.T) {
	blob := probeSign(t, validFields())
	values, err := url.ParseQuery(blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLink(values, probeToken, chat.NewMemory(), nowish()); err == nil {
		t.Error("an initData blob verified as a link")
	}
	if _, err := VerifyGrant(blob, probeToken, nowish()); err == nil {
		t.Error("an initData blob verified as a grant")
	}
}
