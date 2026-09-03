package discord_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
	"github.com/quilzo/quilzo/internal/discord"
)

func at() time.Time { return time.Unix(1787000000, 0) }

// keys returns a deterministic Ed25519 pair, so a failure is reproducible.
func keys(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

const guildBody = `{"type":2,"guild_id":"G1","data":{"name":"publish"},` +
	`"member":{"user":{"id":"80351110224678912","username":"dana",` +
	`"global_name":"Dana"}}}`

const dmBody = `{"type":2,"data":{"name":"publish"},` +
	`"user":{"id":"80351110224678912","username":"dana"}}`

// signed builds a request the way Discord would.
//
// Written out rather than calling the package's own helper: a test that signs
// with the function it is testing proves only that the function agrees with
// itself, and this is the one check between a Discord app and anyone who can
// reach the URL.
func signed(t *testing.T, priv ed25519.PrivateKey, body string, stamp int64) *http.Request {
	t.Helper()
	ts := fmt.Sprintf("%d", stamp)
	sig := ed25519.Sign(priv, append([]byte(ts), body...))

	r := httptest.NewRequest("POST", "/discord/interactions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Signature-Timestamp", ts)
	r.Header.Set("X-Signature-Ed25519", hex.EncodeToString(sig))
	return r
}

// The control. Without it every refusal below proves only that Verify refuses.
func TestAGenuineInteractionIsAccepted(t *testing.T) {
	priv, pub := keys(t)
	got, err := discord.Verify(signed(t, priv, guildBody, at().Unix()), pub, at())
	if err != nil {
		t.Fatalf("a correctly signed interaction was refused: %v", err)
	}
	if got.Name != "publish" {
		t.Errorf("command is %q, want publish", got.Name)
	}
	if got.Account.Platform != chat.Discord {
		t.Errorf("platform is %q", got.Account.Platform)
	}
	if got.Account.Username != "dana" {
		t.Errorf("username is %q", got.Account.Username)
	}
	if got.GuildID != "G1" {
		t.Errorf("guild is %q", got.GuildID)
	}
}

// A direct message carries the user at the top level rather than under member.
// An integration that only worked in servers would fail in a DM with "names no
// user", which reads as a bug in Discord rather than a gap here.
func TestADirectMessageNamesItsUserToo(t *testing.T) {
	priv, pub := keys(t)
	got, err := discord.Verify(signed(t, priv, dmBody, at().Unix()), pub, at())
	if err != nil {
		t.Fatalf("a direct message was refused: %v", err)
	}
	if got.Account.Username != "dana" {
		t.Fatalf("no user was found in a direct message: %+v", got.Account)
	}

	// And it is the same person as in a guild, or their pages would split.
	inGuild, err := discord.Verify(signed(t, priv, guildBody, at().Unix()), pub, at())
	if err != nil {
		t.Fatal(err)
	}
	if got.Account.Handle() != inGuild.Account.Handle() {
		t.Errorf("the same person got two handles: %s in a DM, %s in a guild",
			got.Account.Handle(), inGuild.Account.Handle())
	}
}

// The reachability check Discord sends when the endpoint URL is saved. It names
// no user, and refusing it means the endpoint is silently rejected and no
// interaction ever arrives — a failure that looks like nothing happening.
func TestThePingIsAcceptedEvenThoughItNamesNoUser(t *testing.T) {
	priv, pub := keys(t)
	got, err := discord.Verify(signed(t, priv, `{"type":1}`, at().Unix()), pub, at())
	if err != nil {
		t.Fatalf("the reachability ping was refused: %v", err)
	}
	if !got.IsPing() {
		t.Errorf("type %d was not recognised as a ping", got.Type)
	}
}

// A ping must still be signed. Accepting an unsigned one would let anybody
// confirm the endpoint, and more importantly is the shape of a check that
// treats one message type as exempt.
func TestAnUnsignedPingIsStillRefused(t *testing.T) {
	priv, pub := keys(t)
	r := signed(t, priv, `{"type":1}`, at().Unix())
	r.Header.Set("X-Signature-Ed25519", strings.Repeat("00", ed25519.SignatureSize))
	if _, err := discord.Verify(r, pub, at()); err == nil {
		t.Fatal("an unsigned ping was accepted")
	}
}

func TestATamperedBodyIsRefused(t *testing.T) {
	priv, pub := keys(t)
	r := signed(t, priv, guildBody, at().Unix())
	r.Body = httptest.NewRequest("POST", "/", strings.NewReader(
		strings.Replace(guildBody, "publish", "wiretap", 1))).Body

	if got, err := discord.Verify(r, pub, at()); err == nil {
		t.Fatalf("a body changed after signing verified: %+v", got)
	}
}

// Another application's key must not verify here.
func TestAnotherApplicationsSignatureIsRefused(t *testing.T) {
	priv, _ := keys(t)
	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = byte(200 - i)
	}
	otherPub := hex.EncodeToString(
		ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey))

	if _, err := discord.Verify(signed(t, priv, guildBody, at().Unix()),
		otherPub, at()); err == nil {
		t.Fatal("an interaction signed by another application verified")
	}
}

// Discord sets no expiry, so a captured body would authenticate forever.
func TestAnOldInteractionIsRefused(t *testing.T) {
	priv, pub := keys(t)
	old := at().Add(-10 * time.Minute)
	if _, err := discord.Verify(signed(t, priv, guildBody, old.Unix()), pub, at()); err == nil {
		t.Fatal("a ten-minute-old interaction verified")
	}
	recent := at().Add(-4 * time.Minute)
	if _, err := discord.Verify(signed(t, priv, guildBody, recent.Unix()), pub, at()); err != nil {
		t.Errorf("a four-minute-old interaction was refused: %v", err)
	}
}

// Re-dating a captured interaction must break the signature, because the
// timestamp is part of what was signed.
func TestTheTimestampCannotBeMovedToDefeatTheAgeCheck(t *testing.T) {
	priv, pub := keys(t)
	old := at().Add(-10 * time.Minute)
	r := signed(t, priv, guildBody, old.Unix())
	r.Header.Set("X-Signature-Timestamp", fmt.Sprintf("%d", at().Unix()))

	if _, err := discord.Verify(r, pub, at()); err == nil {
		t.Fatal("re-dating a captured interaction let it through")
	}
}

// No key configured must refuse everything. "Nothing configured" reading as
// "everything is signed" appears the moment somebody forgets a variable.
func TestNoConfiguredKeyRefusesEverything(t *testing.T) {
	priv, _ := keys(t)
	for _, k := range []string{"", "   ", "not-hex", "aabb"} {
		if _, err := discord.Verify(signed(t, priv, guildBody, at().Unix()),
			k, at()); err == nil {
			t.Errorf("verified with public key %q", k)
		}
	}
}

// Derived ids must be positive and stable, because chat.Account refuses a
// non-positive one and a failure depending on which user arrived is the worst
// kind. Discord snowflakes are 64-bit, so they cannot be parsed into the
// positive int64 space intact.
func TestDerivedIDsArePositiveAndStable(t *testing.T) {
	priv, pub := keys(t)
	seen := map[int64]string{}
	for i := 0; i < 400; i++ {
		id := fmt.Sprintf("%d", 18446744073709551615-uint64(i))
		body := strings.Replace(dmBody, "80351110224678912", id, 1)
		got, err := discord.Verify(signed(t, priv, body, at().Unix()), pub, at())
		if err != nil {
			t.Fatalf("snowflake %s: %v", id, err)
		}
		if got.Account.ID <= 0 {
			t.Fatalf("snowflake %s derived a non-positive id: %d", id, got.Account.ID)
		}
		if other, clash := seen[got.Account.ID]; clash {
			t.Fatalf("two snowflakes derived id %d: %s and %s",
				got.Account.ID, other, id)
		}
		seen[got.Account.ID] = id
	}
	if len(seen) != 400 {
		t.Fatalf("checked %d ids, expected 400", len(seen))
	}
}

func TestAnInteractionWithNoUserIsRefused(t *testing.T) {
	priv, pub := keys(t)
	body := `{"type":2,"data":{"name":"publish"}}`
	if _, err := discord.Verify(signed(t, priv, body, at().Unix()), pub, at()); err == nil {
		t.Fatal("an interaction naming no user verified")
	}
}

func TestAnOversizedBodyIsRefusedForBeingOversized(t *testing.T) {
	priv, pub := keys(t)
	huge := `{"type":2,"pad":"` + strings.Repeat("x", discord.MaxBody+10) + `"}`
	_, err := discord.Verify(signed(t, priv, huge, at().Unix()), pub, at())
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

// A Discord account and a Slack account with the same derived number are two
// people. This is the property the shared layer provides and it is worth
// checking from a platform rather than only inside chat.
func TestADiscordHandleIsNotASlackHandle(t *testing.T) {
	priv, pub := keys(t)
	got, err := discord.Verify(signed(t, priv, dmBody, at().Unix()), pub, at())
	if err != nil {
		t.Fatal(err)
	}
	same := chat.Account{Platform: chat.Slack, ID: got.Account.ID}
	if got.Account.Handle() == same.Handle() {
		t.Fatalf("the same id on Discord and Slack produced one handle: %s",
			got.Account.Handle())
	}
}
