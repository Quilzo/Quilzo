// Package discord accepts an interaction from Discord and proves it came from
// Discord.
//
// # What is different here, and what is not
//
// Not much, which is the point. Like the Slack package this is a verifier and a
// handle rule; everything after the identity is established lives in
// internal/chat and is shared. Adding this platform did not change a line of
// the credential scheme, the draft handling or the policy gate.
//
// What is different is the signature. Slack signs with a shared secret and
// HMAC; Discord signs with Ed25519 and gives you a public key. That is a
// better arrangement for the receiving side and it is worth naming why: a
// shared secret has to exist on both machines, so a leak from either end lets
// somebody forge requests in both directions. A public key cannot be used to
// sign anything. Losing it costs nothing.
//
// crypto/ed25519 is in the standard library, so the whole difference between
// this package and the Slack one is which verification call it makes.
//
// # Still no JavaScript
//
// An interaction arrives as an HTTP POST and is answered with JSON the server
// writes. Discord's components — buttons, select menus, modals — are JSON in
// that response, not code a client runs. The same property that made Telegram
// possible holds here for the same reason: this is a server-to-server
// protocol that happens to have a chat client at the far end.
package discord

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
)

// MaxAge is how old a signed interaction may be.
//
// Discord does not specify one, which means a captured interaction body
// authenticates forever: the signature is over bytes that do not change. Five
// minutes matches what Slack recommends for the same problem, and is long
// enough that no legitimate request is near it.
const MaxAge = 5 * time.Minute

// MaxBody bounds what will be read before verifying.
//
// The signature covers the body, so the body has to be read before anything is
// known about the sender. That makes this the one place an unauthenticated
// caller decides how much memory to use.
const MaxBody = 1 << 20

// Interaction types, from Discord's own numbering.
const (
	// Ping is the reachability check Discord sends when an endpoint URL is
	// saved, and it must be answered or the endpoint is rejected.
	Ping = 1
	// Command is a slash command.
	Command = 2
	// Component is a button or select menu.
	Component = 3
	// Submit is a modal submission.
	Submit = 5
)

// Request is a verified inbound interaction.
type Request struct {
	Type    int
	Account chat.Account
	// GuildID is the server, empty in a direct message.
	GuildID string
	// Name is the command name, for a Command interaction.
	Name string
	// Raw is the whole payload, for a caller that needs more than this struct
	// carries. Safe to read because the signature covered it.
	Raw []byte
}

// IsPing reports whether this is the reachability check.
//
// Named rather than left as a magic number at the call site, because the
// handler must answer it and an endpoint that does not is silently rejected by
// Discord with no interaction ever arriving — a failure that looks like
// nothing happening.
func (r Request) IsPing() bool { return r.Type == Ping }

// payload is the part of an interaction this package reads.
//
// Only the fields that are used. A struct mirroring every key Discord sends is
// a struct that invites somebody to trust a field nobody checked.
type payload struct {
	Type    int    `json:"type"`
	GuildID string `json:"guild_id"`
	Data    struct {
		Name string `json:"name"`
	} `json:"data"`
	// A guild interaction carries member.user; a direct message carries user.
	Member struct {
		User *discordUser `json:"user"`
	} `json:"member"`
	User *discordUser `json:"user"`
}

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Global   string `json:"global_name"`
}

// Verify checks an interaction came from Discord and returns who is asking.
//
// publicKey is the application's Ed25519 public key, as Discord shows it: hex.
func Verify(r *http.Request, publicKey string, now time.Time) (Request, error) {
	key, err := parseKey(publicKey)
	if err != nil {
		return Request{}, err
	}

	stamp := r.Header.Get("X-Signature-Timestamp")
	sig := r.Header.Get("X-Signature-Ed25519")
	if stamp == "" || sig == "" {
		return Request{}, fmt.Errorf(
			"this interaction is not signed. Discord sends both " +
				"X-Signature-Ed25519 and X-Signature-Timestamp on every one")
	}

	// Age first, on a cheap comparison, so replaying a captured body does not
	// cost a signature verification each time.
	seconds, err := parseUnix(stamp)
	if err != nil {
		return Request{}, fmt.Errorf("the timestamp is not a number: %q", stamp)
	}
	sent := time.Unix(seconds, 0)
	if age := now.Sub(sent); age > MaxAge {
		return Request{}, fmt.Errorf(
			"this interaction was signed %s ago and the limit is %s. Discord "+
				"sets no expiry, so this one does",
			age.Round(time.Second), MaxAge)
	}
	if sent.Sub(now) > time.Minute {
		return Request{}, fmt.Errorf(
			"this interaction is dated in the future; check the server's clock")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		return Request{}, fmt.Errorf("cannot read the interaction: %w", err)
	}
	if len(body) > MaxBody {
		return Request{}, fmt.Errorf(
			"this interaction is larger than %d bytes, which none is", MaxBody)
	}

	raw, err := hex.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Request{}, fmt.Errorf("the signature is not a %d-byte hex value",
			ed25519.SignatureSize)
	}

	// The timestamp and the raw body, in that order, exactly as they arrived.
	// Parsing the JSON and re-encoding it produces different bytes — key order
	// and whitespace both move — and the signature then fails for interactions
	// that were perfectly genuine.
	signed := append([]byte(stamp), body...)
	if !ed25519.Verify(key, signed, raw) {
		return Request{}, fmt.Errorf(
			"this interaction is not signed by the configured application. " +
				"Either it came from somewhere else, or the public key does " +
				"not match the app")
	}

	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Request{}, fmt.Errorf("the interaction is not readable: %w", err)
	}

	out := Request{Type: p.Type, GuildID: p.GuildID, Name: p.Data.Name, Raw: body}
	if out.IsPing() {
		// A ping names no user, and that is correct rather than a failure.
		// Refusing it here would reject the endpoint at the moment it is saved.
		return out, nil
	}

	account, err := accountFrom(p)
	if err != nil {
		return Request{}, err
	}
	out.Account = account
	return out, nil
}

// parseKey turns Discord's hex public key into one Ed25519 can use.
func parseKey(publicKey string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf(
			"no Discord public key is configured, so no interaction can be " +
				"verified. Refusing rather than accepting: a check with no key " +
				"is not a check")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return nil, fmt.Errorf("the public key is not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"the public key is %d bytes and an Ed25519 key is %d",
			len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// accountFrom maps Discord's identity onto the shared one.
//
// A guild interaction carries the user under member; a direct message carries
// it at the top level. Both are checked, because an integration that worked
// only in servers would fail in a DM with "names no user", which reads as a
// bug in Discord rather than a gap here.
func accountFrom(p payload) (chat.Account, error) {
	u := p.User
	if u == nil && p.Member.User != nil {
		u = p.Member.User
	}
	if u == nil || u.ID == "" {
		return chat.Account{}, fmt.Errorf(
			"this interaction names no user, so there is nobody to publish as")
	}

	name := u.Username
	if u.Global != "" {
		name = u.Global
	}
	return chat.Account{
		Platform: chat.Discord,
		// Discord ids are globally unique snowflakes, so unlike Slack there is
		// no workspace to fold in. They are also numeric strings up to 64 bits,
		// which will not fit the positive int64 space intact — so they are
		// hashed for the same reason Slack's are, rather than parsed and
		// truncated.
		ID:        numericID(u.ID),
		Username:  u.Username,
		FirstName: name,
	}, nil
}

// numericID maps a Discord snowflake onto the positive int64 space, stably.
//
// Seven bytes rather than eight, so the result cannot go negative and needs no
// sign fixing — a negative id would fail chat.Account.Valid and the failure
// would depend on which user happened to arrive.
func numericID(s string) int64 {
	sum := sha256.Sum256([]byte("quilzo/discord/user\x00" + s))
	var n int64
	for _, b := range sum[:7] {
		n = n<<8 | int64(b)
	}
	return n
}

func parseUnix(s string) (int64, error) {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}
