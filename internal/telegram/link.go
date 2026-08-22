package telegram

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// A signed link: the script-free way to know who is asking.
//
// # Why this exists alongside initData
//
// Telegram hands a Mini App its launch parameters in the URL fragment. A browser
// never sends a fragment to a server, so reading initData server-side means
// running JavaScript on the page to lift it out and post it back. That is one
// script tag, from another origin, on the exact surface where a stranger's
// content gets published — which is the surface where this program's central
// property is worth the most.
//
// So the bot mints the credential instead. It builds a URL whose query string
// carries the user id, an expiry and a nonce, signed with the bot token, and
// sends it as a button. The server reads it from the query string, which it does
// see, and the page needs no script at all.
//
// # Why single-use matters more than length
//
// A link like this ends up in a chat, and a chat is forwarded, screenshotted and
// backed up. The defence is not making the token unguessable — HMAC-SHA256
// already does that — it is making a captured one worthless. Each link carries a
// nonce, the server records the nonce when it spends it, and a second attempt
// with the same nonce is refused.
//
// That means this is the one thing in the package with state, and the state is
// deliberately outside it: Spender is an interface, so the caller decides where
// spent nonces live and how long they are kept. A package that opened its own
// database would be a package you cannot use in a test.
//
// # What a link is not
//
// It is not a session. It authorises one arrival, for a bounded window, once.
// Somebody who needs to publish twice taps the button twice, which is a small
// cost and removes every question about session fixation, logout and expiry
// drift from a surface that would otherwise have to answer them.

// LinkLifetime is how long a minted link works for.
//
// Short on purpose. The link is tapped seconds after the bot sends it in the
// overwhelming majority of cases, and every minute beyond that is a minute a
// forwarded message stays live.
const LinkLifetime = 15 * time.Minute

// linkVersion prefixes the signed payload.
//
// Present so that a future change to what is signed cannot be replayed against
// a server that understands the old shape. A version in the signed data is the
// cheapest form of that protection; adding one later is not possible, because
// the tokens already in circulation do not have it.
const linkVersion = "q1"

// Spender records which one-time tokens have been used.
//
// An interface rather than a map, because where this lives is the caller's
// decision: a single process can keep it in memory, and anything with more than
// one process needs it somewhere both can see. Getting that wrong is a real
// hole — two replicas with separate memories accept the same link twice — so
// the choice is made visible rather than defaulted.
type Spender interface {
	// Spend records a nonce and reports whether it was unused. It must be
	// atomic: a check followed by a separate write is a race two simultaneous
	// taps of the same link will win.
	Spend(nonce string, expires time.Time) bool
}

// NewLink returns the query string a bot should append to the Mini App URL.
//
// The caller joins it to whatever base URL the Mini App is served at, which this
// package deliberately does not know: a package that built absolute URLs would
// need to be told its own public name, and a server that guesses its own name
// from a request header is how a link ends up pointing somewhere else.
func NewLink(user User, botToken string, now time.Time) (string, error) {
	if strings.TrimSpace(botToken) == "" {
		return "", fmt.Errorf("no bot token, so nothing can be signed")
	}
	if user.ID <= 0 {
		return "", fmt.Errorf("a link needs a user to be for")
	}
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}
	expires := now.Add(LinkLifetime).Unix()

	values := url.Values{}
	values.Set("v", linkVersion)
	values.Set("u", strconv.FormatInt(user.ID, 10))
	values.Set("e", strconv.FormatInt(expires, 10))
	values.Set("n", nonce)
	if user.Username != "" {
		values.Set("h", user.Username)
	}
	values.Set("s", sign(values, botToken))
	return values.Encode(), nil
}

// VerifyLink checks a link's query string and spends its nonce.
//
// The order matters and is the reverse of what reads naturally: the signature is
// checked before the nonce is spent. Spending first would let anybody with a URL
// burn a legitimate user's token by requesting it with a broken signature.
func VerifyLink(query url.Values, botToken string, spender Spender, now time.Time) (User, error) {
	if strings.TrimSpace(botToken) == "" {
		return User{}, fmt.Errorf(
			"no bot token is configured, so no link can be verified")
	}
	if query.Get("v") != linkVersion {
		return User{}, fmt.Errorf(
			"this link was made by a different version of this program and is " +
				"not accepted. Ask the bot for a new one")
	}
	supplied := query.Get("s")
	if supplied == "" {
		return User{}, fmt.Errorf("this link is not signed")
	}
	if !hmac.Equal([]byte(sign(query, botToken)), []byte(supplied)) {
		return User{}, fmt.Errorf(
			"this link is not signed by this bot. It has been edited, or it " +
				"came from somewhere else")
	}

	seconds, err := strconv.ParseInt(query.Get("e"), 10, 64)
	if err != nil {
		return User{}, fmt.Errorf("this link has no usable expiry")
	}
	expires := time.Unix(seconds, 0)
	if now.After(expires) {
		return User{}, fmt.Errorf(
			"this link expired %s ago. They last %s, because a link in a chat "+
				"is a link that gets forwarded — ask the bot for a new one",
			now.Sub(expires).Round(time.Second), LinkLifetime)
	}

	id, err := strconv.ParseInt(query.Get("u"), 10, 64)
	if err != nil || id <= 0 {
		return User{}, fmt.Errorf("this link names no user")
	}
	nonce := query.Get("n")
	if nonce == "" {
		return User{}, fmt.Errorf("this link carries no nonce, so it cannot be single-use")
	}
	if spender == nil {
		return User{}, fmt.Errorf(
			"no way to record a spent link is configured. Refusing rather " +
				"than accepting a token that could be replayed indefinitely")
	}
	// Spent last, and only once everything else has passed, so a request with a
	// bad signature cannot burn somebody else's link.
	if !spender.Spend(nonce, expires) {
		return User{}, fmt.Errorf(
			"this link has already been used. They work once — tap the button " +
				"again for a new one")
	}

	return User{
		ID: id, Username: query.Get("h"), AuthDate: expires.Add(-LinkLifetime),
	}, nil
}

// sign is the HMAC over everything except the signature itself.
//
// url.Values.Encode sorts by key, so the signed string is canonical without a
// separate sort here — and canonical matters: two orderings of the same data
// producing two valid signatures is how a signature stops meaning one thing.
func sign(values url.Values, botToken string) string {
	signed := url.Values{}
	for key, vs := range values {
		if key == "s" || len(vs) == 0 {
			continue
		}
		signed.Set(key, vs[0])
	}
	secret := mac([]byte("QuilzoTelegramLink"), []byte(botToken))
	return hex.EncodeToString(mac(secret, []byte(signed.Encode())))
}

// newNonce returns 128 bits of randomness, url-safe.
//
// crypto/rand, and the error is returned rather than ignored. A nonce from a
// failed read is a nonce of zeroes, and a predictable nonce defeats the whole
// single-use mechanism — so a machine that cannot produce randomness gets an
// error rather than a token.
func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf(
			"no randomness available, so no single-use token can be minted: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GrantLifetime is how long a form stays submittable after arrival.
//
// The link that authenticated the arrival is single-use and spent by the time
// the form is drawn, so the form needs its own credential. Fifteen minutes is
// long enough to write a paragraph and short enough that a page left open on a
// shared device stops being a way to publish.
const GrantLifetime = 15 * time.Minute

// NewGrant returns a hidden-field value authorising this user to submit a form.
//
// # Why this is not the link
//
// The link is single-use, and it is used by the act of arriving. Reusing it for
// the submission would mean either accepting it twice — which is not single-use
// — or spending it on the POST and leaving the GET unauthenticated, which is
// worse. So arrival mints a grant: same key, same construction, bounded in
// time, and multi-use within its window because a form somebody mistypes has to
// be submittable twice.
//
// # Why it is not a cookie
//
// A Mini App runs in a webview inside somebody else's client, and third-party
// cookie behaviour there is not something this program should be relying on. A
// hidden field travels with the form that needs it, is scoped to that form by
// construction, and needs no storage on either side.
func NewGrant(user User, botToken string, now time.Time) (string, error) {
	if strings.TrimSpace(botToken) == "" {
		return "", fmt.Errorf("no bot token, so nothing can be signed")
	}
	if user.ID <= 0 {
		return "", fmt.Errorf("a grant needs a user to be for")
	}
	values := url.Values{}
	values.Set("v", linkVersion)
	values.Set("p", "form")
	values.Set("u", strconv.FormatInt(user.ID, 10))
	values.Set("e", strconv.FormatInt(now.Add(GrantLifetime).Unix(), 10))
	if user.Username != "" {
		values.Set("h", user.Username)
	}
	values.Set("s", sign(values, botToken))
	return values.Encode(), nil
}

// VerifyGrant checks a form submission's grant.
//
// The purpose field is checked, not merely present. Without it a link and a
// grant are the same bytes under the same key, so a captured link could be
// submitted as a grant and skip the single-use check entirely — which is the
// kind of hole that comes from two credentials sharing a signing scheme and not
// saying which they are.
func VerifyGrant(encoded, botToken string, now time.Time) (User, error) {
	if strings.TrimSpace(botToken) == "" {
		return User{}, fmt.Errorf("no bot token is configured, so no grant can be verified")
	}
	values, err := url.ParseQuery(encoded)
	if err != nil {
		return User{}, fmt.Errorf("this form is not readable: %w", err)
	}
	if values.Get("v") != linkVersion {
		return User{}, fmt.Errorf("this form was made by a different version of this program")
	}
	if values.Get("p") != "form" {
		return User{}, fmt.Errorf(
			"this is not a form grant. A link and a grant are signed the same " +
				"way, so which one it is has to be stated and checked, or a " +
				"captured link could be submitted as a grant and skip being " +
				"single-use")
	}
	supplied := values.Get("s")
	if supplied == "" || !hmac.Equal([]byte(sign(values, botToken)), []byte(supplied)) {
		return User{}, fmt.Errorf("this form was not issued by this bot")
	}
	seconds, err := strconv.ParseInt(values.Get("e"), 10, 64)
	if err != nil {
		return User{}, fmt.Errorf("this form has no usable expiry")
	}
	if now.After(time.Unix(seconds, 0)) {
		return User{}, fmt.Errorf(
			"this form expired. It lasts %s from arriving — open the Mini App "+
				"again and your draft is still here", GrantLifetime)
	}
	id, err := strconv.ParseInt(values.Get("u"), 10, 64)
	if err != nil || id <= 0 {
		return User{}, fmt.Errorf("this form names no user")
	}
	return User{ID: id, Username: values.Get("h")}, nil
}
