// Package chat is the part of a messaging integration that is not about any
// one messenger.
//
// # Why this exists
//
// The Telegram integration is about five thousand lines, and most of them are
// not about Telegram. Every chat platform poses the same three problems:
//
//	prove the request came from the platform
//	map a platform identity to a handle that survives a rename
//	turn a message into a content operation, through the same policy gate
//
// Only the first differs. So a platform is a verifier and a handle rule, and
// everything after that point is shared — which is what this package holds.
//
// Written by extraction rather than up front. The shape below is what the
// Telegram integration turned out to need after it worked, and a second
// platform is what proves an abstraction rather than what motivates one.
//
// # The risk this design introduces, and closes
//
// One messenger has one signing key and one kind of credential. Several
// messengers have several, and the moment two of them share a construction,
// a credential minted for one can be replayed at the other — a confused
// deputy across platforms rather than within one.
//
// So the platform is inside the signing context. A link minted for Telegram
// does not verify as a Slack link even when the same secret is configured for
// both, because the derived key differs. That is not a hypothetical: an
// operator who reuses a secret across two integrations is doing the obvious
// wrong thing, and the design should survive it.
//
// # What that separation does not buy, said plainly
//
// The signing secret is the platform's own — the bot token for Telegram, the
// signing secret for Slack. Both are values the platform itself knows, so the
// platform can mint a credential for any of its own users.
//
// That is not a hole so much as the shape of the trust already being extended.
// The whole integration rests on believing the platform when it says who is
// asking; a messenger willing to lie about that does not need to forge a link,
// because it can simply assert a different user id in the request. Minting a
// link adds no capability it did not already have.
//
// The consequence worth knowing is a smaller one: because the key is the
// platform secret, anybody who obtains that secret can mint links as well as
// forge inbound requests. Deriving from a separate, Quilzo-owned key would
// contain the second half of that — and would add a secret to manage for a
// containment gain that only applies in the window between a leak and a
// rotation. It is written down here rather than decided quietly either way.
package chat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Platform names a messenger, and is part of every signature this package
// makes.
//
// A string rather than an enum so an integration can be added without editing
// this file — but a *typed* string, because it lands in a key derivation and a
// bare string parameter there is an argument somebody eventually passes in the
// wrong order.
type Platform string

const (
	Telegram Platform = "telegram"
	Slack    Platform = "slack"
	Discord  Platform = "discord"
)

// Valid reports whether a platform name can be part of a signing context and
// of a handle.
//
// Three rules, and the third is the one that is not obvious.
//
// Empty is refused rather than defaulted. A credential signed under an empty
// platform is a credential every platform would accept, which is exactly the
// cross-replay this design exists to prevent.
//
// The context separator is refused, because the signing context is built by
// concatenation and a name containing "/" could make two platforms derive one
// key.
//
// # And a name may not end in a digit
//
// Handle() is the platform followed by the decimal id, with nothing between
// them, and that is ambiguous the moment a name ends in a digit:
//
//	platform "tele"  id 4212  ->  tele4212
//	platform "tele4" id  212  ->  tele4212
//
// Two accounts, one handle, one set of pages — so one person would be editing
// another's. Not reachable with the names declared above, which is exactly why
// it is worth refusing now: it appears when somebody adds a platform, and the
// symptom is content quietly belonging to the wrong person rather than an
// error anybody sees.
//
// A separator between the two would also fix it, and is not used because a
// handle is a content path and keeping it alphanumeric avoids a second
// question about what a path may contain. With no trailing digit the split is
// unambiguous: the id is the trailing run of digits and the platform is the
// rest.
func (p Platform) Valid() bool {
	name := string(p)
	if strings.TrimSpace(name) == "" {
		return false
	}
	if strings.ContainsAny(name, " \t\n:/") {
		return false
	}
	if last := name[len(name)-1]; last >= '0' && last <= '9' {
		return false
	}
	return true
}

// Account is who is asking, on whichever platform they came from.
//
// The numeric id is the identity, never the username. A username can be
// released and taken by somebody else, so a store keyed on one hands a
// stranger the previous owner's pages the day they rename. The id does not
// move.
type Account struct {
	Platform Platform
	// ID is the platform's own numeric identifier for this person.
	ID int64
	// Username is what they chose to be called, where the platform has one.
	Username string
	// FirstName is a display name, where the platform gives one.
	FirstName string
	// At is when the platform vouched for this identity.
	At time.Time
}

// Handle is the name this account's pages live under.
//
// Prefixed by platform, so two people with the same numeric id on different
// messengers are two accounts. Without the prefix they would be one, and the
// second one to arrive would inherit the first one's pages.
//
// The prefix is unambiguous because a platform name may not end in a digit —
// see Platform.Valid, which is where that rule and its reason live.
func (a Account) Handle() string {
	return string(a.Platform) + strconv.FormatInt(a.ID, 10)
}

// Label is how to address this person on a screen, preferring what they chose.
func (a Account) Label() string {
	switch {
	case a.Username != "":
		return "@" + a.Username
	case a.FirstName != "":
		return a.FirstName
	default:
		return a.Handle()
	}
}

// Valid reports whether this account can be issued a credential.
func (a Account) Valid() error {
	if !a.Platform.Valid() {
		return fmt.Errorf("%q is not a usable platform name", a.Platform)
	}
	if a.ID <= 0 {
		return fmt.Errorf("an account needs a platform id")
	}
	return nil
}

// -- credentials -------------------------------------------------------------

// LinkLifetime is how long an arrival link is good for.
const LinkLifetime = 10 * time.Minute

// GrantLifetime is how long a form stays submittable after arrival.
const GrantLifetime = 15 * time.Minute

// version is signed into every credential.
//
// Present so that a future change to what is signed cannot be replayed against
// a server that understands the old shape. Adding one later is not possible,
// because the credentials already in circulation would not have it.
const version = "q1"

// Purpose separates the two credentials, which are otherwise the same bytes
// under the same key.
type Purpose string

const (
	// Arrival is single-use: it is spent by the act of opening the page.
	Arrival Purpose = "link"
	// Form is multi-use within its window, because a form somebody mistypes
	// has to be submittable twice.
	Form Purpose = "form"
)

// Spender records which one-time tokens have been used.
//
// An interface rather than a map, because where this lives is the caller's
// decision: a single process can keep it in memory, and anything with more
// than one process needs it somewhere both can see. Getting that wrong is a
// real hole — two replicas with separate memories accept the same link twice —
// so the choice is made visible rather than defaulted.
type Spender interface {
	// Spend records a nonce and reports whether it was unused. It must be
	// atomic: a check followed by a separate write is a race two simultaneous
	// taps of the same link will win.
	Spend(nonce string, expires time.Time) bool
}

// NewLink returns the query string to append to the app URL for this account.
//
// The caller joins it to whatever base URL the app is served at, which this
// package deliberately does not know: a package that built absolute URLs would
// need to be told its own public name, and a server that guesses its own name
// from a request header is how a link ends up pointing somewhere else.
func NewLink(a Account, secret string, now time.Time) (string, error) {
	return mint(a, secret, Arrival, LinkLifetime, now)
}

// NewGrant returns a hidden-field value authorising this account to submit a
// form.
//
// The arrival link is single-use and is spent by arriving, so the form needs
// its own credential. Reusing the link would mean either accepting it twice —
// which is not single-use — or spending it on the POST and leaving the GET
// unauthenticated, which is worse.
func NewGrant(a Account, secret string, now time.Time) (string, error) {
	return mint(a, secret, Form, GrantLifetime, now)
}

func mint(a Account, secret string, p Purpose, life time.Duration,
	now time.Time) (string, error) {

	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("no signing secret, so nothing can be signed")
	}
	if err := a.Valid(); err != nil {
		return "", err
	}

	values := url.Values{}
	values.Set("v", version)
	values.Set("p", string(p))
	values.Set("m", string(a.Platform))
	values.Set("u", strconv.FormatInt(a.ID, 10))
	values.Set("e", strconv.FormatInt(now.Add(life).Unix(), 10))
	if a.Username != "" {
		values.Set("h", a.Username)
	}
	// Only the single-use credential carries a nonce. A grant is multi-use
	// within its window on purpose, and giving it a nonce nothing spends would
	// suggest a protection it does not have.
	if p == Arrival {
		nonce, err := newNonce()
		if err != nil {
			return "", err
		}
		values.Set("n", nonce)
	}
	values.Set("s", sign(values, secret, a.Platform))
	return values.Encode(), nil
}

// VerifyLink checks an arrival link and spends its nonce.
//
// The order matters and is the reverse of what reads naturally: the signature
// is checked before the nonce is spent. Spending first would let anybody with
// a URL burn a legitimate person's token by requesting it with a broken
// signature.
func VerifyLink(query url.Values, secret string, platform Platform,
	spender Spender, now time.Time) (Account, error) {

	a, err := check(query, secret, platform, Arrival, now)
	if err != nil {
		return Account{}, err
	}
	nonce := query.Get("n")
	if nonce == "" {
		return Account{}, fmt.Errorf(
			"this link carries no nonce, so it cannot be single-use")
	}
	if spender == nil {
		return Account{}, fmt.Errorf(
			"no spender is configured, so single-use cannot be enforced. " +
				"Refusing rather than accepting a token that could be " +
				"replayed indefinitely")
	}
	expires, _ := strconv.ParseInt(query.Get("e"), 10, 64)
	if !spender.Spend(nonce, time.Unix(expires, 0)) {
		return Account{}, fmt.Errorf(
			"this link has already been used. They are single-use on purpose " +
				"— ask for a new one")
	}
	return a, nil
}

// VerifyGrant checks a form submission's grant.
func VerifyGrant(encoded, secret string, platform Platform,
	now time.Time) (Account, error) {

	values, err := url.ParseQuery(encoded)
	if err != nil {
		return Account{}, fmt.Errorf("this form is not readable: %w", err)
	}
	return check(values, secret, platform, Form, now)
}

// check is the shared verification, and the purpose is checked rather than
// merely read.
//
// Without it a link and a grant are the same bytes under the same key, so a
// captured link could be submitted as a grant and skip the single-use check
// entirely — the kind of hole that comes from two credentials sharing a
// signing scheme and not saying which they are.
func check(values url.Values, secret string, platform Platform, want Purpose,
	now time.Time) (Account, error) {

	if strings.TrimSpace(secret) == "" {
		return Account{}, fmt.Errorf(
			"no signing secret is configured, so nothing can be verified")
	}
	if !platform.Valid() {
		return Account{}, fmt.Errorf(
			"no platform given, so the signing context is undefined and any " +
				"platform's credential would verify")
	}
	if values.Get("v") != version {
		return Account{}, fmt.Errorf(
			"this was made by a different version of this program. Ask for a " +
				"new link")
	}
	if got := Purpose(values.Get("p")); got != want {
		return Account{}, fmt.Errorf(
			"this is a %q credential and a %q one was expected. They are "+
				"signed the same way, so which one it is has to be stated and "+
				"checked", got, want)
	}
	// The platform is checked as data as well as being in the key. The key
	// alone would refuse a foreign credential with "not signed by this bot",
	// which is true and unhelpful; this says what actually happened.
	if got := Platform(values.Get("m")); got != platform {
		return Account{}, fmt.Errorf(
			"this credential is for %q and this is %q", got, platform)
	}

	supplied := values.Get("s")
	if supplied == "" {
		return Account{}, fmt.Errorf("this is not signed")
	}
	if !hmac.Equal([]byte(sign(values, secret, platform)), []byte(supplied)) {
		return Account{}, fmt.Errorf(
			"this was not issued here. Either it came from somewhere else, or " +
				"the signing secret does not match the one that minted it")
	}

	seconds, err := strconv.ParseInt(values.Get("e"), 10, 64)
	if err != nil {
		return Account{}, fmt.Errorf("this has no usable expiry")
	}
	if now.After(time.Unix(seconds, 0)) {
		return Account{}, fmt.Errorf(
			"this expired. Open the app again and your draft is still here")
	}

	id, err := strconv.ParseInt(values.Get("u"), 10, 64)
	if err != nil || id <= 0 {
		return Account{}, fmt.Errorf("this names no account")
	}
	return Account{
		Platform: platform, ID: id, Username: values.Get("h"),
		At: now,
	}, nil
}

// sign covers every field except the signature itself.
//
// The platform is in the key derivation as well as in the signed data. Either
// alone would be enough to separate two messengers; both means the separation
// survives somebody adding a field, or a future version dropping the "m" value
// from what is checked.
func sign(values url.Values, secret string, platform Platform) string {
	signed := url.Values{}
	for key, vs := range values {
		if key == "s" || len(vs) == 0 {
			continue
		}
		signed.Set(key, vs[0])
	}
	context := "QuilzoChat/" + version + "/" + string(platform)
	return hex.EncodeToString(
		mac(mac([]byte(context), []byte(secret)), []byte(signed.Encode())))
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
			"no randomness available, so no single-use token can be minted: %w",
			err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
