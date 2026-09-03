package telegram

import (
	"net/url"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
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

// # Where the mechanism actually lives now
//
// In internal/chat, along with everything else a messenger integration needs
// that is not about the messenger. What remains here is the Telegram-shaped
// signature over it: the same four calls, taking a telegram.User and a bot
// token, so the six hundred lines of Mini App and editor above did not have to
// change to gain a second platform.
//
// Delegating rather than duplicating is the whole point. Two implementations of
// a credential scheme is two things to keep true, and the second one to be
// changed is the one that quietly stops matching.
//
// One consequence worth stating: the signing context changed when this moved,
// so a link minted by an older build no longer verifies. It fails closed — the
// signature simply does not match — which is the right direction for a
// credential to break in, and no link outlives its ten-minute expiry anyway.

// LinkLifetime is how long an arrival link is good for.
const LinkLifetime = chat.LinkLifetime

// GrantLifetime is how long a form stays submittable after arrival.
const GrantLifetime = chat.GrantLifetime

// Spender records which one-time tokens have been used.
//
// The shared interface, so a deployment can hand the same store to every
// platform it runs rather than one per messenger.
type Spender = chat.Spender

// account maps a Telegram user onto the shared identity.
//
// The platform travels with it, which is what stops a Telegram credential
// verifying at another messenger even when an operator has configured the same
// secret for both.
func (u User) account() chat.Account {
	return chat.Account{
		Platform:  chat.Telegram,
		ID:        u.ID,
		Username:  u.Username,
		FirstName: u.FirstName,
		At:        u.AuthDate,
	}
}

func fromAccount(a chat.Account) User {
	return User{ID: a.ID, Username: a.Username, FirstName: a.FirstName,
		AuthDate: a.At}
}

// NewLink returns the query string a bot should append to the Mini App URL.
//
// The caller joins it to whatever base URL the Mini App is served at, which
// this package deliberately does not know: a package that built absolute URLs
// would need to be told its own public name, and a server that guesses its own
// name from a request header is how a link ends up pointing somewhere else.
func NewLink(user User, botToken string, now time.Time) (string, error) {
	return chat.NewLink(user.account(), botToken, now)
}

// VerifyLink checks a link's query string and spends its nonce.
func VerifyLink(query url.Values, botToken string, spender Spender,
	now time.Time) (User, error) {

	a, err := chat.VerifyLink(query, botToken, chat.Telegram, spender, now)
	if err != nil {
		return User{}, err
	}
	return fromAccount(a), nil
}

// NewGrant returns a hidden-field value authorising this user to submit a form.
func NewGrant(user User, botToken string, now time.Time) (string, error) {
	return chat.NewGrant(user.account(), botToken, now)
}

// VerifyGrant checks a form submission's grant.
func VerifyGrant(encoded, botToken string, now time.Time) (User, error) {
	a, err := chat.VerifyGrant(encoded, botToken, chat.Telegram, now)
	if err != nil {
		return User{}, err
	}
	return fromAccount(a), nil
}
