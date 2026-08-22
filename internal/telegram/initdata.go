// Package telegram authenticates a person arriving from a Telegram chat.
//
// # What this is for
//
// Telegram is building a publishing surface for a billion accounts. This package
// is the part of that which decides *who is asking* — and it exists separately
// from everything else because getting it wrong is the whole risk. A Mini App
// receives its launch parameters from a client this server does not control, so
// the only thing standing between "a Telegram user" and "anyone with a URL" is
// the signature check below.
//
// # Two ways in, and why both
//
// **initData** is Telegram's documented scheme: the client hands the page a
// signed blob describing the user, keyed on the bot token. It is what a Mini App
// running Telegram's SDK produces, and it is implemented here in full because
// anybody running this as a real Mini App needs it verified properly.
//
// **A signed link** is the other way, and it is the one this project prefers.
// Telegram delivers launch parameters in the URL *fragment*, which a browser
// never sends to a server — so reading initData server-side requires JavaScript
// on the page to lift it out of the fragment and post it back. That would mean
// this program's one script-free property ending at exactly the surface where a
// stranger's content gets published. So the bot mints a short-lived, single-use
// token in the query string instead, which the server does see, and the page
// stays script-free.
//
// The security is not weaker for it. Both paths are HMAC-SHA256 keyed on the bot
// token, both are bounded in time, and the link path additionally cannot be
// replayed. What the link path gives up is the extra fields Telegram packs into
// initData — the user's photo, their language — which are conveniences rather
// than credentials.
//
// # What is deliberately absent
//
// No token cache, no session store, no cookie. A link carries its own expiry and
// its own single-use marker; initData carries its own auth_date. Nothing here
// needs to remember anything between requests, which is what keeps this package
// something you can read in one sitting and reason about completely.
package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxInitDataAge is how old a launch may be and still be accepted.
//
// Telegram does not set one, which means an initData blob captured from a URL,
// a screenshot or a shared link authenticates forever. Twenty-four hours is
// long enough for somebody to open a Mini App, get distracted, and come back
// after lunch; it is short enough that a leaked blob stops working the same day.
const MaxInitDataAge = 24 * time.Hour

// User is who Telegram says is asking.
//
// Only the fields that are used. A struct that mirrors every key Telegram sends
// is a struct that invites somebody to trust a field nobody checked — the
// signature covers the whole blob, but "covered by the signature" and "safe to
// put in a page" are different claims, and the second one is decided by what is
// done with the value rather than by where it came from.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	// AuthDate is when Telegram signed this launch.
	AuthDate time.Time `json:"auth_date"`
}

// Handle is the name this user's pages live under.
//
// The numeric id rather than the username, because a username can be released
// and taken by somebody else — so a store keyed on it would hand a stranger the
// previous owner's pages the day they renamed. The id never moves.
func (u User) Handle() string { return "tg" + strconv.FormatInt(u.ID, 10) }

// Label is how to address this person on a screen, preferring what they chose.
func (u User) Label() string {
	switch {
	case u.Username != "":
		return "@" + u.Username
	case u.FirstName != "":
		return u.FirstName
	default:
		return u.Handle()
	}
}

// VerifyInitData checks a Mini App launch and returns who it is from.
//
// The algorithm is Telegram's, implemented exactly:
//
//	secret  = HMAC-SHA256(key: "WebAppData", data: bot token)
//	check   = HMAC-SHA256(key: secret,       data: sorted "k=v" lines)
//	accept if check == the supplied hash
//
// Three details that are easy to get wrong and are the reason this is a package
// rather than twenty lines in a handler:
//
//   - The key and the data are the other way round from what reading the
//     formula quickly suggests. The bot token is the *message* in the first
//     step, not the key.
//   - `hash` and `signature` are excluded from the check string. `hash` because
//     it is the thing being checked; `signature` because it belongs to
//     Telegram's separate third-party Ed25519 scheme and including it makes
//     every launch from a newer client fail.
//   - The comparison is constant-time. A byte-by-byte comparison of a hex
//     digest is a timing oracle that lets somebody find the right hash one
//     character at a time.
func VerifyInitData(initData, botToken string, now time.Time) (User, error) {
	if strings.TrimSpace(botToken) == "" {
		return User{}, fmt.Errorf(
			"no bot token is configured, so no launch can be verified. " +
				"Refusing rather than accepting: a check with no key is not a " +
				"check")
	}
	values, err := url.ParseQuery(initData)
	if err != nil {
		return User{}, fmt.Errorf("this launch is not readable: %w", err)
	}
	supplied := values.Get("hash")
	if supplied == "" {
		return User{}, fmt.Errorf("this launch carries no hash, so it is not signed")
	}

	pairs := make([]string, 0, len(values))
	for key, vs := range values {
		if key == "hash" || key == "signature" {
			continue
		}
		if len(vs) == 0 {
			continue
		}
		pairs = append(pairs, key+"="+vs[0])
	}
	sort.Strings(pairs)

	secret := mac([]byte("WebAppData"), []byte(botToken))
	expected := hex.EncodeToString(mac(secret, []byte(strings.Join(pairs, "\n"))))
	if !hmac.Equal([]byte(expected), []byte(supplied)) {
		return User{}, fmt.Errorf(
			"this launch is not signed by the configured bot. Either it came " +
				"from somewhere else, or the bot token does not match the bot " +
				"the Mini App is attached to")
	}

	seconds, err := strconv.ParseInt(values.Get("auth_date"), 10, 64)
	if err != nil {
		return User{}, fmt.Errorf(
			"this launch has no usable auth_date, so its age cannot be " +
				"checked and it has to be refused")
	}
	signed := time.Unix(seconds, 0)
	if age := now.Sub(signed); age > MaxInitDataAge {
		return User{}, fmt.Errorf(
			"this launch was signed %s ago and the limit is %s. Telegram sets "+
				"no expiry, so this one does: a blob lifted out of a URL "+
				"otherwise authenticates forever",
			age.Round(time.Minute), MaxInitDataAge)
	}
	// A launch signed in the future is a clock problem or a forgery, and both
	// are reasons to stop. A minute of slack covers ordinary drift.
	if signed.Sub(now) > time.Minute {
		return User{}, fmt.Errorf(
			"this launch is dated in the future; check the server's clock")
	}

	user, err := userFrom(values.Get("user"))
	if err != nil {
		return User{}, err
	}
	user.AuthDate = signed
	return user, nil
}

// userFrom reads the user object Telegram packs into initData as JSON.
func userFrom(raw string) (User, error) {
	if strings.TrimSpace(raw) == "" {
		return User{}, fmt.Errorf(
			"this launch names no user. A Mini App opened from a channel or an " +
				"inline query can be unattributed, and there is nobody to " +
				"publish as")
	}
	var u struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
	}
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return User{}, fmt.Errorf("the user in this launch is not readable: %w", err)
	}
	if u.ID <= 0 {
		return User{}, fmt.Errorf("the user in this launch has no id")
	}
	return User{ID: u.ID, Username: u.Username, FirstName: u.FirstName}, nil
}

func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
