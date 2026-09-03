// Package slack accepts a request from Slack and proves it came from Slack.
//
// # What this is, and what it deliberately is not
//
// This is a verifier and a handle rule. Everything after the identity is
// established — the credentials, the draft handling, the policy gate — lives in
// internal/chat and is shared with every other messenger, because none of it is
// about Slack.
//
// That split is the point of the package being this short. The Telegram
// integration is about five thousand lines and most of them were never about
// Telegram; this one is the part that genuinely is.
//
// # Why Slack fits an interface that serves no JavaScript
//
// A slash command arrives as an ordinary form POST and is answered with JSON
// the server writes. Slack's interactive surfaces — modals, block actions — are
// also JSON returned by a server, not code a client runs. So the whole
// integration is request in, response out, with nothing executing anywhere near
// a browser.
//
// # The signature, and the two things that decide whether it works
//
// Slack signs with HMAC-SHA256 over a base string of "v0:timestamp:body",
// keyed on the signing secret, and sends the hex digest prefixed "v0=".
//
// The timestamp is inside the signed string, which is what makes the staleness
// check meaningful: a captured request replayed tomorrow carries yesterday's
// timestamp, and changing it invalidates the signature. Slack's own guidance is
// to refuse anything more than five minutes old, and that is enforced here
// rather than treated as advice.
//
// The body must be the raw bytes. Parsing the form first and re-encoding it
// produces a different string — parameter order and escaping both move — and
// the signature then fails for requests that were perfectly genuine, which is
// the bug people spend an afternoon on.
package slack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
)

// MaxAge is how old a signed request may be.
//
// Five minutes, which is Slack's own recommendation. Without it a request
// captured from a proxy log authenticates forever, because the signature is
// over bytes that do not change.
const MaxAge = 5 * time.Minute

// MaxBody bounds what will be read before verifying.
//
// The signature covers the body, so the body has to be read before anything is
// known about the sender — which makes this the one place an unauthenticated
// caller decides how much memory to use. A slash command is a few hundred
// bytes; a megabyte is generous and finite.
const MaxBody = 1 << 20

// Request is a verified inbound request from Slack.
type Request struct {
	// Form is the parsed body, safe to read because the signature covered it.
	Form url.Values
	// Account is who Slack says is asking.
	Account chat.Account
	// TeamID is the workspace, kept because one bot serves several and a
	// person's id is only unique within one.
	TeamID string
}

// Command is the slash command, without its leading slash.
func (r Request) Command() string {
	return strings.TrimPrefix(r.Form.Get("command"), "/")
}

// Text is everything the person typed after the command.
func (r Request) Text() string { return strings.TrimSpace(r.Form.Get("text")) }

// Verify checks a request came from Slack and returns who is asking.
//
// The body is returned to the caller's io.Reader contract by being read here
// once: a handler that reads it again gets nothing, so this is the only reader
// and the parsed result is handed back rather than the stream.
func Verify(r *http.Request, signingSecret string, now time.Time) (Request, error) {
	if strings.TrimSpace(signingSecret) == "" {
		return Request{}, fmt.Errorf(
			"no Slack signing secret is configured, so no request can be " +
				"verified. Refusing rather than accepting: a check with no key " +
				"is not a check")
	}

	stamp := r.Header.Get("X-Slack-Request-Timestamp")
	if stamp == "" {
		return Request{}, fmt.Errorf("this request carries no timestamp, so " +
			"its age cannot be checked and it has to be refused")
	}
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return Request{}, fmt.Errorf("the timestamp is not a number: %q", stamp)
	}

	// Age is checked before the signature rather than after. A stale request
	// is refused on a cheap integer comparison, so replaying a captured body
	// does not cost an HMAC each time.
	sent := time.Unix(seconds, 0)
	if age := now.Sub(sent); age > MaxAge {
		return Request{}, fmt.Errorf(
			"this request was signed %s ago and the limit is %s. A captured "+
				"request would otherwise authenticate forever",
			age.Round(time.Second), MaxAge)
	}
	if sent.Sub(now) > time.Minute {
		return Request{}, fmt.Errorf(
			"this request is dated in the future; check the server's clock")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		return Request{}, fmt.Errorf("cannot read the request: %w", err)
	}
	if len(body) > MaxBody {
		return Request{}, fmt.Errorf(
			"this request is larger than %d bytes, which no slash command is",
			MaxBody)
	}

	supplied := r.Header.Get("X-Slack-Signature")
	if supplied == "" {
		return Request{}, fmt.Errorf("this request is not signed")
	}
	// The raw bytes, exactly as they arrived. Parsing and re-encoding produces
	// a different string — parameter order and escaping both move — and the
	// signature then fails for genuine requests.
	expected := signature(signingSecret, stamp, body)
	if !hmac.Equal([]byte(expected), []byte(supplied)) {
		return Request{}, fmt.Errorf(
			"this request is not signed by the configured workspace. Either " +
				"it came from somewhere else, or the signing secret does not " +
				"match the app")
	}

	form, err := url.ParseQuery(string(body))
	if err != nil {
		return Request{}, fmt.Errorf("the body is not a form: %w", err)
	}

	account, err := accountFrom(form)
	if err != nil {
		return Request{}, err
	}
	return Request{Form: form, Account: account, TeamID: form.Get("team_id")}, nil
}

// signature computes the value Slack would have sent.
func signature(secret, stamp string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("v0:" + stamp + ":"))
	h.Write(body)
	return "v0=" + hex.EncodeToString(h.Sum(nil))
}

// accountFrom maps Slack's identity onto the shared one.
//
// # Why the id is converted rather than kept as a string
//
// chat.Account uses a numeric id because a username can be released and taken
// by somebody else, and a store keyed on one hands a stranger the previous
// owner's pages. Slack's user ids are strings — "U024BE7LH" — so they are
// hashed into the numeric space rather than parsed.
//
// A hash rather than a counter, because a counter needs state and this needs
// none. It is not a secret and does not need to be: the id is already public
// within the workspace, and the mapping only has to be stable and collision-
// resistant, which a truncated SHA-256 is.
func accountFrom(form url.Values) (chat.Account, error) {
	id := form.Get("user_id")
	if id == "" {
		return chat.Account{}, fmt.Errorf(
			"this request names no user. A Slack event without a user is not " +
				"something to publish as")
	}
	team := form.Get("team_id")
	if team == "" {
		return chat.Account{}, fmt.Errorf(
			"this request names no workspace, and a user id is only unique " +
				"within one")
	}

	return chat.Account{
		Platform: chat.Slack,
		// The workspace is part of the identity. Two people in two workspaces
		// can hold the same user id, and without the team in the hash they
		// would be one account holding one set of pages.
		ID:       numericID(team + ":" + id),
		Username: form.Get("user_name"),
	}, nil
}

// numericID maps a Slack id onto the positive int64 space, stably.
//
// Seven bytes rather than eight, so the result cannot go negative and needs no
// sign fixing — a negative id would fail chat.Account.Valid and the failure
// would depend on which user happened to arrive.
func numericID(s string) int64 {
	sum := sha256.Sum256([]byte("quilzo/slack/user\x00" + s))
	var n int64
	for _, b := range sum[:7] {
		n = n<<8 | int64(b)
	}
	return n
}
