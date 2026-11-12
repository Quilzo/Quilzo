// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package webhook tells other systems that something was published.
//
// # A webhook is an SSRF primitive with a friendly name
//
// The endpoint is a URL somebody configured, and this program makes a request
// to it from inside the network. That is the same shape as importing from a
// URL, so it goes through the same connect-time address check rather than a
// second one written here — one defence, not two that can disagree.
//
// # Signing, and the two mistakes people make
//
// The receiver has to know the request came from here. That means an HMAC over
// the body, and two details decide whether it works:
//
// The signature covers a timestamp as well as the body. Without one, a request
// captured today can be replayed next year and still verifies, because the
// signature is over bytes that have not changed. With one, the receiver rejects
// anything outside a window.
//
// The signature covers them together, in a defined order, with a separator. A
// naive HMAC over timestamp+body lets an attacker move the boundary — the same
// bytes split differently produce the same digest, so a crafted timestamp can
// absorb the start of the body. The construction here is length-prefixed, which
// removes the ambiguity rather than documenting it.
//
// # Delivery is at-least-once and says so
//
// A receiver that is down gets retried, so a receiver that is slow can see a
// delivery twice. Every delivery carries an id that is stable across retries,
// which is what lets a receiver make its own handling idempotent. Pretending
// exactly-once is achievable over HTTP is how integrations end up processing a
// publication twice and nobody knowing why.
//
// The retries are spaced over a few seconds, which is what a receiver being
// restarted needs, and no longer: a delivery that fails every attempt is
// recorded as failed with the deliveries, for somebody to see, rather than
// queued to be sent again later.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	events "github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/fetch"
)

// MaxBody bounds a payload. A webhook says what happened; it does not carry
// content, and a receiver should fetch what it needs.
const MaxBody = 64 << 10

// Tolerance is how far a delivery's timestamp may be from the receiver's clock.
//
// Five minutes: wide enough for ordinary drift between two machines, narrow
// enough that a captured request is useless by the time anybody replays it.
const Tolerance = 5 * time.Minute

// Event is what a receiver is told.
//
// Deliberately thin. Naming what changed rather than shipping it means a
// webhook cannot leak unpublished content to a misconfigured endpoint, and a
// receiver that wants the content fetches it over an authenticated channel.
type Event struct {
	// ID is stable across retries, so a receiver can make its own handling
	// idempotent.
	ID string `json:"id"`
	// Type is what happened: published, rolled-back, scheduled.
	Type string `json:"type"`
	// Commit is what the site is now.
	Commit string `json:"commit"`
	// Pages are the names that changed, not their contents.
	Pages []string `json:"pages,omitempty"`
	// Form is which form was submitted, for a "submitted" event.
	//
	// The name and nothing else. A submission is what a member of the public
	// typed, it has a retention period, and a webhook body is a copy of it
	// leaving this system for one that has never heard of that period — so
	// this says that something arrived and where to read it, exactly as the
	// audit record for the same event does.
	Form string `json:"form,omitempty"`
	// Service is which service was booked, or had a booking cancelled, for
	// a "booked" or "booking-cancelled" event. The service, never when or
	// by whom: who booked is in the admin, behind a sign-in.
	Service string `json:"service,omitempty"`
	// By is who proposed a change, for a "proposed" event.
	By string `json:"by,omitempty"`
	// Machine says a model wrote the content being proposed.
	//
	// The one field that changes what the reader has to do: an AI-authored
	// change needs a person to have read it, and somebody deciding whether to
	// open the review screen should not have to open the review screen to
	// find that out.
	Machine bool   `json:"machine,omitempty"`
	At      string `json:"at"`
	Site    string `json:"site,omitempty"`
}

// EventTypes is everything this program sends, by the names webhooks are
// told events by: the nine they always were, in the same order, taken
// from the event package's one table between the two spellings.
//
// A closed list, because --types took any string and stored it: an endpoint
// asking for "publish" instead of "published" was configured, reported as
// configured, and never fired — a silent subscription to an event that does not
// exist. The same shape as an unchecked crawl-licence term, and the same fix.
var EventTypes = events.WebhookNames()

// KnownType reports whether this program ever sends an event of this type,
// named either way: "published", or "page.published" as an agent's trigger
// and a staff notice name it. Both were always the same event, and each
// surface refused the other's spelling.
func KnownType(t string) bool {
	e, ok := events.Parse(t)
	if !ok {
		return false
	}
	_, sent := events.WebhookName(e)
	return sent
}

// Endpoint is somewhere to send them.
type Endpoint struct {
	URL string `json:"url"`
	// Secret is the HMAC key. Stored hashed nowhere — the receiver needs the
	// same bytes, so this is a shared secret and is what it is. It is kept out
	// of every log by the audit package's forbidden-key check.
	Secret string `json:"secret"`
	// Types filters what this endpoint is told. Empty means everything.
	Types []string `json:"types,omitempty"`
	// Disabled stops delivery without losing the configuration, so turning an
	// endpoint off during an incident does not mean retyping it afterwards.
	Disabled bool   `json:"disabled,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Wants reports whether this endpoint should receive an event type.
//
// The types are kept as they were typed, by either spelling, and an
// endpoint subscribed to "page.published" is told "published" as one
// subscribed to "published" is. A stored name that never was an event
// matches nothing, as it always did.
func (e Endpoint) Wants(t string) bool {
	if e.Disabled {
		return false
	}
	if len(e.Types) == 0 {
		return true
	}
	sent, known := events.Parse(t)
	for _, want := range e.Types {
		if want == t {
			return true
		}
		if w, ok := events.Parse(want); ok && known && w == sent {
			return true
		}
	}
	return false
}

// NewSecret generates a signing key.
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no randomness available: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewID returns a delivery id.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Sign produces the signature header for a body at a time.
//
// The construction is length-prefixed rather than a plain concatenation. With
// `HMAC(secret, timestamp + body)` an attacker can move the boundary between
// the two — a longer timestamp absorbing the first bytes of the body produces
// the same input and therefore the same digest, so a signature valid for one
// pair is valid for another. Prefixing each field with its length removes the
// ambiguity instead of relying on the fields never being attacker-influenced.
func Sign(secret string, at time.Time, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	ts := strconv.FormatInt(at.Unix(), 10)

	writeField(mac, []byte(ts))
	writeField(mac, body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func writeField(w interface{ Write([]byte) (int, error) }, b []byte) {
	var n [8]byte
	l := uint64(len(b))
	for i := range 8 {
		n[7-i] = byte(l >> (8 * i))
	}
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

// Verify checks a signature, which is what a receiver runs.
//
// Exported because a receiver written against this needs the same construction,
// and shipping the verifier is the difference between a documented scheme and
// one everybody implements slightly differently.
func Verify(secret, signature string, at time.Time, body []byte,
	now time.Time) error {

	// The window is checked first and separately. Checking the signature first
	// would mean a replayed request with a valid signature takes the same path
	// as a fresh one until the very end, and the two deserve different
	// answers — one is an old message, the other is a forgery.
	drift := now.Sub(at)
	if drift < 0 {
		drift = -drift
	}
	if drift > Tolerance {
		return fmt.Errorf(
			"this delivery is timestamped %s away from now, past the %s window. "+
				"A captured request replayed later has a signature that still "+
				"verifies; the timestamp is what stops it",
			drift.Round(time.Second), Tolerance)
	}

	want := Sign(secret, at, body)
	// Constant time, because a comparison that returns early leaks how much of
	// the signature was right, and enough of those leak the whole thing.
	if subtle.ConstantTimeCompare([]byte(want), []byte(signature)) != 1 {
		return fmt.Errorf("the signature does not match")
	}
	return nil
}

// Delivery is one attempt to reach an endpoint.
type Delivery struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Type      string `json:"type"`
	Attempt   int    `json:"attempt"`
	Status    int    `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	At        string `json:"at"`
	Succeeded bool   `json:"succeeded"`
}

// Sender delivers events.
type Sender interface {
	Post(url string, body []byte, headers map[string]string) (int, error)
}

// MaxAttempts bounds retries.
//
// Three. A receiver that is down for longer than a few seconds is down, and
// retrying for an hour turns one outage into a queue somebody has to drain.
const MaxAttempts = 3

// retryAfter is how long Send waits before each attempt after the first.
//
// The attempts used to be made back to back, all three within about 10 ms,
// so a receiver restarting for a deploy — down for well under a second —
// answered every one of them with a 503 and the event was lost. One second
// and then four more cover a restart, keep the last attempt within the few
// seconds MaxAttempts gives a receiver, and keep every attempt's timestamp
// far inside Tolerance.
var retryAfter = [MaxAttempts - 1]time.Duration{time.Second, 4 * time.Second}

// Waiter is a Sender that does its own waiting between attempts, which is
// how a test gives Send a clock of its own. Any other Sender is waited for
// with time.Sleep.
type Waiter interface {
	Wait(d time.Duration)
}

// Send delivers one event to one endpoint.
//
// At-least-once, and the id is stable across attempts so a receiver can
// deduplicate. Claiming exactly-once over HTTP is how an integration ends up
// processing a publication twice with nobody knowing why.
func Send(s Sender, e Endpoint, ev Event, now time.Time) []Delivery {
	body, err := json.Marshal(ev)
	if err != nil {
		return []Delivery{{ID: ev.ID, URL: e.URL, Type: ev.Type,
			Error: err.Error(), At: now.UTC().Format(time.RFC3339)}}
	}
	if len(body) > MaxBody {
		return []Delivery{{ID: ev.ID, URL: e.URL, Type: ev.Type,
			Error: "the payload is too large; a webhook names what changed " +
				"rather than carrying it",
			At: now.UTC().Format(time.RFC3339)}}
	}

	var out []Delivery
	var waited time.Duration
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if attempt > 1 {
			d := retryAfter[attempt-2]
			if w, ok := s.(Waiter); ok {
				w.Wait(d)
			} else {
				time.Sleep(d)
			}
			waited += d
		}
		// Signed for when it is sent: a retry carrying the first attempt's
		// timestamp is a few seconds stale before it leaves.
		at := now.Add(waited)
		headers := map[string]string{
			"Content-Type":       "application/json",
			"X-Quilzo-Event":     ev.Type,
			"X-Quilzo-Delivery":  ev.ID,
			"X-Quilzo-Timestamp": strconv.FormatInt(at.Unix(), 10),
			"X-Quilzo-Signature": Sign(e.Secret, at, body),
		}
		status, err := s.Post(e.URL, body, headers)
		d := Delivery{
			ID: ev.ID, URL: e.URL, Type: ev.Type, Attempt: attempt,
			Status: status, At: at.UTC().Format(time.RFC3339),
		}
		if err != nil {
			d.Error = err.Error()
		}
		d.Succeeded = err == nil && status >= 200 && status < 300
		out = append(out, d)
		if d.Succeeded {
			return out
		}
		// A 4xx is the receiver saying the request is wrong, and repeating it
		// will not make it right. Only server errors and transport failures are
		// worth another attempt, and the two 4xx that ask for one later: 408,
		// a receiver that timed out reading the request, and 429, one taking
		// fewer requests for a moment. Both were dropped on the first answer.
		if status >= 400 && status < 500 && status != 408 && status != 429 {
			return out
		}
	}
	return out
}

// Redact removes the secret from an endpoint, for anything that displays one.
func Redact(e Endpoint) Endpoint {
	if e.Secret != "" {
		e.Secret = "(set)"
	}
	return e
}

// SecretHint shows enough of a secret to recognise it and not enough to use it.
func SecretHint(secret string) string {
	if len(secret) < 8 {
		return "(too short)"
	}
	return secret[:4] + strings.Repeat("·", 8)
}

// Check is the one rule an endpoint is registered by, wherever it is
// registered: `quilzo webhook add`, the Integrations screen and a feature's
// webhooks. The address is held to CheckURL and every type to KnownType.
//
// The screen had a rule of its own, that the address began with https://,
// and so stored an address with a password in it, an address inside the
// network and a subscription to an event that is never sent, each of which
// the command line refused. Each was shown as added, with a new key, and
// nothing could ever be delivered to it.
func Check(raw string, types []string) error {
	if err := CheckURL(raw); err != nil {
		return fmt.Errorf("that endpoint is not usable: %w", err)
	}
	for _, t := range types {
		if !KnownType(t) {
			return fmt.Errorf(
				"%q is not an event this sends. The types are %s, or each "+
					"one's event name (page.published, booking.made) — an "+
					"endpoint subscribed to something that never happens is "+
					"configured, reported as configured, and silent",
				t, strings.Join(EventTypes, ", "))
		}
	}
	return nil
}

// CheckURL holds an endpoint's address to the rules its deliveries are
// sent by, those of the fetch client for webhooks, so an address that is
// accepted is one that can be delivered to.
//
// An address that does not parse is refused without being repeated, in
// whole or in part. The screen shows a refusal through a redirect, which
// goes into the browser's history and the access log, and the address may
// be a credential however badly it was typed. The parser's error quotes the
// part it could not read, and that part is left out too: for a password
// with a "/" or a "#" in it, it is what the parser took for the port, the
// password up to that character.
func CheckURL(raw string) error {
	if _, err := url.Parse(strings.TrimSpace(raw)); err != nil {
		var bad *url.Error
		if errors.As(err, &bad) {
			err = bad.Err
		}
		return fmt.Errorf("that is not a URL: %s", withoutQuoted(err.Error()))
	}
	_, err := fetch.For("webhook").ValidateURL(raw)
	return err
}

// withoutQuoted is msg with whatever it quotes written as "…".
func withoutQuoted(msg string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(msg, '"')
		if i < 0 {
			break
		}
		b.WriteString(msg[:i] + `"…"`)
		j := i + 1
		for j < len(msg) && msg[j] != '"' {
			if msg[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(msg) {
			// Never closed: the rest is all quoted.
			return b.String()
		}
		msg = msg[j+1:]
	}
	b.WriteString(msg)
	return b.String()
}

// LogForm is how an endpoint's address is written in the audit log and in
// anything else that is kept: its scheme and host, and "/…" in place of
// any path or query. Ref is what tells two endpoints on one host apart.
//
// Never the address itself. The path of an incoming-webhook address
// (Slack, Teams, Discord) is the credential, whoever has it posts as the
// site, and many receivers take ?token= for the same thing. The log held
// the address in full, so the auditor, who reads the log and should change
// nothing, and every copy of the log forwarded to a SIEM could post as the
// site. The administrators who saw the address before still see it in full,
// in `quilzo webhook list` and on the Integrations screen.
func LogForm(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "(not an address)"
	}
	where := u.Scheme + "://" + u.Host
	if strings.Trim(u.EscapedPath(), "/") != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		where += "/…"
	}
	return where
}

// Ref is the audit log's reference to an endpoint, by which its addition,
// changes and removal line up where LogForm alone would make two endpoints
// on one host look alike.
//
// An HMAC of the address under the endpoint's own signing key, rather than
// a digest of the address: a digest is worked back to a short ?token= by
// anyone who guesses the rest of the address and tries tokens until one
// matches, and without the key there is nothing to try. The message starts
// with "endpoint ", and every message Sign signs starts with a length whose
// first byte is zero, so a reference is never a signature.
func Ref(e Endpoint) string {
	mac := hmac.New(sha256.New, []byte(e.Secret))
	mac.Write([]byte("endpoint " + e.URL))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}
