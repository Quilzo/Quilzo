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
// restarted needs, with a little randomness so that deliveries turned away
// together are not retried together. A receiver can ask for longer with
// Retry-After, up to MaxRetryAfter, and no longer: a delivery that fails
// every attempt, or is asked to wait past that, is recorded as failed with
// the deliveries, for somebody to see, rather than queued to be sent again
// later.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
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

// EventTypes is everything this program sends.
//
// A closed list, because --types took any string and stored it: an endpoint
// asking for "publish" instead of "published" was configured, reported as
// configured, and never fired — a silent subscription to an event that does not
// exist. The same shape as an unchecked crawl-licence term, and the same fix.
var EventTypes = []string{"published", "rolled-back", "scheduled", "submitted",
	// A change is waiting for somebody to agree to it.
	//
	// Dual authorisation only works if the people it waits on find out they
	// are being waited on. Without this the approval screen is a page
	// somebody has to think to open, which means a proposal sits until its
	// author asks in person -- and the reliable way to stop being asked in
	// person is to turn the requirement off.
	//
	// It carries who proposed and whether a machine wrote it. That second
	// part is the one that decides whether a person has to read it, so it is
	// the part worth putting in front of them rather than behind a click.
	"proposed",
	// A visitor booked a time, or cancelled one: the moment a business
	// taking bookings needs to hear about, as a form's "submitted" is.
	"booked", "booking-cancelled",
	// Somebody confirmed they want the newsletter, or left it: which, and
	// never the address.
	"subscribed", "unsubscribed"}

// KnownType reports whether this program ever sends an event of this type.
func KnownType(t string) bool {
	for _, known := range EventTypes {
		if known == t {
			return true
		}
	}
	return false
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
func (e Endpoint) Wants(t string) bool {
	if e.Disabled {
		return false
	}
	if len(e.Types) == 0 {
		return true
	}
	for _, want := range e.Types {
		if want == t {
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

// HeaderSender is a Sender that also gives back the receiver's response
// headers, which is how Send reads a Retry-After. A Sender that is not one is
// tried again on Send's own schedule alone.
type HeaderSender interface {
	PostHeaders(url string, body []byte, headers map[string]string) (int, http.Header, error)
}

// post makes one attempt, through PostHeaders where s has it.
func post(s Sender, url string, body []byte, headers map[string]string) (int, http.Header, error) {
	if hs, ok := s.(HeaderSender); ok {
		return hs.PostHeaders(url, body, headers)
	}
	status, err := s.Post(url, body, headers)
	return status, nil, err
}

// MaxAttempts bounds retries.
//
// Three. A receiver that is down for longer than a few seconds is down, and
// retrying for an hour turns one outage into a queue somebody has to drain.
const MaxAttempts = 3

// retryAfter is how long Send waits, at least, before each attempt after the
// first.
//
// The attempts used to be made back to back, all three within about 10 ms,
// so a receiver restarting for a deploy — down for well under a second —
// answered every one of them with a 503 and the event was lost. One second
// and then four more cover a restart, keep the last attempt within the few
// seconds MaxAttempts gives a receiver, and keep every attempt's timestamp
// far inside Tolerance.
var retryAfter = [MaxAttempts - 1]time.Duration{time.Second, 4 * time.Second}

// backoff is Send's own wait before the attempt after this one: the schedule
// plus up to half again, at random.
//
// Every delivery used to wait exactly the schedule, so a burst that a
// receiver turned away at once came back at once and was turned away again.
// The random part is added on top rather than taken off, because the floor
// is what covers a restart.
func backoff(attempt int) time.Duration {
	d := retryAfter[attempt-1]
	return d + mrand.N(max(d/2, 1))
}

// MaxRetryAfter is the longest Send waits because a receiver asked it to.
//
// A receiver that answers with Retry-After (RFC 9110, section 10.2.3), in
// seconds or as a date, is waited for as long as it asked, when that is longer
// than Send's own wait. One asking for longer than this is not tried again
// sooner than it asked, which would be one more request to a receiver that
// has said it is taking fewer: the delivery stops there and says why. Ten
// seconds, as the REST client waits, keeps a publish waiting on its webhooks
// for seconds rather than minutes, and every attempt far inside Tolerance.
const MaxRetryAfter = 10 * time.Second

// askedWait is how long a Retry-After value asks for, counted from at, and
// whether it is one: a number of seconds, or a date in any of the three forms
// RFC 9110 has a recipient accept. A date already past asks for no wait.
//
// at is the clock Send signs with, which runs behind the real one by however
// long the requests took, so a date is waited for at least as long as asked.
func askedWait(v string, at time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if strings.Trim(v, "0123456789") == "" {
		s, err := strconv.ParseInt(v, 10, 64)
		if err != nil || s > math.MaxInt64/int64(time.Second) {
			// Digits, and too many of them for a Duration: a very long time.
			return math.MaxInt64, true
		}
		return time.Duration(s) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(at), 0), true
	}
	return 0, false
}

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
	var waited, wait time.Duration
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if attempt > 1 {
			if w, ok := s.(Waiter); ok {
				w.Wait(wait)
			} else {
				time.Sleep(wait)
			}
			waited += wait
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
		status, answer, err := post(s, e.URL, body, headers)
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
		if attempt == MaxAttempts {
			break
		}
		// Send's own wait, or the receiver's, when it asked for longer.
		wait = backoff(attempt)
		if asked, ok := askedWait(answer.Get("Retry-After"), at); ok {
			if asked > MaxRetryAfter {
				out[len(out)-1].Error = fmt.Sprintf("the receiver asked to be "+
					"tried again in %s (Retry-After), longer than the %s a "+
					"delivery waits, so it was not tried again",
					asked.Round(time.Second), MaxRetryAfter)
				return out
			}
			wait = max(wait, asked)
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
