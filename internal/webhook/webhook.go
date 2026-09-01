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
	At   string `json:"at"`
	Site string `json:"site,omitempty"`
}

// EventTypes is everything this program sends.
//
// A closed list, because --types took any string and stored it: an endpoint
// asking for "publish" instead of "published" was configured, reported as
// configured, and never fired — a silent subscription to an event that does not
// exist. The same shape as an unchecked crawl-licence term, and the same fix.
var EventTypes = []string{"published", "rolled-back", "scheduled", "submitted"}

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

// MaxAttempts bounds retries.
//
// Three. A receiver that is down for longer than a few seconds is down, and
// retrying for an hour turns one outage into a queue somebody has to drain.
const MaxAttempts = 3

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
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		at := now
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
		// worth another attempt.
		if status >= 400 && status < 500 {
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
