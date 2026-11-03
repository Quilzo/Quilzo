// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/rate"
	"github.com/quilzo/quilzo/internal/replay"
)

// Receiving a push (RFC 8935).
//
// Each check is cheaper than the one after it and comes first for that
// reason: the bearer before the body, the size before parsing, the
// signature before anything is believed, and the replay check before
// anything is done. A request refused early costs almost nothing, so
// whoever is sending them chooses nothing about how hard this works.
//
// The rate comes after the bearer, not before it, and is two rates: one
// for pushes that carry the stream's bearer and one for those that do not.
// With one rate in front of everything, anybody could send a minute's
// worth of guesses and have the transmitter's real event told to wait,
// and somebody holding a stolen session would do exactly that, for as
// long as the transmitter kept retrying, to keep the provider's
// session-revoked from ending it. Comparing a bearer is a hash of a few
// dozen bytes, so it costs no more to do first.

// PushRate is how many deliveries a minute the endpoint takes from the
// transmitter. A transmitter sends one event per change to somebody's
// account; even an organisation offboarding a department at once sends a
// few a second at most, and the hourly cap on people acted on is what
// bounds the effect. Pushes without its bearer are held to the same rate,
// apart: past it they are told to wait and not counted, so a flood of them
// writes nothing.
const PushRate = 120

// maxBearer is longer than any push secret this store makes. A longer one
// is refused without being hashed: the header can be a megabyte.
const maxBearer = 256

// Connected is the stream as connected now: its verifier and the digest
// of the bearer the transmitter was given to push with. A nil verifier is
// no stream.
type Connected struct {
	Receiver *Receiver
	// Bearer is the SHA-256 of the push secret, hex. The secret itself is
	// kept nowhere here: it was handed to the transmitter, or shown once to
	// whoever connected it.
	Bearer string
}

// Push is the endpoint a transmitter pushes to.
type Push struct {
	// Stream is read on each delivery, so a stream connected or turned
	// off from the command line applies at once.
	Stream func() (Connected, error)
	// Deliver is told each verified event once. An error asks the
	// transmitter to send it again, and the event is not remembered as
	// seen, so the retry is acted on rather than refused as a replay.
	Deliver func(*SET) error
	// Refused is told each delivery that did not prove itself, and why.
	// Counted, not written to the audit log one by one: whoever is failing
	// would be choosing how fast it grows.
	Refused func(why string)
	Now     func() time.Time

	once sync.Once
	// limit holds two rates, "push" for deliveries that carry the stream's
	// bearer and "refused" for those that do not, so the second cannot
	// spend the first.
	limit *rate.Limiter
	// mu holds the replay check, the action and remembering the id
	// together, so two copies of one event arriving at once are one event.
	mu   sync.Mutex
	seen replay.Cache
}

// Digest is the stored form of a push secret.
func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (p *Push) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Push) refused(why string) {
	if p.Refused != nil {
		p.Refused(why)
	}
}

// allow spends one of the rate's units, or answers that the sender has to
// wait.
func (p *Push) allow(w http.ResponseWriter, which string) bool {
	ok, wait := p.limit.Allow(which, p.now())
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		WriteError(w, http.StatusTooManyRequests, &Error{Code: "access_denied", Description: "too many deliveries; send it again later"})
	}
	return ok
}

// WriteError answers with an RFC 8935 error.
func WriteError(w http.ResponseWriter, status int, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}

func (p *Push) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a transmitter pushes here with POST", http.StatusMethodNotAllowed)
		return
	}
	p.once.Do(func() {
		p.limit = &rate.Limiter{Every: time.Minute / PushRate, Burst: PushRate, MaxKeys: 2}
	})
	st, err := p.Stream()
	if err != nil {
		WriteError(w, http.StatusServiceUnavailable, &Error{Code: "access_denied", Description: "this receiver cannot read its stream right now"})
		return
	}
	if st.Receiver == nil {
		http.NotFound(w, r)
		return
	}
	// The bearer, before the body is read and before either rate. A stream
	// with no digest kept is one nobody can push to: an empty secret
	// matching an empty header is the mistake this refuses.
	got, scheme := auth.Presented(r.Header.Get("Authorization"))
	if st.Bearer == "" || scheme != "Bearer" || got == "" || len(got) > maxBearer ||
		subtle.ConstantTimeCompare([]byte(Digest(got)), []byte(st.Bearer)) != 1 {
		if !p.allow(w, "refused") {
			return
		}
		p.refused("the push did not carry this stream's authorization")
		WriteError(w, http.StatusUnauthorized, &Error{Code: "authentication_failed", Description: "the push did not carry this stream's authorization"})
		return
	}
	if !p.allow(w, "push") {
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/secevent+jwt" {
		p.refused("the push was not a security event token (content type " + ct + ")")
		WriteError(w, http.StatusBadRequest, &Error{Code: "invalid_request", Description: "a push is a security event token, content type application/secevent+jwt"})
		return
	}
	// Capped as it is read, before anything parses it: a body one byte
	// over is refused without the rest being taken.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxToken))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			p.refused("the push was larger than a security event can be")
			WriteError(w, http.StatusRequestEntityTooLarge, &Error{Code: "invalid_request", Description: "a security event token is at most 64 KiB"})
			return
		}
		WriteError(w, http.StatusBadRequest, &Error{Code: "invalid_request", Description: "the body could not be read"})
		return
	}
	set, err := st.Receiver.Verify(string(body))
	if errors.Is(err, ErrKeysUnread) {
		// Not the token's fault, and not counted as a push that failed to
		// prove itself: asked for again. A key set that stays out of reach
		// stops verification answering too, which posture reports.
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, err.(*Error))
		return
	}
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: "invalid_request", Description: err.Error()}
		}
		p.refused(e.Error())
		WriteError(w, http.StatusBadRequest, e)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	// By issuer as well as id: a jti is unique to the transmitter that
	// made it, and a stream connected again to another one starts afresh.
	id := set.Issuer + "\x00" + set.JTI
	// Accepted and not done again: the transmitter was told yes the first
	// time, and is told yes now, so it stops sending.
	if p.seen.Seen(id, now) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if p.seen.Full(now) {
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, &Error{Code: "access_denied", Description: "busy; send it again"})
		return
	}
	if err := p.Deliver(set); err != nil {
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, &Error{Code: "access_denied", Description: "this receiver could not act on it; send it again"})
		return
	}
	p.seen.First(id, st.Receiver.Until(set), now)
	w.WriteHeader(http.StatusAccepted)
}
