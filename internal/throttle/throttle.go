// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package throttle slows down repeated attempts from one subject.
//
// Two jobs, and they count different things. For authentication it counts
// failures, which is what the standards below are about. For an anonymous
// write it counts every attempt, because a successful one is the abuse — see
// Spend.
//
// NIST SP 800-63B-4 says a verifier SHALL rate-limit failed authentication
// attempts. ASVS 5.0 puts numbers on it: no more than 100 failures per hour on
// one account, and more than five in an hour should trigger a reaction.
//
// The design decision worth stating is the one ASVS asks to be documented:
// **how this prevents malicious account lockout**. A hard lockout — n failures
// and the account stops working — is a denial of service anybody can aim at
// anybody else. You do not need the credential, only the principal's name, and
// names are not secret. It converts "an attacker must guess a secret" into "an
// attacker must know who you are", which is a downgrade wearing the costume of
// a control.
//
// So this is a soft lockout: the delay doubles with each failure and decays
// with time. It costs an attacker exactly what a hard lockout costs them, and
// costs the victim a wait rather than an outage. Where a person's account does
// need locking, internal/lockout locks the places the failures come from out
// of it, and leaves the person's own places working.
//
// It cannot be switched off, and its numbers are held between bounds whatever
// the configuration says (Bounded): a limit somebody can raise to a million is
// not a limit.
//
// Two other things this must not do:
//
//   - It must not become an enumeration oracle. Failing against a principal
//     that exists must be indistinguishable from failing against one that does
//     not, so counters are kept for whatever was presented rather than only
//     for principals that resolve.
//   - It must not sleep. A delay implemented as time.Sleep inside a request
//     handler is a way to exhaust the server's own workers by failing
//     authentication in parallel — the throttle becomes the denial of service.
//     Attempts inside the window are refused immediately and told when to come
//     back.
package throttle

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Policy is the configuration, already resolved from config settings.
type Policy struct {
	// After is how many failures are free before delays begin.
	After int
	// Ceiling is failures per Window after which nothing is accepted for the
	// rest of it, however long the caller waits.
	Ceiling int
	// Base is the first delay; it doubles per failure up to Max.
	Base time.Duration
	Max  time.Duration
	// Window is how long failures are remembered. Older ones decay.
	Window time.Duration
	// Alert is the failure count in a Window that deserves a record somebody
	// will look at.
	Alert int
}

// Default is the policy this ships with, which is the one in the settings
// table. Kept here so the package is usable without the config package, and so
// a test can state the numbers it expects.
func Default() Policy {
	return Policy{
		After: 5, Ceiling: 100,
		Base: time.Second, Max: 15 * time.Minute,
		Window: time.Hour, Alert: 5,
	}
}

// The bounds a policy is held to. The configuration refuses a value outside
// them, and New holds a policy built any other way to them too, except
// LeastCeiling, which only the configuration enforces: a policy derived from
// the configured one may be stricter than a person could be (a share takes
// half a form's ceiling).
const (
	// MostFree is the most failures that may be free: NIST SP 800-63B-4
	// suggests no more than 10.
	MostFree = 10
	// LeastCeiling and MostCeiling bound the failures in a window after
	// which nothing is accepted. ASVS 5.0 allows at most 100 an hour; fewer
	// than 10 would let anybody who knows a name keep its owner out for an
	// hour with a handful of attempts.
	LeastCeiling = 10
	MostCeiling  = 100
	// LeastDelay is the shortest first delay, below which an attacker does
	// not notice it.
	LeastDelay = time.Second
	// LongestDelay is the longest a delay may grow to: any longer is worth
	// triggering deliberately, to keep somebody else out.
	LongestDelay = time.Hour
	// LatestAlert is the most failures in a window before one is reported;
	// a slow run under it would never be.
	LatestAlert = 20
)

// Bounded is the policy held to the bounds.
func (p Policy) Bounded() Policy {
	if p.Window <= 0 {
		p.Window = time.Hour
	}
	p.After = max(0, min(p.After, MostFree))
	p.Ceiling = max(1, min(p.Ceiling, MostCeiling))
	p.Base = max(LeastDelay, min(p.Base, LongestDelay))
	if p.Max <= 0 {
		p.Max = 15 * time.Minute
	}
	p.Max = max(p.Base, min(p.Max, LongestDelay))
	p.Alert = max(1, min(p.Alert, LatestAlert))
	return p
}

// Subject is who or what is being throttled.
//
// Both halves are counted separately and the stricter answer wins. A single
// attacker working through many principals from one address is caught by the
// source; a distributed attempt on one principal is caught by the principal.
// Either alone leaves an obvious gap.
type Subject struct {
	// Principal is whatever identity was presented — a name, a token prefix,
	// a client id. It does not have to exist.
	Principal string
	// Source is where the attempt came from, when that is known: an address
	// for HTTP, empty for the CLI where the caller is already local.
	Source string
}

// Limiter tracks failures. The zero value is not usable; call New.
type Limiter struct {
	mu     sync.Mutex
	policy Policy
	// key is HMAC'd rather than stored, because this map holds attempted
	// usernames and addresses — which is to say, a list of who is being
	// attacked and from where. A crash dump or a debug endpoint should not
	// hand that over, and nothing here needs the original value back.
	key   []byte
	state map[string]*record
	now   func() time.Time
}

type record struct {
	failures int
	first    time.Time
	last     time.Time
	// alerted stops one slow attack producing an audit record per attempt for
	// an hour. The threshold crossing is the event; the attempts after it are
	// the same event continuing.
	alerted bool
}

// New returns a limiter.
func New(p Policy) *Limiter {
	p = p.Bounded()
	key := make([]byte, 32)
	// A per-process key. It does not need to survive a restart: the counters
	// do not either, and a restart clearing the throttle is a property to
	// document rather than a flaw to engineer around — an attacker who can
	// restart the process has already won more than this.
	if _, err := randRead(key); err != nil {
		// Falling back to a fixed key would make the map's keys predictable,
		// which matters only for a local attacker reading memory. Panicking
		// on a failed read from the system CSPRNG is the honest response;
		// there is no safe degraded mode.
		panic("throttle: no entropy available: " + err.Error())
	}
	return &Limiter{policy: p, key: key, state: map[string]*record{},
		now: time.Now}
}

// WithClock is for tests.
func (l *Limiter) WithClock(now func() time.Time) *Limiter { l.now = now; return l }

// Decision is the answer to "may this attempt proceed".
type Decision struct {
	Allowed bool
	// RetryAfter is how long until the next attempt would be allowed. Zero
	// when allowed.
	RetryAfter time.Duration
	// Failures is how many are on record for this subject in the window.
	Failures int
	// Locked reports the ceiling reached rather than a delay, so a caller can
	// say which one happened.
	Locked bool
	// Why is the sentence to show the person waiting.
	Why string
}

// Check asks whether an attempt may proceed. It does not record anything —
// Fail and Succeed do that — so a caller that checks and then never attempts
// has not consumed anything.
func (l *Limiter) Check(s Subject) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	worst := Decision{Allowed: true}
	for _, k := range l.keys(s) {
		d := l.checkOne(k, now)
		if !d.Allowed && (worst.Allowed || d.RetryAfter > worst.RetryAfter) {
			worst = d
		} else if worst.Allowed && d.Failures > worst.Failures {
			worst.Failures = d.Failures
		}
	}
	return worst
}

func (l *Limiter) checkOne(key string, now time.Time) Decision {
	r := l.state[key]
	if r == nil || l.expired(r, now) {
		return Decision{Allowed: true}
	}
	if r.failures >= l.policy.Ceiling {
		wait := l.policy.Window - now.Sub(r.first)
		if wait < 0 {
			wait = 0
		}
		return Decision{
			RetryAfter: wait, Failures: r.failures, Locked: true,
			Why: fmt.Sprintf(
				"%d failed attempts in the last hour, which is the ceiling. "+
					"Nothing further is accepted for %s.",
				r.failures, round(wait)),
		}
	}
	// After is how many failures are free, so the delay starts on the one
	// after that. Using < here charged a delay on the fifth failure when five
	// were meant to be free, and started the doubling at 2s instead of 1s —
	// an off-by-one in both directions at once, which is what comes of
	// writing the condition and the exponent from the same wrong idea of
	// which failure is the first delayed one.
	if r.failures <= l.policy.After {
		return Decision{Allowed: true, Failures: r.failures}
	}
	delay := l.policy.Base << uint(min(r.failures-l.policy.After-1, 30))
	if delay > l.policy.Max || delay <= 0 {
		delay = l.policy.Max
	}
	if wait := delay - now.Sub(r.last); wait > 0 {
		return Decision{
			RetryAfter: wait, Failures: r.failures,
			Why: fmt.Sprintf(
				"%d recent failures, so attempts are being slowed down. Try "+
					"again in %s.", r.failures, round(wait)),
		}
	}
	return Decision{Allowed: true, Failures: r.failures}
}

// Fail records a failed attempt and returns the decision that now applies,
// plus whether this attempt crossed the alerting threshold.
func (l *Limiter) Fail(s Subject) (Decision, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	alert := false
	for _, k := range l.keys(s) {
		r := l.state[k]
		if r == nil || l.expired(r, now) {
			r = &record{first: now}
			l.state[k] = r
		}
		r.failures++
		r.last = now
		if !r.alerted && l.policy.Alert > 0 && r.failures > l.policy.Alert {
			r.alerted = true
			alert = true
		}
	}

	worst := Decision{Allowed: true}
	for _, k := range l.keys(s) {
		if d := l.checkOne(k, now); !d.Allowed &&
			(worst.Allowed || d.RetryAfter > worst.RetryAfter) {
			worst = d
		}
	}
	if worst.Allowed {
		// Still under the threshold, but report the count so a caller can say
		// how many attempts remain before it bites.
		if r := l.state[l.keys(s)[0]]; r != nil {
			worst.Failures = r.failures
		}
	}
	return worst, alert
}

// Spend records one attempt against the window, successful or not.
//
// # Why this exists beside Fail
//
// Because this package was written for one job and is used for two, and the
// two count different things.
//
// For sign-in, the thing to bound is failures. A person who signs in
// successfully a hundred times is a person using the product; a hundred
// failures is somebody guessing. Fail is right there, and Succeed clearing the
// record is right, and the whole design follows.
//
// For an anonymous write — a form submission, a share — the thing to bound is
// ATTEMPTS, because a successful one is the abuse. The public form path used
// Check and Fail and nothing else, so only rejected submissions counted: a
// script that loaded the form once, kept the timestamp and posted valid
// submissions in a loop was never slowed at all. Measured against the demo
// before this existed, eighty valid submissions from one address were eighty
// accepted and none refused. The honeypot and the timing check both pass for
// anything that read the page once, which is a low bar for a script and the
// only bar there was.
//
// The counter underneath is the same counter. It has to be: a limiter with a
// second, separate window would let an attacker spend both. What differs is
// the intent of the caller, and that difference is worth a name — a future
// reader finding Fail on the success path would correct it, and be wrong.
//
// Succeed must not be called on a path that uses this. Clearing the record
// after an accepted write is how the limit stops existing. It happens to be a
// no-op for a Subject with no principal, which every anonymous write has, but
// that is a coincidence and not a guarantee.
func (l *Limiter) Spend(s Subject) (Decision, bool) { return l.Fail(s) }

// Succeed clears the principal's record. The source's is left to decay.
//
// Clearing the principal is right: the counter exists to slow down somebody
// who does not have the credential, and once they demonstrably do, the history
// is no longer evidence of anything. A person who mistyped four times and then
// got it right should not still be delayed tomorrow.
//
// Clearing the source is wrong, and a live run showed why. An address is
// shared — a NAT, an office, a CI runner — so a successful sign-in by one
// person would reset the failure count for everybody behind it, and an
// attacker sitting on the same address gets their budget refilled every time a
// colleague logs in. The failures did happen from that address, and a success
// by somebody else is not evidence that they stopped. They expire on their own
// within the window, which is the right way for them to go.
func (l *Limiter) Succeed(s Subject) {
	if s.Principal == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, l.hash("p", s.Principal))
}

// Failures reports the count on record for a subject, for display.
func (l *Limiter) Failures(s Subject) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	most := 0
	for _, k := range l.keys(s) {
		if r := l.state[k]; r != nil && !l.expired(r, now) {
			if r.failures > most {
				most = r.failures
			}
		}
	}
	return most
}

// Tracked is how many subjects are on record, for the posture scan and for a
// test that the map does not grow without bound.
func (l *Limiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(l.now())
	return len(l.state)
}

// sweep drops expired records.
//
// Called from Fail rather than from a goroutine: a background sweeper is a
// goroutine to stop, a test to make deterministic, and a source of races, in
// exchange for tidying a map that only grows when somebody is failing. Doing
// it on write bounds the map by the number of distinct subjects failing within
// one window, which is the same bound a sweeper would give.
func (l *Limiter) sweep(now time.Time) {
	if len(l.state) < 1024 {
		return
	}
	for k, r := range l.state {
		if l.expired(r, now) {
			delete(l.state, k)
		}
	}
}

// expired reports whether a record has decayed out of the window, measured
// from its first failure: measured from the last, an attacker who kept
// failing would keep the subject out for as long as they liked.
func (l *Limiter) expired(r *record, now time.Time) bool {
	return now.Sub(r.first) > l.policy.Window
}

// keys returns the storage keys for a subject, principal first.
func (l *Limiter) keys(s Subject) []string {
	var out []string
	if s.Principal != "" {
		out = append(out, l.hash("p", s.Principal))
	}
	if s.Source != "" {
		out = append(out, l.hash("s", s.Source))
	}
	if len(out) == 0 {
		// Neither known: still counted, under one bucket, so an attempt that
		// presents nothing at all cannot be repeated without limit.
		out = append(out, l.hash("anon", ""))
	}
	return out
}

func (l *Limiter) hash(kind, v string) string {
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// Snapshot describes the current state, for `quilzo auth throttled`.
type Snapshot struct {
	// Subjects are opaque: the map holds HMACs, so this reports counts and
	// timings without being able to say who. That is deliberate — the list of
	// principals currently being attacked is itself worth protecting, and an
	// operator asking "is something happening" does not need names to answer
	// it. The audit log has the identifiers, pseudonymised, for the case where
	// somebody does.
	Failures int
	Since    time.Duration
	RetryIn  time.Duration
	Locked   bool
	Alerted  bool
}

// State returns a snapshot of every tracked subject, worst first.
func (l *Limiter) State() []Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var out []Snapshot
	for k, r := range l.state {
		if l.expired(r, now) {
			continue
		}
		d := l.checkOne(k, now)
		out = append(out, Snapshot{
			Failures: r.failures, Since: now.Sub(r.first),
			RetryIn: d.RetryAfter, Locked: d.Locked, Alerted: r.alerted,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Failures > out[j].Failures
	})
	return out
}

func round(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(time.Millisecond)
	}
	return d.Round(time.Second)
}

// randRead is crypto/rand.Read, named so the panic above reads clearly.
func randRead(b []byte) (int, error) { return rand.Read(b) }
