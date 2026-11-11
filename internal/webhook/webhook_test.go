// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func event() Event {
	return Event{ID: "abc123", Type: "published", Commit: "deadbeef",
		Pages: []string{"index"}, At: now.Format(time.RFC3339)}
}

type recorder struct {
	posts    []map[string]string
	bodies   [][]byte
	statuses []int
	err      error
	i        int
}

func (r *recorder) Post(url string, body []byte, headers map[string]string) (int, error) {
	r.posts = append(r.posts, headers)
	r.bodies = append(r.bodies, body)
	if r.err != nil {
		return 0, r.err
	}
	s := 200
	if r.i < len(r.statuses) {
		s = r.statuses[r.i]
	}
	r.i++
	return s, nil
}

// Wait does not: these tests are about what is sent, not when.
func (r *recorder) Wait(time.Duration) {}

func TestASignatureVerifies(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"type":"published"}`)
	sig := Sign(secret, now, body)

	if err := Verify(secret, sig, now, body, now); err != nil {
		t.Fatalf("a fresh signature did not verify: %v", err)
	}
	if err := Verify(secret, sig, now, []byte(`{"type":"other"}`), now); err == nil {
		t.Error("a signature verified against a different body")
	}
	if err := Verify("another-secret", sig, now, body, now); err == nil {
		t.Error("a signature verified under the wrong secret")
	}
}

// Without a timestamp in the signed material, a request captured today verifies
// next year — the signature is over bytes that have not changed.
func TestAnOldDeliveryIsRefusedEvenWithAValidSignature(t *testing.T) {
	secret, _ := NewSecret()
	body := []byte(`{"type":"published"}`)
	sent := now.Add(-2 * time.Hour)
	sig := Sign(secret, sent, body)

	// The signature itself is genuinely correct for that timestamp.
	if err := Verify(secret, sig, sent, body, sent); err != nil {
		t.Fatalf("the fixture is wrong: %v", err)
	}
	err := Verify(secret, sig, sent, body, now)
	if err == nil {
		t.Fatal("a two-hour-old delivery was accepted; a captured request " +
			"could be replayed indefinitely")
	}
	if !strings.Contains(err.Error(), "replayed") {
		t.Errorf("the refusal does not explain the risk: %v", err)
	}
}

// Ordinary clock drift between two machines must not break delivery, or the
// tolerance gets set to something absurd instead.
func TestSmallClockDriftIsTolerated(t *testing.T) {
	secret, _ := NewSecret()
	body := []byte(`{}`)
	sent := now.Add(-30 * time.Second)
	if err := Verify(secret, Sign(secret, sent, body), sent, body, now); err != nil {
		t.Errorf("thirty seconds of drift was refused: %v", err)
	}
	// And a delivery from the future is drift too, not a special case.
	ahead := now.Add(30 * time.Second)
	if err := Verify(secret, Sign(secret, ahead, body), ahead, body, now); err != nil {
		t.Errorf("a delivery thirty seconds ahead was refused: %v", err)
	}
}

// The construction is length-prefixed. With a plain concatenation an attacker
// can move the boundary — the same bytes split differently produce the same
// digest, so a signature valid for one pair is valid for another.
func TestTheBoundaryBetweenTimestampAndBodyCannotBeMoved(t *testing.T) {
	secret := "the-secret"

	// Two pairs whose naive concatenation is identical: timestamp "1" + body
	// "23x" against timestamp "12" + body "3x". Under HMAC(ts+body) both hash
	// "123x" and share a signature.
	a := Sign(secret, time.Unix(1, 0), []byte("23x"))
	b := Sign(secret, time.Unix(12, 0), []byte("3x"))
	if a == b {
		t.Fatal("two different (timestamp, body) pairs produced the same " +
			"signature; the field boundary can be moved")
	}
}

// A comparison that returns early leaks how much of the signature was right,
// and enough of those leak the whole thing.
func TestSignaturesAreComparedWholeNotPrefixWise(t *testing.T) {
	secret, _ := NewSecret()
	body := []byte(`{}`)
	sig := Sign(secret, now, body)

	// A signature sharing a long prefix must still be refused.
	near := sig[:len(sig)-1] + "0"
	if near == sig {
		near = sig[:len(sig)-1] + "1"
	}
	if err := Verify(secret, near, now, body, now); err == nil {
		t.Error("a signature differing in one character was accepted")
	}
	if err := Verify(secret, sig[:10], now, body, now); err == nil {
		t.Error("a truncated signature was accepted")
	}
}

// -- delivery ----------------------------------------------------------------

func TestDeliveryCarriesEverythingAReceiverNeeds(t *testing.T) {
	secret, _ := NewSecret()
	r := &recorder{}
	deliveries := Send(r, Endpoint{URL: "https://receiver.example/hook",
		Secret: secret}, event(), now)

	if len(deliveries) != 1 || !deliveries[0].Succeeded {
		t.Fatalf("got %#v", deliveries)
	}
	h := r.posts[0]
	for _, want := range []string{
		"X-Quilzo-Event", "X-Quilzo-Delivery", "X-Quilzo-Timestamp",
		"X-Quilzo-Signature",
	} {
		if h[want] == "" {
			t.Errorf("the request omits %s", want)
		}
	}
	// And the receiver, running the exported verifier, must accept it.
	ts, err := strconv.ParseInt(h["X-Quilzo-Timestamp"], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(secret, h["X-Quilzo-Signature"], time.Unix(ts, 0),
		r.bodies[0], now); err != nil {
		t.Errorf("a receiver running the shipped verifier rejected our own "+
			"delivery: %v", err)
	}
}

// The id is stable across retries, which is what lets a receiver deduplicate.
// Claiming exactly-once over HTTP is how an integration processes a
// publication twice with nobody knowing why.
func TestRetriesReuseTheSameDeliveryID(t *testing.T) {
	r := &recorder{statuses: []int{500, 502, 200}}
	deliveries := Send(r, Endpoint{URL: "https://x.example", Secret: "s"},
		event(), now)

	if len(deliveries) != 3 {
		t.Fatalf("got %d attempts", len(deliveries))
	}
	for _, d := range deliveries {
		if d.ID != "abc123" {
			t.Errorf("the delivery id changed between attempts: %s", d.ID)
		}
	}
	if !deliveries[2].Succeeded {
		t.Error("the third attempt did not succeed")
	}
	for _, h := range r.posts {
		if h["X-Quilzo-Delivery"] != "abc123" {
			t.Error("the header id changed between retries")
		}
	}
}

// A 4xx is the receiver saying the request is wrong, and repeating it will not
// make it right.
func TestAClientErrorIsNotRetried(t *testing.T) {
	r := &recorder{statuses: []int{400}}
	deliveries := Send(r, Endpoint{URL: "https://x.example", Secret: "s"},
		event(), now)
	if len(deliveries) != 1 {
		t.Errorf("a 400 was retried %d times", len(deliveries))
	}

	// A 500 is worth another go.
	r = &recorder{statuses: []int{500, 500, 500}}
	if got := len(Send(r, Endpoint{URL: "https://x.example", Secret: "s"},
		event(), now)); got != MaxAttempts {
		t.Errorf("a 500 was attempted %d times", got)
	}
}

// restarting is a receiver that answers 503, or status, until a moment
// has passed on its own clock, which only waiting moves: a receiver being
// deployed.
type restarting struct {
	clock, back time.Duration
	status      int
	at          []time.Duration
	stamps      []string
}

func (r *restarting) Post(_ string, _ []byte, headers map[string]string) (int, error) {
	r.at = append(r.at, r.clock)
	r.stamps = append(r.stamps, headers["X-Quilzo-Timestamp"])
	if r.clock < r.back {
		return cmp.Or(r.status, 503), nil
	}
	return 200, nil
}

func (r *restarting) Wait(d time.Duration) { r.clock += d }

// A receiver restarting for less than a second still gets the event.
//
// The three attempts were made back to back, about 10 ms apart, so a
// receiver down for a deploy answered all three with 503 and the event was
// never delivered: "at-least-once" was at most once for anybody who
// restarts. Each attempt after the first now waits, and is signed for the
// moment it is sent rather than the moment the first one was.
func TestARetryWaitsLongEnoughForAReceiverToRestart(t *testing.T) {
	r := &restarting{back: 800 * time.Millisecond}
	deliveries := Send(r, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)
	last := deliveries[len(deliveries)-1]
	if !last.Succeeded {
		t.Fatalf("a receiver back after %s missed every attempt, made at %v", r.back, r.at)
	}
	if len(r.at) < 2 || r.at[1]-r.at[0] < r.back {
		t.Fatalf("the attempts were made at %v", r.at)
	}
	if r.stamps[0] == r.stamps[1] {
		t.Errorf("a retry was signed for the time of the first attempt: %v", r.stamps)
	}
	// Bounded still: a receiver that stays down is tried MaxAttempts times,
	// within the few seconds a receiver is given, and well inside the window
	// in which a receiver accepts a signed timestamp.
	down := &restarting{back: time.Hour}
	if got := len(Send(down, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)); got != MaxAttempts {
		t.Fatalf("%d attempts against a receiver that stays down", got)
	}
	if waited := down.at[len(down.at)-1]; waited > 10*time.Second || waited >= Tolerance {
		t.Errorf("the last attempt came %s after the first", waited)
	}
}

// A receiver that answers 429, taking fewer requests for a moment, or 408,
// having timed out reading the request, is asking for it again later. Both
// are 4xx, which was read as the request being wrong, so the event was
// dropped on the first answer, as an event to a receiver restarting was.
func TestABusyReceiverIsTriedAgainLater(t *testing.T) {
	for _, busy := range []int{429, 408} {
		r := &restarting{back: time.Second, status: busy}
		deliveries := Send(r, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)
		if last := deliveries[len(deliveries)-1]; !last.Succeeded || len(deliveries) != 2 {
			t.Errorf("a receiver that answered %d for a second: %d attempt(s), made at %v",
				busy, len(deliveries), r.at)
		}
	}
	// Any other 4xx still says the request is wrong.
	for _, wrong := range []int{400, 401, 403, 404, 410, 413, 422} {
		r := &recorder{statuses: []int{wrong, 200}}
		if got := len(Send(r, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)); got != 1 {
			t.Errorf("a %d was attempted %d times", wrong, got)
		}
	}
}

// asking is a receiver that answers status, with a Retry-After of retry,
// to its first request and 200 to the rest. It answers through PostHeaders,
// as the program's own sender does, and keeps the waits it was given.
type asking struct {
	status int
	retry  string
	waits  []time.Duration
	stamps []string
}

func (a *asking) PostHeaders(_ string, _ []byte, headers map[string]string) (int, http.Header, error) {
	a.stamps = append(a.stamps, headers["X-Quilzo-Timestamp"])
	if len(a.stamps) == 1 {
		return a.status, http.Header{"Retry-After": {a.retry}}, nil
	}
	return 200, nil, nil
}

// Post is the same answer without its headers, which was all Send read.
func (a *asking) Post(url string, body []byte, headers map[string]string) (int, error) {
	status, _, err := a.PostHeaders(url, body, headers)
	return status, err
}

func (a *asking) Wait(d time.Duration) { a.waits = append(a.waits, d) }

// A receiver that says when to come back is come back to then.
//
// Send read only the status, so a 429 with Retry-After: 3 was tried again
// after one second, while the receiver was still refusing, and a second
// time after four more: the event spent its attempts on the moment it had
// been asked to keep clear of. Both forms RFC 9110 gives are read, seconds
// and a date, and the retry is signed for the moment it goes.
func TestARetryAfterIsWaitedForAsAsked(t *testing.T) {
	for _, c := range []struct {
		form, header string
		want         time.Duration
	}{
		{"seconds", "3", 3 * time.Second},
		{"a date", now.Add(5 * time.Second).Format(http.TimeFormat), 5 * time.Second},
	} {
		a := &asking{status: 429, retry: c.header}
		deliveries := Send(a, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)
		if len(deliveries) != 2 || !deliveries[1].Succeeded {
			t.Errorf("Retry-After as %s: got %+v", c.form, deliveries)
			continue
		}
		if len(a.waits) != 1 || a.waits[0] != c.want {
			t.Errorf("Retry-After as %s (%q) asked for %s; Send waited %v",
				c.form, c.header, c.want, a.waits)
		}
		if want := strconv.FormatInt(now.Add(c.want).Unix(), 10); a.stamps[1] != want {
			t.Errorf("Retry-After as %s: the retry was signed for %s, not %s", c.form, a.stamps[1], want)
		}
	}
}

// A receiver asking for longer than Send waits is not tried again sooner
// than it asked: that is another refusal, and one more request to a
// receiver that has said it is taking fewer. The delivery says why it
// stopped, since a 429 tried once looks like one Send forgot to retry.
func TestARetryAfterPastTheCapStopsTheDelivery(t *testing.T) {
	for _, header := range []string{"3600", now.Add(time.Hour).Format(http.TimeFormat),
		"99999999999999999999"} {
		a := &asking{status: 503, retry: header}
		deliveries := Send(a, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)
		if len(deliveries) != 1 || len(a.waits) != 0 {
			t.Errorf("Retry-After %q: %d attempts after waits of %v", header, len(deliveries), a.waits)
			continue
		}
		if d := deliveries[0]; d.Succeeded || d.Status != 503 || !strings.Contains(d.Error, "Retry-After") {
			t.Errorf("Retry-After %q: the delivery does not say why it stopped: %+v", header, d)
		}
	}
	// What is not a delay, or is one already over, leaves Send's own
	// schedule as it was.
	for _, header := range []string{"soon", "-1", "+3", "1.5", "0",
		now.Add(-time.Minute).Format(http.TimeFormat)} {
		a := &asking{status: 429, retry: header}
		deliveries := Send(a, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)
		if len(deliveries) != 2 || len(a.waits) != 1 ||
			a.waits[0] < retryAfter[0] || a.waits[0] >= retryAfter[0]*3/2 {
			t.Errorf("Retry-After %q: %d attempts after waits of %v", header, len(deliveries), a.waits)
		}
	}
}

// Deliveries one receiver turned away together do not come back together.
//
// Every delivery waited exactly one second and then four, so a burst a
// receiver refused at once arrived again at once, and was refused again.
// Each wait is now Send's schedule plus up to half again: never sooner
// than the schedule, which is what a receiver restarting needs.
func TestRetriesAreSpreadOut(t *testing.T) {
	first := map[time.Duration]bool{}
	for range 20 {
		down := &restarting{back: time.Hour}
		Send(down, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)
		for i, least := range retryAfter {
			if gap := down.at[i+1] - down.at[i]; gap < least || gap >= least*3/2 {
				t.Fatalf("wait %d was %s, outside [%s, %s)", i+1, gap, least, least*3/2)
			}
		}
		first[down.at[1]] = true
	}
	if len(first) < 2 {
		t.Errorf("twenty deliveries refused together all came back after %v", first)
	}
}

// Retrying for an hour turns one outage into a queue somebody has to drain.
func TestRetriesAreBounded(t *testing.T) {
	r := &recorder{err: fmt.Errorf("connection refused")}
	if got := len(Send(r, Endpoint{URL: "https://x.example", Secret: "s"},
		event(), now)); got != MaxAttempts {
		t.Errorf("%d attempts against an unreachable receiver", got)
	}
}

// Naming what changed rather than shipping it means a webhook cannot leak
// unpublished content to a misconfigured endpoint.
func TestThePayloadNamesWhatChangedRatherThanCarryingIt(t *testing.T) {
	r := &recorder{}
	Send(r, Endpoint{URL: "https://x.example", Secret: "s"}, event(), now)

	var got map[string]any
	if err := json.Unmarshal(r.bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if _, carries := got["content"]; carries {
		t.Error("the payload carries content")
	}
	if _, carries := got["body"]; carries {
		t.Error("the payload carries a page body")
	}
	if got["pages"] == nil {
		t.Error("the payload does not say which pages changed")
	}
}

func TestAnEndpointOnlyGetsTheTypesItAskedFor(t *testing.T) {
	all := Endpoint{URL: "https://x.example"}
	only := Endpoint{URL: "https://x.example", Types: []string{"published"}}
	off := Endpoint{URL: "https://x.example", Disabled: true}

	if !all.Wants("published") || !all.Wants("rolled-back") {
		t.Error("an endpoint with no filter should get everything")
	}
	if !only.Wants("published") || only.Wants("rolled-back") {
		t.Error("the filter was not applied")
	}
	if off.Wants("published") {
		t.Error("a disabled endpoint was sent an event")
	}
}

// A secret shown in full in a listing is a secret in somebody's scrollback.
func TestSecretsAreNotDisplayed(t *testing.T) {
	e := Endpoint{URL: "https://x.example", Secret: "super-secret-value"}
	if Redact(e).Secret == e.Secret {
		t.Error("the secret survived redaction")
	}
	hint := SecretHint(e.Secret)
	if strings.Contains(hint, "secret-value") {
		t.Errorf("the hint reveals the secret: %q", hint)
	}
	if len(hint) == 0 {
		t.Error("the hint is empty, so an operator cannot tell two apart")
	}
}

// A golden value computed by an independent implementation of the documented
// scheme:
//
//	def field(b): return struct.pack('>Q', len(b)) + b
//	m = hmac.new(secret, digestmod=hashlib.sha256)
//	m.update(field(timestamp_ascii)); m.update(field(body))
//
// This is what makes the construction a specification rather than whatever this
// code happens to do. A receiver written in another language has to arrive at
// the same bytes, and if this test fails after a change here, every existing
// receiver has silently stopped verifying.
func TestTheSignatureMatchesAnIndependentImplementation(t *testing.T) {
	body := []byte(`{"id":"abc","type":"published","commit":"deadbeef"}`)
	got := Sign("shared-secret", time.Unix(1786000000, 0), body)
	const want = "v1=3e54ba6febbcd79937fe6911f7c52ce1f314f13036574d58eb04df7af17cadd9"

	if got != want {
		t.Errorf("the signature has changed:\n  got  %s\n  want %s\n"+
			"Every receiver written against the documented scheme has stopped "+
			"verifying.", got, want)
	}
}

// A submitted event names the form and carries nothing that was typed.
//
// A webhook body leaving this system goes to one that has never heard of the
// retention period the submission was collected under. So the event says that
// something arrived and where it came through, and the operator reads the
// message where it is kept — the same rule the audit record for the same event
// follows.
func TestASubmittedEventCarriesNoSubmittedValues(t *testing.T) {
	var sent []byte
	s := senderFunc(func(url string, body []byte, h map[string]string) (int, error) {
		sent = append([]byte(nil), body...)
		return 200, nil
	})
	ev := Event{ID: "d1", Type: "submitted", Form: "wholesale",
		At: "2026-08-31T09:00:00Z", Site: "https://example.com"}
	deliveries := Send(s, Endpoint{URL: "https://receiver.example/hook",
		Secret: "shh"}, ev, time.Unix(1787000000, 0))
	if len(deliveries) == 0 || !deliveries[len(deliveries)-1].Succeeded {
		t.Fatalf("the event was not delivered: %+v", deliveries)
	}

	var got map[string]any
	if err := json.Unmarshal(sent, &got); err != nil {
		t.Fatal(err)
	}
	if got["form"] != "wholesale" {
		t.Errorf("the event does not name the form: %v", got)
	}
	// Every key is one of the event's own. A field carrying an answer would be
	// somebody's email address in a system nobody agreed to.
	for key := range got {
		switch key {
		case "id", "type", "commit", "pages", "form", "at", "site":
		default:
			t.Errorf("the event carries %q, which is not part of an event", key)
		}
	}
}

// The event types are a closed list, because --types stored whatever it was
// given: an endpoint asking for "publish" instead of "published" was configured,
// reported as configured, and never fired.
func TestTheEventVocabularyIsClosed(t *testing.T) {
	for _, known := range EventTypes {
		if !KnownType(known) {
			t.Errorf("%q is listed and not known", known)
		}
	}
	for _, wrong := range []string{"publish", "submit", "", "PUBLISHED"} {
		if KnownType(wrong) {
			t.Errorf("%q was accepted as an event type", wrong)
		}
	}
	// Every type this program actually sends has to be in the list, or the
	// list is a way to subscribe to nothing.
	for _, sent := range []string{"published", "submitted"} {
		if !KnownType(sent) {
			t.Errorf("%q is sent and is not in EventTypes", sent)
		}
	}
}

type senderFunc func(string, []byte, map[string]string) (int, error)

func (f senderFunc) Post(url string, body []byte, h map[string]string) (int, error) {
	return f(url, body, h)
}
