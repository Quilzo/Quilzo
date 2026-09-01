package webhook

import (
	"encoding/json"
	"fmt"
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
