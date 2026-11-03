// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const pushSecret = "qzsig_the-transmitter-was-given-this"

// pushed is a Push in front of a receiver for key k, counting what it was
// told.
type pushed struct {
	p         *Push
	delivered []*SET
	refusals  []string
	fail      error
}

func newPush(t *testing.T, k *key) *pushed {
	t.Helper()
	r := receiver(t, k)
	out := &pushed{}
	out.p = &Push{
		Stream: func() (Connected, error) { return Connected{Receiver: r, Bearer: Digest(pushSecret)}, nil },
		Deliver: func(s *SET) error {
			if out.fail != nil {
				return out.fail
			}
			out.delivered = append(out.delivered, s)
			return nil
		},
		Refused: func(why string) { out.refusals = append(out.refusals, why) },
		Now:     func() time.Time { return now },
	}
	return out
}

func (x *pushed) send(t *testing.T, bearer, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/sso/signals", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	x.p.ServeHTTP(w, req)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return e.Code
}

// No bearer or the wrong one is authentication_failed; the wrong content
// type is a bad request; a body over 64 KiB is refused as it is read, before
// anything verifies it. Nothing is delivered in any of them, and each is
// counted.
func TestAPushThatDoesNotProveItselfIsRefusedBeforeAnythingIsDone(t *testing.T) {
	k := newKey(t)
	x := newPush(t, k)
	good := k.sign(t, nil, revoked())

	if w := x.send(t, "", "application/secevent+jwt", good); w.Code != http.StatusUnauthorized || errCode(t, w) != "authentication_failed" {
		t.Errorf("no bearer: %d %s", w.Code, w.Body)
	}
	if w := x.send(t, "qzsig_somebody-else", "application/secevent+jwt", good); w.Code != http.StatusUnauthorized || errCode(t, w) != "authentication_failed" {
		t.Errorf("the wrong bearer: %d %s", w.Code, w.Body)
	}
	if w := x.send(t, pushSecret, "application/json", good); w.Code != http.StatusBadRequest || errCode(t, w) != "invalid_request" {
		t.Errorf("the wrong content type: %d %s", w.Code, w.Body)
	}
	// 413, which only the cap answers: Verify's own size check says 400.
	w := x.send(t, pushSecret, "application/secevent+jwt", strings.Repeat("a", MaxToken+1))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized body: %d %s", w.Code, w.Body)
	}
	if len(x.delivered) != 0 {
		t.Fatalf("%d delivered from pushes that proved nothing", len(x.delivered))
	}
	if len(x.refusals) != 4 {
		t.Errorf("refusals counted: %q", x.refusals)
	}

	// And a stream with no digest kept takes nothing, not even an empty
	// bearer matching it.
	x.p.Stream = func() (Connected, error) { return Connected{Receiver: receiver(t, k)}, nil }
	if w := x.send(t, "", "application/secevent+jwt", good); w.Code != http.StatusUnauthorized {
		t.Errorf("a stream with no bearer kept answered %d", w.Code)
	}
}

// A token that fails verification is refused with its own RFC 8935 code.
func TestAForgedPushIsRefusedWithItsCode(t *testing.T) {
	k, other := newKey(t), newKey(t)
	x := newPush(t, k)
	w := x.send(t, pushSecret, "application/secevent+jwt", other.sign(t, nil, revoked()))
	if w.Code != http.StatusBadRequest || errCode(t, w) != "invalid_key" || len(x.delivered) != 0 {
		t.Errorf("signed by another key: %d %s", w.Code, w.Body)
	}
}

// The same event sent twice is accepted twice and delivered once.
func TestAReplayedEventIsAcceptedAndActedOnOnce(t *testing.T) {
	k := newKey(t)
	x := newPush(t, k)
	tok := k.sign(t, nil, revoked())
	for i := 0; i < 3; i++ {
		if w := x.send(t, pushSecret, "application/secevent+jwt", tok); w.Code != http.StatusAccepted {
			t.Fatalf("delivery %d: %d %s", i, w.Code, w.Body)
		}
	}
	if len(x.delivered) != 1 {
		t.Errorf("delivered %d times", len(x.delivered))
	}
}

// An event whose action failed is asked for again, and the retry is acted
// on rather than refused as a replay.
func TestAnEventThatCouldNotBeActedOnIsTakenAgain(t *testing.T) {
	k := newKey(t)
	x := newPush(t, k)
	tok := k.sign(t, nil, revoked())
	x.fail = errors.New("the policy could not be written")
	if w := x.send(t, pushSecret, "application/secevent+jwt", tok); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("a failed action: %d %s", w.Code, w.Body)
	}
	x.fail = nil
	if w := x.send(t, pushSecret, "application/secevent+jwt", tok); w.Code != http.StatusAccepted || len(x.delivered) != 1 {
		t.Fatalf("the retry: %d, delivered %d", w.Code, len(x.delivered))
	}
}

// About two a second, in a burst of a minute's worth; then told to wait.
func TestPushesAreHeldToAMinutesRate(t *testing.T) {
	k := newKey(t)
	x := newPush(t, k)
	for i := 0; i < PushRate; i++ {
		if w := x.send(t, "", "application/secevent+jwt", ""); w.Code == http.StatusTooManyRequests {
			t.Fatalf("refused for rate at %d", i)
		}
	}
	w := x.send(t, pushSecret, "application/secevent+jwt", k.sign(t, nil, revoked()))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("past the rate: %d", w.Code)
	}
	if len(x.delivered) != 0 {
		t.Error("a delivery past the rate was acted on")
	}
}

// Only POST, and nothing at all while no stream is connected.
func TestOnlyAConnectedStreamIsPushedTo(t *testing.T) {
	k := newKey(t)
	x := newPush(t, k)
	req := httptest.NewRequest(http.MethodGet, "/sso/signals", nil)
	w := httptest.NewRecorder()
	x.p.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
	x.p.Stream = func() (Connected, error) { return Connected{}, nil }
	if w := x.send(t, pushSecret, "application/secevent+jwt", k.sign(t, nil, revoked())); w.Code != http.StatusNotFound || len(x.delivered) != 0 {
		t.Errorf("with nothing connected: %d", w.Code)
	}
}
