// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
)

// scribe is a route's model that transcribes, or fails with err.
type scribe struct {
	name  string
	err   error
	calls int
}

func (s *scribe) Name() string { return s.name }
func (s *scribe) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("asked for words")
}
func (s *scribe) Transcribe(context.Context, []byte, string, string) (string, assist.Usage, error) {
	s.calls++
	if s.err != nil {
		return "", assist.Usage{}, s.err
	}
	return "WEBVTT\n\n00:00.000 --> 00:01.000\nhello\n", assist.Usage{Out: 4}, nil
}

func scribeRig(t *testing.T, cfg Config, models map[string]Model) *Gateway {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLedger(t.TempDir()+"/usage.jsonl", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, func(r Route) (Model, error) { return models[r.Name], nil }, l)
}

// A recording goes only to a route that transcribes and may be sent
// personal data, in their order, charged by the minute; words never go to
// a route that transcribes.
func TestARecordingGoesOnlyWhereItMay(t *testing.T) {
	cfg := Config{Currency: "USD", Routes: []Route{
		{Name: "words", URL: "https://api.example/v1", Model: "big", KeyEnv: "K"},
		{Name: "hosted", URL: "https://api.example/v1", Model: "whisper-hosted", KeyEnv: "K", Transcribes: true},
		{Name: "down", URL: "http://localhost:9000/v1", Model: "whisper-a", Transcribes: true, Personal: true},
		{Name: "here", URL: "http://localhost:9001/v1", Model: "whisper-b", Transcribes: true, Personal: true, PriceMinute: "0.006"},
	}}
	hosted, down, here := &scribe{name: "hosted"}, &scribe{name: "down", err: &assist.StatusError{Code: http.StatusServiceUnavailable}}, &scribe{name: "here"}
	words := &answering{name: "words"}
	g := scribeRig(t, cfg, map[string]Model{"words": words, "hosted": hosted, "down": down, "here": here})
	vtt, model, cost, err := g.Transcribe(context.Background(), []string{"media", "person:dana"}, []byte("x"), "a.wav", "en", 150)
	if err != nil || model != "whisper-b" || vtt == "" {
		t.Fatalf("%q %q %v", vtt, model, err)
	}
	if hosted.calls != 0 {
		t.Error("a recording went to a route not allowed personal data")
	}
	if down.calls != 1 || here.calls != 1 {
		t.Errorf("down %d, here %d", down.calls, here.calls)
	}
	if cost.String() != "0.015" {
		t.Errorf("two and a half minutes at 0.006 cost %s", cost.String())
	}
	if out, err := g.For("assist").Complete(context.Background(), "s", "u"); err != nil || out != "answer from words" {
		t.Fatalf("%q %v", out, err)
	}
	if hosted.calls+down.calls+here.calls != 2 {
		t.Error("a route that transcribes was asked for words")
	}
}

// With no route allowed personal data, a recording goes nowhere, and why
// is said; a price a minute belongs to a route that transcribes.
func TestARecordingWithNowhereToGoIsRefused(t *testing.T) {
	cfg := Config{Routes: []Route{{Name: "hosted", URL: "https://api.example/v1", Model: "w", KeyEnv: "K", Transcribes: true}}}
	hosted := &scribe{name: "hosted"}
	g := scribeRig(t, cfg, map[string]Model{"hosted": hosted})
	if _, _, _, err := g.Transcribe(context.Background(), []string{"media"}, []byte("x"), "a.wav", "", 10); !errors.Is(err, ErrRecordingNotAllowed) || hosted.calls != 0 {
		t.Fatalf("%v", err)
	}
	none := scribeRig(t, Config{}, nil)
	if _, _, _, err := none.Transcribe(context.Background(), []string{"media"}, []byte("x"), "a.wav", "", 10); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("%v", err)
	}
	for _, bad := range []Route{
		{Name: "w", URL: "https://api.example/v1", Model: "m", KeyEnv: "K", PriceMinute: "0.01"},
		{Name: "w", URL: "https://api.example/v1", Model: "m", KeyEnv: "K", Transcribes: true, Draws: true},
	} {
		if (Config{Currency: "USD", Routes: []Route{bad}}).Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (Route{Name: "w", Transcribes: true}).CheckWire(WireAnthropic) == nil {
		t.Error("a route to Anthropic that transcribes")
	}
}
