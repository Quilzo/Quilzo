// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
)

// voice is a route's model that reads text aloud, and says what it read.
type voice struct {
	name string
	read []string
}

func (v *voice) Name() string { return v.name }
func (v *voice) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("asked for words")
}
func (v *voice) Speak(_ context.Context, text, _ string) ([]byte, assist.Usage, error) {
	v.read = append(v.read, text)
	return []byte("ID3..."), assist.Usage{In: len(text) / 4}, nil
}

// Text goes to a route that speaks, charged; text holding personal data
// is never read by a route not allowed it, since a voice cannot leave it
// out, and goes to one that is; with none, why is said.
func TestTextIsReadOnlyWhereItsPersonalDataMayGo(t *testing.T) {
	cfg := Config{Routes: []Route{
		{Name: "words", URL: "https://api.example/v1", Model: "big", KeyEnv: "K"},
		{Name: "hosted", URL: "https://api.example/v1", Model: "tts-hosted", KeyEnv: "K", Speaks: true},
		{Name: "here", URL: "http://localhost:8880/v1", Model: "kokoro", Speaks: true, Personal: true},
	}}
	hosted, here := &voice{name: "hosted"}, &voice{name: "here"}
	words := &answering{name: "words"}
	g := scribeRig(t, cfg, map[string]Model{"words": words, "hosted": hosted, "here": here})

	_, model, _, err := g.Speak(context.Background(), []string{"media"}, "Welcome to the shop.", "alloy")
	if err != nil || model != "tts-hosted" || len(hosted.read) != 1 {
		t.Fatalf("%q %v", model, err)
	}
	_, model, _, err = g.Speak(context.Background(), []string{"media"}, "Write to dana@inkmail.net for a refund.", "alloy")
	if err != nil || model != "kokoro" || len(hosted.read) != 1 || !strings.Contains(here.read[0], "dana@inkmail.net") {
		t.Fatalf("%q %v %q", model, err, hosted.read)
	}

	only := Config{Routes: []Route{{Name: "hosted", URL: "https://api.example/v1", Model: "tts", KeyEnv: "K", Speaks: true}}}
	h2 := &voice{name: "hosted"}
	g2 := scribeRig(t, only, map[string]Model{"hosted": h2})
	if _, _, _, err := g2.Speak(context.Background(), []string{"media"}, "Call dana@inkmail.net.", "alloy"); err == nil ||
		!strings.Contains(err.Error(), "a voice cannot leave out") || len(h2.read) != 0 {
		t.Fatalf("%v %q", err, h2.read)
	}
	if out, err := g.For("assist").Complete(context.Background(), "s", "u"); err != nil || out != "answer from words" {
		t.Fatalf("%q %v", out, err)
	}
	if len(hosted.read)+len(here.read) != 2 {
		t.Error("a route that speaks was asked for words")
	}
	if (Route{Name: "s", Speaks: true}).CheckWire(WireAnthropic) == nil {
		t.Error("a route to Anthropic that speaks")
	}
	if (Config{Routes: []Route{{Name: "s", URL: "https://a.example/v1", Model: "m", KeyEnv: "K", Speaks: true, Draws: true}}}).Validate() == nil {
		t.Error("a route that speaks and draws")
	}
}
