// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
)

// artist is a model that draws, and says what it was asked.
type artist struct {
	fake
	asked []string
}

func (a *artist) Paint(_ context.Context, prompt, _ string) (assist.Picture, error) {
	a.asked = append(a.asked, prompt)
	if a.fail {
		return assist.Picture{}, errors.New("down")
	}
	return assist.Picture{Body: []byte("png"), Prompt: prompt}, nil
}

// A picture goes through the routes that draw, and words never do: under
// the same budgets, with personal data and credentials taken out of the
// prompt, charged by the picture, and in the ledger.
func TestPicturesGoThroughTheGateway(t *testing.T) {
	cfg := Config{Currency: "USD", Routes: []Route{
		{Name: "words", URL: "https://api.example/v1", Model: "big", KeyEnv: "K"},
		{Name: "pictures", URL: "https://img.example/v1", Model: "gpt-image-2", KeyEnv: "K", Draws: true, PricePicture: "0.04"},
	}, Budgets: []Budget{{Consumer: "media", PerMinute: 1}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	words := &fake{name: "words"}
	painter := &artist{fake: fake{name: "pictures"}}
	path := t.TempDir() + "/usage.jsonl"
	c := &clock{time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	l, err := OpenLedger(path, c.t)
	if err != nil {
		t.Fatal(err)
	}
	g := New(cfg, func(r Route) (Model, error) {
		if r.Name == "pictures" {
			return painter, nil
		}
		return words, nil
	}, l).WithClock(c.now)

	pic, cost, err := g.Paint(context.Background(), []string{"media", "person:dana"},
		"a portrait for dana@hartsbakery.co.uk, key AKIAIOSFODNN7EXAMPLE", "1024x1024")
	if err != nil || string(pic.Body) != "png" || cost != 40000 {
		t.Fatalf("%+v %d %v", pic, cost, err)
	}
	if got := painter.asked[0]; strings.Contains(got, "dana@hartsbakery.co.uk") || strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("the prompt left with %q", got)
	}
	// Words never go to the route that draws.
	if out, err := g.For("chatbot:help").Complete(context.Background(), "s", "u"); err != nil || out != "answer from words" {
		t.Fatalf("%q %v", out, err)
	}
	if painter.calls != 0 {
		t.Fatal("a route that draws was asked for words")
	}
	// The budget holds for pictures: one a minute.
	if _, _, err := g.Paint(context.Background(), []string{"media"}, "a second", ""); !errors.Is(err, ErrBudget) {
		t.Fatalf("a second picture inside the minute: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"route":"pictures"`) || !strings.Contains(string(b), `"consumer":"media"`) {
		t.Fatalf("the ledger: %s", b)
	}

	// No route that draws: said, not attempted elsewhere.
	g2 := New(Config{Routes: []Route{{Name: "words", URL: "https://api.example/v1", Model: "m", KeyEnv: "K"}}},
		func(Route) (Model, error) { return words, nil }, nil)
	if g2.Draws() {
		t.Fatal("a gateway with no route that draws says it draws")
	}
	if _, _, err := g2.Paint(context.Background(), []string{"media"}, "x", ""); !errors.Is(err, ErrNoRoute) ||
		!strings.Contains(err.Error(), "--draws") {
		t.Fatalf("%v", err)
	}
	// A price that is not an amount is refused when the route is declared.
	bad := Config{Currency: "USD", Routes: []Route{{Name: "p", URL: "https://img.example/v1", Model: "m",
		KeyEnv: "K", Draws: true, PricePicture: "four cents"}}}
	if bad.Validate() == nil {
		t.Fatal("a price that is not an amount was accepted")
	}
}

// censoring is a painter whose provider refuses what it is asked to draw.
type censoring struct {
	fake
	calls int
}

func (r *censoring) Paint(context.Context, string, string) (assist.Picture, error) {
	r.calls++
	return assist.Picture{}, &assist.StatusError{Code: 400, Body: "moderation_blocked"}
}

// A picture the provider refuses to draw goes back to whoever asked, as it
// was refused: it is not sent to the next route that draws, and it rests
// nothing. A route asking for the bytes must be one that draws.
func TestARefusedPictureGoesBack(t *testing.T) {
	cfg := Config{Routes: []Route{
		{Name: "strict", URL: "https://img.example/v1", Model: "painter", KeyEnv: "K", Draws: true},
		{Name: "lenient", URL: "https://img2.example/v1", Model: "painter", KeyEnv: "K", Draws: true,
			Params: RouteParams{AskBase64: true}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	strict, lenient := &censoring{fake: fake{name: "strict"}}, &artist{fake: fake{name: "lenient"}}
	l, err := OpenLedger(t.TempDir()+"/usage.jsonl", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g := New(cfg, func(r Route) (Model, error) {
		if r.Name == "strict" {
			return strict, nil
		}
		return lenient, nil
	}, l)
	for i := 0; i <= FailuresBeforeCooldown; i++ {
		_, _, err := g.Paint(context.Background(), []string{"media"}, "something it will not draw", "1024x1024")
		var se *assist.StatusError
		if !errors.As(err, &se) || se.Code != 400 {
			t.Fatalf("%v", err)
		}
	}
	if len(lenient.asked) != 0 || strict.calls != FailuresBeforeCooldown+1 {
		t.Errorf("a refused picture was sent on, or rested its route: %d %d", len(lenient.asked), strict.calls)
	}
	if p, _ := cfg.Routes[1].Params.Model(); !p.AskBase64 || cfg.Routes[1].Params.String() != "asks for base64" {
		t.Errorf("%+v", cfg.Routes[1].Params)
	}
	words := Config{Routes: []Route{{Name: "w", URL: "https://api.example/v1", Model: "m", KeyEnv: "K",
		Params: RouteParams{AskBase64: true}}}}
	if err := words.Validate(); err == nil || !strings.Contains(err.Error(), "does not draw") {
		t.Errorf("a route of words asking for a picture's bytes: %v", err)
	}
}
