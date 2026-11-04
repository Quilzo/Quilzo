// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
)

// embedding is a route's model that makes embeddings, or fails with err.
type embedding struct {
	name  string
	err   error
	calls int
	sent  []string
}

func (e *embedding) Name() string { return e.name }
func (e *embedding) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("asked for words")
}
func (e *embedding) Embed(_ context.Context, texts []string) ([][]float64, assist.Usage, error) {
	e.calls++
	e.sent = append(e.sent, texts...)
	if e.err != nil {
		return nil, assist.Usage{}, e.err
	}
	out := make([][]float64, len(texts))
	for i := range texts {
		out[i] = []float64{1, float64(i)}
	}
	return out, assist.Usage{In: 2000000, Reported: true}, nil
}

var withEmbeddings = Config{Currency: "USD", Routes: []Route{
	{Name: "words", URL: "https://api.example/v1", Model: "big", KeyEnv: "WORDS_KEY"},
	{Name: "vectors", URL: "https://api.example/v1", Model: "embed-small", KeyEnv: "WORDS_KEY", Embeds: true, PriceIn: "0.02"},
	{Name: "vectors-too", URL: "https://api.example/v1", Model: "embed-large", KeyEnv: "WORDS_KEY", Embeds: true},
}}

func embedRig(t *testing.T, models map[string]Model) *Gateway {
	t.Helper()
	l, err := OpenLedger(filepath.Join(t.TempDir(), "usage.jsonl"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return New(withEmbeddings, func(r Route) (Model, error) { return models[r.Name], nil }, l)
}

// Embeddings go through the route named and no other, masked, charged and
// counted; a route that makes embeddings is never asked for words, and a
// route that answers in words is never asked for embeddings.
func TestEmbeddingsGoThroughTheRouteNamed(t *testing.T) {
	words := &answering{name: "words"}
	vectors, too := &embedding{name: "vectors"}, &embedding{name: "vectors-too"}
	g := embedRig(t, map[string]Model{"words": words, "vectors": vectors, "vectors-too": too})
	if g.EmbeddingModel("vectors") != "embed-small" || g.EmbeddingModel("words") != "" || g.EmbeddingModel("nope") != "" {
		t.Fatal("the embedding model of a route")
	}
	vecs, err := g.Embed(context.Background(), "vectors", []string{"embed:help"},
		[]string{"write to dana@inkmail.net about returns", "delivery"})
	if err != nil || len(vecs) != 2 {
		t.Fatalf("%v %v", vecs, err)
	}
	if too.calls != 0 || words.calls != 0 {
		t.Error("another route was asked")
	}
	if strings.Contains(strings.Join(vectors.sent, " "), "dana@inkmail.net") {
		t.Errorf("personal data left for a route not allowed it: %q", vectors.sent)
	}
	sum := g.ledger.Summary(withEmbeddings, g.now())
	if len(sum) != 1 || sum[0].Consumer != "embed:help" || sum[0].Calls != 1 || sum[0].Tokens != 2000000 || sum[0].Cost.String() != "0.04" {
		t.Errorf("%+v", sum)
	}
	if out, err := g.For("chatbot:help").Complete(context.Background(), "s", "u"); err != nil || out != "answer from words" {
		t.Fatalf("%q %v", out, err)
	}
	if vectors.calls != 1 || too.calls != 0 {
		t.Error("a route that makes embeddings was asked for words")
	}
	if _, err := g.Embed(context.Background(), "words", []string{"embed:help"}, []string{"x"}); !errors.Is(err, ErrNoRoute) {
		t.Errorf("a route of words was asked for embeddings: %v", err)
	}
}

// EmbedCosted says what an embedding used and cost, the same figures the
// ledger charged, for a caller that keeps a budget of its own: an agent's
// run, whose chatbot questions were embedded where its budget could not
// see them.
func TestAnEmbeddingSaysWhatItCost(t *testing.T) {
	vectors := &embedding{name: "vectors"}
	g := embedRig(t, map[string]Model{"vectors": vectors})
	vecs, used, cost, err := g.EmbedCosted(context.Background(), "vectors",
		[]string{"chatbot:help", "person:dana"}, []string{"returns"})
	if err != nil || len(vecs) != 1 {
		t.Fatalf("%v %v", vecs, err)
	}
	if used.In != 2000000 || Money(cost).String() != "0.04" {
		t.Errorf("an embedding of 2000000 tokens at 0.02 a million said it used %d and cost %s",
			used.In, Money(cost))
	}
	for _, sum := range g.ledger.Summary(withEmbeddings, g.now()) {
		if sum.Cost != Money(cost) {
			t.Errorf("%s was charged %s and the call said %s", sum.Consumer, sum.Cost, Money(cost))
		}
	}
	if _, used, cost, err := g.EmbedCosted(context.Background(), "nope", []string{"chatbot:help"},
		[]string{"x"}); err == nil || used.In != 0 || cost != 0 {
		t.Errorf("an embedding that was not made said it used %d and cost %d: %v", used.In, cost, err)
	}
}

// A route that fails is not stood in for by another: vectors from two
// models are not comparable, so the caller does without.
func TestAFailingEmbeddingRouteHasNoFallback(t *testing.T) {
	vectors := &embedding{name: "vectors", err: &assist.StatusError{Code: http.StatusServiceUnavailable}}
	too := &embedding{name: "vectors-too"}
	g := embedRig(t, map[string]Model{"vectors": vectors, "vectors-too": too})
	for i := 0; i < FailuresBeforeCooldown+1; i++ {
		if _, err := g.Embed(context.Background(), "vectors", []string{"chatbot:help"}, []string{"x"}); err == nil {
			t.Fatal("a failing route answered")
		}
	}
	if too.calls != 0 {
		t.Error("another model's embeddings stood in")
	}
	if vectors.calls != FailuresBeforeCooldown {
		t.Errorf("the failing route was not rested: %d calls", vectors.calls)
	}
}

// A route draws pictures or makes embeddings, not both; Anthropic makes
// neither.
func TestAnEmbeddingRouteIsChecked(t *testing.T) {
	r := withEmbeddings.Routes[1]
	r.Draws = true
	if (Config{Currency: "USD", Routes: []Route{r}}).Validate() == nil {
		t.Error("a route that draws and embeds")
	}
	if err := (Route{Name: "e", Embeds: true}).CheckWire(WireAnthropic); err == nil {
		t.Error("an embedding route to Anthropic")
	}
}
