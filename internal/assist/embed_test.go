// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func embedAt(t *testing.T, answer string) (*HTTPModel, chan map[string]any) {
	t.Helper()
	seen := make(chan map[string]any, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" || r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("%s %v", r.URL.Path, r.Header)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen <- body
		w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	return &HTTPModel{BaseURL: srv.URL + "/v1", APIKey: "k", Model: "embed-small", Client: srv.Client()}, seen
}

// Texts go to /embeddings, and come back one vector each, in their order
// whatever order the provider wrote them in, with what the call used.
func TestTextsAreEmbeddedInTheirOrder(t *testing.T) {
	m, seen := embedAt(t, `{"data":[{"index":1,"embedding":[0,1]},{"index":0,"embedding":[1,0]}],"usage":{"prompt_tokens":7,"total_tokens":7}}`)
	vecs, u, err := m.Embed(context.Background(), []string{"returns", "delivery"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 2 || vecs[0][0] != 1 || vecs[1][1] != 1 || u != (Usage{In: 7, Reported: true}) {
		t.Fatalf("%v %+v", vecs, u)
	}
	body := <-seen
	if body["model"] != "embed-small" || len(body["input"].([]any)) != 2 {
		t.Errorf("%v", body)
	}
}

// What is not one vector of numbers for each text is refused, whole.
func TestEmbeddingsThatDoNotFitAreRefused(t *testing.T) {
	for name, answer := range map[string]string{
		"too few":         `{"data":[{"index":0,"embedding":[1,0]}]}`,
		"twice":           `{"data":[{"index":0,"embedding":[1,0]},{"index":0,"embedding":[0,1]}]}`,
		"out of range":    `{"data":[{"index":0,"embedding":[1,0]},{"index":5,"embedding":[0,1]}]}`,
		"different sizes": `{"data":[{"index":0,"embedding":[1,0]},{"index":1,"embedding":[0,1,0]}]}`,
		"empty":           `{"data":[{"index":0,"embedding":[]},{"index":1,"embedding":[]}]}`,
	} {
		m, _ := embedAt(t, answer)
		if _, _, err := m.Embed(context.Background(), []string{"a", "b"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	m, seen := embedAt(t, `{}`)
	for name, texts := range map[string][]string{
		"nothing": nil, "blank": {" "}, "too long": {strings.Repeat("x", MaxEmbedText+1)},
		"too many": make([]string, MaxEmbedBatch+1),
	} {
		if _, _, err := m.Embed(context.Background(), texts); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if len(seen) != 0 {
		t.Error("a refused request was sent")
	}
	m.Wire = WireAnthropic
	if _, _, err := m.Embed(context.Background(), []string{"a"}); err == nil {
		t.Error("Anthropic was asked for embeddings")
	}
}

// A provider's refusal is a StatusError, as for words.
func TestAnEmbeddingErrorIsAStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	m := &HTTPModel{BaseURL: srv.URL, APIKey: "k", Model: "e", Client: srv.Client()}
	_, _, err := m.Embed(context.Background(), []string{"a"})
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusTooManyRequests {
		t.Fatalf("%v", err)
	}
}
