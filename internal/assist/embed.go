// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

// Embeddings, from an endpoint that serves OpenAI's /embeddings: OpenAI,
// Mistral, Gemini's compatible endpoint, Ollama, vLLM, and most others.
//
// A text's vector is only comparable with vectors from the same model, so
// the caller keeps the model's name beside every vector (internal/vector)
// and never mixes two. Anthropic serves no embeddings.

// Limits on one request for embeddings.
const (
	// MaxEmbedBatch is how many texts go in one request: fewer than any
	// provider's own limit.
	MaxEmbedBatch = 64
	// MaxEmbedText is the longest text sent, in bytes: a passage is
	// shorter, and a longer text would be cut by the provider anyway.
	MaxEmbedText = 8000
	// MaxEmbedDims is the most dimensions a vector may have.
	MaxEmbedDims = 8192
)

// Embed asks for one vector for each text, in order, and says what it used.
func (h *HTTPModel) Embed(ctx context.Context, texts []string) ([][]float64, Usage, error) {
	if h.Wire == WireAnthropic {
		return nil, Usage{}, fmt.Errorf("%s answers in words and serves no embeddings", h.Model)
	}
	if len(texts) == 0 || len(texts) > MaxEmbedBatch {
		return nil, Usage{}, fmt.Errorf("a request for embeddings carries 1 to %d texts", MaxEmbedBatch)
	}
	chars := 0
	for _, t := range texts {
		if strings.TrimSpace(t) == "" {
			return nil, Usage{}, errors.New("an empty text has no embedding")
		}
		if len(t) > MaxEmbedText {
			return nil, Usage{}, fmt.Errorf("a text for embedding is at most %d bytes", MaxEmbedText)
		}
		chars += len(t)
	}
	b, err := json.Marshal(map[string]any{"model": h.Model, "input": texts})
	if err != nil {
		return nil, Usage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/embeddings", bytes.NewReader(b))
	if err != nil {
		return nil, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := h.prepare(req); err != nil {
		return nil, Usage{}, err
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, Usage{}, fmt.Errorf("embedding request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, 4<<10))
		return nil, Usage{}, &StatusError{Code: resp.StatusCode, Body: clip300(strings.TrimSpace(buf.String()))}
	}
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Usage *struct {
			Prompt int `json:"prompt_tokens"`
			Total  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, Usage{}, fmt.Errorf("cannot read the embeddings: %w", err)
	}
	if len(out.Data) != len(texts) {
		return nil, Usage{}, fmt.Errorf("asked for %d embeddings and got %d", len(texts), len(out.Data))
	}
	vecs := make([][]float64, len(texts))
	dims := 0
	for _, d := range out.Data {
		if d.Index < 0 || d.Index >= len(texts) || vecs[d.Index] != nil {
			return nil, Usage{}, errors.New("the embeddings are not one for each text")
		}
		if len(d.Embedding) == 0 || len(d.Embedding) > MaxEmbedDims || (dims != 0 && len(d.Embedding) != dims) {
			return nil, Usage{}, fmt.Errorf("an embedding of %d dimensions, among others of %d", len(d.Embedding), dims)
		}
		dims = len(d.Embedding)
		for _, x := range d.Embedding {
			if math.IsNaN(x) || math.IsInf(x, 0) {
				return nil, Usage{}, errors.New("an embedding is not a vector of numbers")
			}
		}
		vecs[d.Index] = d.Embedding
	}
	u := Usage{In: (chars + 3) / 4}
	if out.Usage != nil {
		n := out.Usage.Prompt
		if n == 0 {
			n = out.Usage.Total
		}
		if n > 0 {
			u = Usage{In: n, Reported: true}
		}
	}
	return vecs, u, nil
}
