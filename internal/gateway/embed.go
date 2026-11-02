// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/pii"
)

// Embeddings through the gateway: the same budgets, ledger, privacy guard
// and shield as words, through a route that makes embeddings and nothing
// else (Route.Embeds).
//
// One route, named, and no fallback. Vectors from two models are not
// comparable, so a passage embedded by one route and a question by
// another would be ranked by a number that means nothing. When the named
// route cannot answer, the caller does without (a chatbot ranks by words
// alone) rather than asking another route.

// embedder is a model that makes embeddings.
type embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float64, assist.Usage, error)
}

// EmbeddingModel is the model a route makes embeddings with, which is
// stored beside every vector it makes; "" when there is no such route.
func (g *Gateway) EmbeddingModel(route string) string {
	for _, r := range g.cfg.Routes {
		if r.Name == route && r.Embeds {
			return r.Model
		}
	}
	return ""
}

// Embed turns texts into vectors through the route named, charged to the
// consumers each against its budget.
func (g *Gateway) Embed(ctx context.Context, route string, consumers []string, texts []string) ([][]float64, error) {
	if len(consumers) == 0 {
		return nil, errors.New("an embedding is charged to somebody")
	}
	var r *Route
	for i := range g.cfg.Routes {
		if g.cfg.Routes[i].Name == route {
			r = &g.cfg.Routes[i]
		}
	}
	if r == nil || !r.Embeds {
		return nil, fmt.Errorf("%w: %s is not a route that makes embeddings (quilzo gateway route add NAME --embeds ...)",
			ErrNoRoute, route)
	}
	consumer, also := consumers[0], consumers[1:]
	in := 0
	for _, t := range texts {
		in += len(t)
	}
	if err := g.admit(consumers, in); err != nil {
		g.note(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil && !errors.Is(err, ErrUnwritable) {
			g.OnTrouble("spent", consumer)
		}
		return nil, err
	}
	g.mu.Lock()
	down := g.now().Before(g.downTil[r.Name])
	g.mu.Unlock()
	if down {
		return nil, fmt.Errorf("%w: %s: resting after repeated failures", ErrNoRoute, r.Name)
	}
	if g.Cut != nil && g.Cut(r.Name) {
		return nil, fmt.Errorf("%w: %s: cut by the shield", ErrNoRoute, r.Name)
	}
	m, err := g.model(*r)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoRoute, r.Name, err)
	}
	em, ok := m.(embedder)
	if !ok {
		return nil, fmt.Errorf("%w: %s: its model makes no embeddings", ErrNoRoute, r.Name)
	}
	// What may not leave for this route is replaced first. Nothing comes
	// back to put it back into: a vector of a placeholder is as near the
	// question as the vector of what it replaced, near enough.
	mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: codescan.SecretSpans}
	sent := make([]string, len(texts))
	hidden := 0
	for i, t := range texts {
		_, v, h := visible("", t)
		sent[i] = mask.Mask(v, r.Personal)
		hidden += h
	}
	masked := mask.Masked()
	if hidden > 0 {
		masked["invisible"] = hidden
	}
	if len(masked) > 0 && g.OnMasked != nil {
		g.OnMasked(consumer, r.Name, masked)
	}
	start := g.now()
	vecs, used, err := em.Embed(ctx, sent)
	took := g.now().Sub(start)
	if err != nil {
		kind := g.failure(ctx, r.Name, err)
		g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
			Model: r.Model, In: in, Millis: took.Milliseconds(), Outcome: kind.outcome()})
		return nil, err
	}
	g.mu.Lock()
	g.fails[r.Name] = 0
	g.mu.Unlock()
	pin, _, _ := r.prices()
	cost := costOf(pin, 0, used.In, 0)
	g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name, Model: r.Model, In: in,
		Millis: took.Milliseconds(), TokensIn: used.In, Estimated: !used.Reported, Cost: cost,
		Masked: masked, Outcome: "ok"})
	return vecs, nil
}
