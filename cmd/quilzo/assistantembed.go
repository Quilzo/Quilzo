// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/vector"
)

// Chatbots that find passages by what they mean (chatbot.embeddings).
//
// The admin server embeds the passages, after each publish and when asked
// (quilzo assistant embed), and keeps their vectors (vector.Store). The
// public site reads them, and embeds a visitor's question as it is asked.
// Only a chatbot whose answers a model already writes takes part: one that
// quotes its pages promises nothing is sent anywhere, and one kept to one
// route promises its visitors' words go to no other.

func embeddingsDir(root string) string { return filepath.Join(root, "embeddings") }

func embeddingStore(root string) vector.Store { return vector.Store{Dir: embeddingsDir(root)} }

// embeddingRoute is the route chatbot.embeddings names and the model it
// embeds with, when there is such a route.
func embeddingRoute(root string) (*gateway.Gateway, string, string) {
	route := strings.TrimSpace(mustConfig(root).Raw("chatbot.embeddings"))
	if route == "" {
		return nil, "", ""
	}
	gw, _, err := modelGateway(root)
	if err != nil || gw == nil {
		return nil, "", ""
	}
	model := gw.EmbeddingModel(route)
	if model == "" {
		return nil, "", ""
	}
	return gw, route, model
}

// meansWithModel reports whether a chatbot takes part.
func meansWithModel(a assistant.Assistant) bool { return a.UseModel && !a.RouteOnly }

// embedText is what of a passage is embedded: what it is ranked by.
func embedText(p assistant.Passage) string {
	t := p.Header() + "\n" + p.Text
	if len(t) > assist.MaxEmbedText {
		t = t[:assist.MaxEmbedText]
	}
	return t
}

// chatbotMeaning is the ranker by meaning for a chatbot's passages, or
// nil when it does not take part.
func chatbotMeaning(root string, a assistant.Assistant, passages []assistant.Passage) *assistant.Meaning {
	if !meansWithModel(a) {
		return nil
	}
	gw, route, model := embeddingRoute(root)
	if gw == nil {
		return nil
	}
	st := embeddingStore(root)
	vecs := make([][]float64, len(passages))
	for i, p := range passages {
		vecs[i], _ = st.Get(model, embedText(p))
	}
	floor := mustConfig(root).Int("chatbot.embeddings_floor")
	return &assistant.Meaning{Model: model, Vectors: vecs, Floor: float64(floor) / 100,
		Question: func(q string) ([]float64, error) {
			if len(q) > assist.MaxEmbedText {
				q = q[:assist.MaxEmbedText]
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, err := gw.Embed(ctx, route, []string{"chatbot:" + a.Name}, []string{q})
			if err != nil {
				return nil, err
			}
			return out[0], nil
		}}
}

// meaningKey is what a cached index by meaning depends on beyond the
// passages: the route, its model, the floor, and when vectors were last
// kept, so an index built before its passages were embedded is rebuilt
// once they are.
func meaningKey(root string, a assistant.Assistant) string {
	if !meansWithModel(a) {
		return ""
	}
	_, route, model := embeddingRoute(root)
	if model == "" {
		return ""
	}
	return route + "|" + model + "|" + mustConfig(root).Raw("chatbot.embeddings_floor") + "|" +
		embeddingStore(root).Stamp(model).Format(time.RFC3339Nano)
}

// withMeaning is an index with its ranker by meaning, when it has one.
func withMeaning(root string, a assistant.Assistant, idx *assistant.Index) *assistant.Index {
	if idx == nil {
		return nil
	}
	return idx.WithMeaning(chatbotMeaning(root, a, idx.Passages))
}

// embedReport is what one embedding found and did.
type embedReport struct {
	Model             string
	Passages, Already int
	Embedded          int
	Chatbots          []string
}

// embedChatbots embeds the passages of every chatbot that takes part (or
// the one named) that are not embedded yet.
func embedChatbots(ctx context.Context, root, only string) (embedReport, error) {
	var rep embedReport
	gw, route, model := embeddingRoute(root)
	if gw == nil {
		return rep, fmt.Errorf("chatbot.embeddings names no route that makes embeddings " +
			"(quilzo gateway route add NAME --embeds ..., then quilzo config set chatbot.embeddings NAME)")
	}
	rep.Model = model
	set, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return rep, err
	}
	st := embeddingStore(root)
	seen := map[string]bool{}
	for _, a := range set.Assistants {
		if (only != "" && a.Name != only) || !meansWithModel(a) {
			continue
		}
		idx, err := assistantIndex(root, a)
		if err != nil {
			return rep, err
		}
		rep.Chatbots = append(rep.Chatbots, a.Name)
		var todo []string
		for _, p := range idx.Passages {
			t := embedText(p)
			if seen[t] {
				continue
			}
			seen[t] = true
			rep.Passages++
			if _, ok := st.Get(model, t); ok {
				rep.Already++
				continue
			}
			todo = append(todo, t)
		}
		for len(todo) > 0 {
			n := min(len(todo), assist.MaxEmbedBatch)
			batch := todo[:n]
			todo = todo[n:]
			vecs, err := gw.Embed(ctx, route, []string{"embed:" + a.Name}, batch)
			if err != nil {
				if rep.Embedded > 0 {
					_ = st.Touch(model, time.Now())
				}
				return rep, err
			}
			for i, v := range vecs {
				if err := st.Put(model, batch[i], v); err != nil {
					return rep, err
				}
				rep.Embedded++
			}
		}
	}
	if only != "" && len(rep.Chatbots) == 0 {
		return rep, fmt.Errorf("%s does not take part: a chatbot that answers with a model, "+
			"and is not kept to one route, does", only)
	}
	if rep.Embedded > 0 {
		if err := st.Touch(model, time.Now()); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// embedAfterPublish embeds what a publish made new, when chatbots find
// passages by meaning.
func embedAfterPublish(ctx context.Context, root string) string {
	if strings.TrimSpace(mustConfig(root).Raw("chatbot.embeddings")) == "" {
		return ""
	}
	rep, err := embedChatbots(ctx, root, "")
	record(root, audit.Record{Action: "assistant.embedded", Resource: "/ask", Outcome: embedOutcome(err),
		Principal: "quilzo", Kind: audit.KindService, Verified: true,
		Detail: map[string]string{"model": rep.Model, "embedded": strconv.Itoa(rep.Embedded),
			"passages": strconv.Itoa(rep.Passages)}})
	switch {
	case err != nil:
		return "embeddings: " + err.Error()
	case rep.Embedded > 0:
		return fmt.Sprintf("%s embedded for chatbots to find by meaning", plural2(rep.Embedded, "a passage", "passages"))
	}
	return ""
}

// assistantEmbed is quilzo assistant embed [NAME].
func assistantEmbed(root string, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: quilzo assistant embed [NAME]")
	}
	only := ""
	if len(args) == 1 {
		only = args[0]
	}
	caller := resolveCaller(root, flagToken)
	// It spends money, and sends the published site to a provider an
	// administrator chose: whoever may change the gateway may run it.
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rep, err := embedChatbots(ctx, root, only)
	record(root, caller.auditRecord("assistant.embedded", "/ask", embedOutcome(err),
		map[string]string{"model": rep.Model, "embedded": strconv.Itoa(rep.Embedded),
			"passages": strconv.Itoa(rep.Passages)}))
	if err != nil {
		return err
	}
	if w.JSON(rep) {
		return nil
	}
	if len(rep.Chatbots) == 0 {
		w.Human("  %sno chatbot takes part: one that answers with a model, and is not kept to one route, does%s\n", dim, reset)
		return nil
	}
	w.Human("  %s%d of %d passages embedded now, %d already%s  (%s, for %s)\n", green, rep.Embedded, rep.Passages,
		rep.Already, reset, rep.Model, strings.Join(rep.Chatbots, ", "))
	return nil
}

func embedOutcome(err error) audit.Outcome {
	if err != nil {
		return audit.Failure
	}
	return audit.Success
}
