// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/pii"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// A whole conversation through the gateway: the same budgets, routes,
// fallbacks, ledger and privacy guard as Complete, for a conversation that
// carries pictures and offers tools (see internal/assist/chat.go).
//
// Text is masked as it is for Complete: what may not leave for a route is
// replaced before the conversation does, and put back in what the model
// says, tool calls' arguments included. A picture cannot be checked for
// what it shows, so it goes only to a route allowed personal data. A
// screenshot of a customer's record is exactly what masking exists for,
// and sending it unread to a route that may not see such things would be
// the guard waving it through.

// imageChars is what one picture counts for against a budget of characters:
// about what a screen costs in tokens, at four characters a token.
const imageChars = 6000

// ErrPictureNotAllowed is a conversation with pictures for a route that may
// not receive personal data.
var ErrPictureNotAllowed = errors.New("a picture cannot be checked for personal data, " +
	"so it goes only to a route allowed personal data")

// ChatCosted is Chat with what the call cost, in millionths of the
// configuration's currency.
func (b *bound) ChatCosted(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, int64, error) {
	r, cost, err := b.g.chat(ctx, b.consumers, req)
	return r, int64(cost), err
}

// Chat sends a conversation through the gateway.
func (b *bound) Chat(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
	r, _, err := b.g.chat(ctx, b.consumers, req)
	return r, err
}

func (g *Gateway) chat(ctx context.Context, consumers []string, req assist.ChatRequest) (assist.ChatReply, Money, error) {
	if err := req.Check(); err != nil {
		return assist.ChatReply{}, 0, err
	}
	consumer, also := consumers[0], consumers[1:]
	in := req.TextLen() + req.Images()*imageChars
	if err := g.admit(consumers, in); err != nil {
		g.ledger.record(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil {
			g.OnTrouble("spent", consumer)
		}
		return assist.ChatReply{}, 0, err
	}
	if len(g.cfg.Routes) == 0 {
		return assist.ChatReply{}, 0, ErrNoRoute
	}
	var errs []string
	for _, r := range g.cfg.Routes {
		g.mu.Lock()
		down := g.now().Before(g.downTil[r.Name])
		g.mu.Unlock()
		switch {
		case down:
			errs = append(errs, r.Name+": resting after repeated failures")
			continue
		case g.Cut != nil && g.Cut(r.Name):
			errs = append(errs, r.Name+": cut by the shield")
			continue
		case req.Images() > 0 && !r.Personal:
			errs = append(errs, r.Name+": "+ErrPictureNotAllowed.Error())
			continue
		}
		m, err := g.model(r)
		if err != nil {
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		cm, ok := m.(assist.Chatter)
		if !ok {
			errs = append(errs, r.Name+": its model takes a prompt, not a conversation")
			continue
		}
		start := g.now()
		mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: codescan.SecretSpans}
		sent, hidden := maskChat(req, mask, r.Personal)
		reply, err := cm.Chat(ctx, sent)
		reply = restoreChat(reply, mask)
		masked := mask.Masked()
		if hidden > 0 {
			masked["invisible"] = hidden
		}
		if len(masked) > 0 && g.OnMasked != nil {
			g.OnMasked(consumer, r.Name, masked)
		}
		took := g.now().Sub(start)
		if err != nil {
			if kind := Trouble(err); kind != "" && g.OnTrouble != nil {
				g.OnTrouble(kind, r.Name)
			}
			g.failed(r.Name)
			g.ledger.record(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
				Model: r.Model, In: in, Millis: took.Milliseconds(), Outcome: "failed"})
			errs = append(errs, r.Name+": "+err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		g.mu.Lock()
		g.fails[r.Name] = 0
		g.mu.Unlock()
		pin, pout, _ := r.prices()
		cost := costOf(pin, pout, reply.Usage.In, reply.Usage.Out)
		g.ledger.record(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
			Model: r.Model, In: in, Out: len(reply.Message.Text()), Millis: took.Milliseconds(),
			TokensIn: reply.Usage.In, TokensOut: reply.Usage.Out, Estimated: !reply.Usage.Reported,
			Cost: cost, Masked: masked, Outcome: "ok"})
		return reply, cost, nil
	}
	return assist.ChatReply{}, 0, fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
}

// maskChat is the conversation as it may leave for a route: invisible
// characters out of every text, and what may not leave replaced, in the
// messages' text and in the arguments of tool calls already made.
func maskChat(req assist.ChatRequest, mask *pii.Masker, personal bool) (assist.ChatRequest, int) {
	hidden := 0
	clean := func(s string) string {
		v, n := plaintext.Visible(s)
		hidden += n
		return mask.Mask(v, personal)
	}
	out := req
	out.Messages = make([]assist.ChatMessage, len(req.Messages))
	for i, m := range req.Messages {
		c := m
		c.Content = make([]assist.Part, len(m.Content))
		for j, p := range m.Content {
			if p.Type == "text" {
				p.Text = clean(p.Text)
			}
			c.Content[j] = p
		}
		c.ToolCalls = make([]assist.ToolCall, len(m.ToolCalls))
		for j, tc := range m.ToolCalls {
			tc.Function.Arguments = clean(tc.Function.Arguments)
			c.ToolCalls[j] = tc
		}
		if len(m.ToolCalls) == 0 {
			c.ToolCalls = nil
		}
		out.Messages[i] = c
	}
	return out, hidden
}

// restoreChat puts back what was masked, in what the model said and in the
// arguments of the tools it chose.
func restoreChat(r assist.ChatReply, mask *pii.Masker) assist.ChatReply {
	parts := make([]assist.Part, len(r.Message.Content))
	for i, p := range r.Message.Content {
		if p.Type == "text" {
			p.Text = mask.Restore(p.Text)
		}
		parts[i] = p
	}
	r.Message.Content = parts
	if len(r.Message.ToolCalls) > 0 {
		calls := make([]assist.ToolCall, len(r.Message.ToolCalls))
		for i, tc := range r.Message.ToolCalls {
			tc.Function.Arguments = mask.Restore(tc.Function.Arguments)
			calls[i] = tc
		}
		r.Message.ToolCalls = calls
	}
	return r
}

// Chat is a conversation through the guard, for the single model an install
// configures without the gateway's routes.
func (g Guarded) Chat(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
	if err := req.Check(); err != nil {
		return assist.ChatReply{}, err
	}
	if req.Images() > 0 && !g.Personal {
		return assist.ChatReply{}, ErrPictureNotAllowed
	}
	cm, ok := g.Model.(assist.Chatter)
	if !ok {
		return assist.ChatReply{}, fmt.Errorf("%s takes a prompt, not a conversation", g.Model.Name())
	}
	mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: codescan.SecretSpans}
	sent, hidden := maskChat(req, mask, g.Personal)
	reply, err := cm.Chat(ctx, sent)
	counts := mask.Masked()
	if hidden > 0 {
		counts["invisible"] = hidden
	}
	if len(counts) > 0 && g.OnMasked != nil {
		g.OnMasked(counts)
	}
	return restoreChat(reply, mask), err
}
