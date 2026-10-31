// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	r, cost, err := b.g.chat(ctx, b.consumers, b.pick, req)
	return r, int64(cost), err
}

// Chat sends a conversation through the gateway.
// TakesPictures reports whether a picture could go anywhere from here:
// some route is marked personal, the only kind a picture is sent to.
func (b *bound) TakesPictures() bool {
	for _, r := range b.g.cfg.Routes {
		if r.Personal {
			return true
		}
	}
	return false
}

func (b *bound) Chat(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
	r, _, err := b.g.chat(ctx, b.consumers, b.pick, req)
	return r, err
}

func (g *Gateway) chat(ctx context.Context, consumers []string, p pick, req assist.ChatRequest) (assist.ChatReply, Money, error) {
	if err := req.Check(); err != nil {
		return assist.ChatReply{}, 0, err
	}
	consumer, also := consumers[0], consumers[1:]
	in := req.TextLen() + req.Images()*imageChars
	if err := g.admit(consumers, in); err != nil {
		g.note(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil && !errors.Is(err, ErrUnwritable) {
			g.OnTrouble("spent", consumer)
		}
		return assist.ChatReply{}, 0, err
	}
	if len(g.cfg.Routes) == 0 {
		return assist.ChatReply{}, 0, ErrNoRoute
	}
	var errs []string
	able := 0
	for _, r := range g.routesFor(p) {
		// A route that cannot honour what the request asks is passed over,
		// and is not tried as a last resort: its answer would ignore what
		// the caller asked for.
		if why := r.Params.cannot(req); why != "" {
			errs = append(errs, r.Name+": "+why)
			continue
		}
		able++
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
		if !r.Params.StructuredOutput {
			sent.Tools = loose(sent.Tools)
		}
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
			kind := g.failure(ctx, r.Name, err)
			g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
				Model: r.Model, In: in, Millis: took.Milliseconds(), Outcome: kind.outcome()})
			if kind != unavailable {
				return assist.ChatReply{}, 0, err
			}
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		g.mu.Lock()
		g.fails[r.Name] = 0
		g.mu.Unlock()
		pin, pout, _ := r.prices()
		cost := costOf(pin, pout, reply.Usage.In, reply.Usage.Out)
		// The route answered, so it is not rested; an answer that is not
		// what the request asked for goes back as an error, and is not
		// asked again of the next route at the caller's expense.
		reply, err = req.Honour(reply)
		outcome := "ok"
		if err != nil {
			outcome = "failed"
		}
		g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
			Model: r.Model, In: in, Out: len(reply.Message.Text()), Millis: took.Milliseconds(),
			TokensIn: reply.Usage.In, TokensOut: reply.Usage.Out, Estimated: !reply.Usage.Reported,
			Cost: cost, Masked: masked, Outcome: outcome})
		if err != nil {
			return assist.ChatReply{}, cost, err
		}
		return reply, cost, nil
	}
	if p.only != "" && len(errs) == 0 {
		return assist.ChatReply{}, 0, fmt.Errorf("%w: the route %s is not declared", ErrNoRoute, p.only)
	}
	if able == 0 {
		return assist.ChatReply{}, 0, fmt.Errorf("%w: %s", assist.ErrCannotHonour, strings.Join(errs, "; "))
	}
	return assist.ChatReply{}, 0, fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
}

// loose is the tools as a model not declared to honour structured output
// is sent them: without strict, which such a server may refuse, or take
// and ignore. A call to a strict tool is held to its parameters all the
// same, on what comes back (assist.ChatRequest.Honour).
func loose(tools []assist.ChatTool) []assist.ChatTool {
	if len(tools) == 0 {
		return tools
	}
	out := make([]assist.ChatTool, len(tools))
	for i, t := range tools {
		t.Function.Strict = false
		out[i] = t
	}
	return out
}

// maskChat is the conversation as it may leave for a route: invisible
// characters out of every text, and what may not leave replaced, in the
// messages' text, in the arguments of tool calls already made, and in
// what the answer is asked to be.
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
		if m.Refusal != "" {
			c.Refusal = clean(m.Refusal)
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
	// A format leaves with its description and every string in its schema
	// cleaned, since an enumeration of customers' names is still their
	// names; the answer comes back with what was masked put back, and is
	// held to the schema as the caller wrote it.
	if f := req.ResponseFormat; f != nil {
		sentFormat := *f
		sentFormat.Description = clean(f.Description)
		sentFormat.Schema = cleanStrings(f.Schema, clean)
		out.ResponseFormat = &sentFormat
	}
	// A stop sequence the guard would change is not sent at all, since
	// changed it would stop the model at something else: the answer is cut
	// at it on its way back instead (assist.ChatRequest.Honour), where what
	// was masked is back.
	out.Stop = nil
	for _, s := range req.Stop {
		if clean(s) == s {
			out.Stop = append(out.Stop, s)
		}
	}
	return out, hidden
}

// cleanStrings is a JSON document with every string in it that is not a
// key passed through clean, and everything else as it was, in the order it
// was: a model writes an object's properties in the order its schema
// gives them. A document that cannot be read leaves as nothing.
func cleanStrings(doc json.RawMessage, clean func(string) string) json.RawMessage {
	if len(doc) == 0 {
		return doc
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var out bytes.Buffer
	// Each open object or list, and how many tokens are in it so far: in
	// an object every other one is a key.
	type open struct {
		object bool
		n      int
	}
	var stack []open
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			out.WriteRune(rune(d))
			continue
		}
		key := false
		if len(stack) > 0 {
			o := &stack[len(stack)-1]
			switch {
			case o.object && o.n%2 == 1:
				out.WriteByte(':')
			case o.n > 0:
				out.WriteByte(',')
			}
			key = o.object && o.n%2 == 0
			o.n++
		}
		switch x := tok.(type) {
		case json.Delim:
			out.WriteRune(rune(x))
			stack = append(stack, open{object: x == '{'})
			continue
		case string:
			if !key {
				tok = clean(x)
			}
		}
		b, err := json.Marshal(tok)
		if err != nil {
			return nil
		}
		out.Write(b)
	}
	return out.Bytes()
}

// restoreChat puts back what was masked, in what the model said, or
// declined to say, and in the arguments of the tools it chose.
func restoreChat(r assist.ChatReply, mask *pii.Masker) assist.ChatReply {
	parts := make([]assist.Part, len(r.Message.Content))
	for i, p := range r.Message.Content {
		if p.Type == "text" {
			p.Text = mask.Restore(p.Text)
		}
		parts[i] = p
	}
	r.Message.Content = parts
	r.Message.Refusal = mask.Restore(r.Message.Refusal)
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
// configures without the gateway's routes. That model has nobody to say
// what it can honour, as a route's administrator does, so a request that
// needs a route to say so is refused here.
func (g Guarded) Chat(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
	if err := req.Check(); err != nil {
		return assist.ChatReply{}, err
	}
	if why := (RouteParams{}).cannot(req); why != "" {
		return assist.ChatReply{}, fmt.Errorf("%w: the model configured without the gateway: %s; "+
			"declare it as a gateway route that does", assist.ErrCannotHonour, why)
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
	sent.Tools = loose(sent.Tools)
	reply, err := cm.Chat(ctx, sent)
	counts := mask.Masked()
	if hidden > 0 {
		counts["invisible"] = hidden
	}
	if len(counts) > 0 && g.OnMasked != nil {
		g.OnMasked(counts)
	}
	reply = restoreChat(reply, mask)
	if err != nil {
		return reply, err
	}
	return req.Honour(reply)
}
