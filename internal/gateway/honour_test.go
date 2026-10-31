// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/modelapi"
)

const citySchema = `{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}`

// chatRig is a gateway over conversation models, with a ledger.
func chatRig(t *testing.T, routes []Route, models map[string]*chatty) *Gateway {
	t.Helper()
	c := &clock{time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	l, err := OpenLedger(filepath.Join(t.TempDir(), "usage.jsonl"), c.t)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Routes: routes}, func(r Route) (Model, error) { return models[r.Name], nil }, l).WithClock(c.now)
}

func said(text string) assist.ChatReply {
	return assist.ChatReply{Message: assist.ChatMessage{Role: "assistant", Content: []assist.Part{{Type: "text", Text: text}}},
		Finish: "stop"}
}

func called(names ...string) assist.ChatReply {
	m := assist.ChatMessage{Role: "assistant"}
	for i, n := range names {
		m.ToolCalls = append(m.ToolCalls, assist.ToolCall{ID: string(rune('a' + i)), Type: "function",
			Function: assist.FunctionCall{Name: n, Arguments: "{}"}})
	}
	return assist.ChatReply{Message: m, Finish: "tool_calls"}
}

func rested(g *Gateway, route string) bool {
	for _, h := range g.Health() {
		if h.Route.Name == route {
			return h.Resting || h.Failures > 0
		}
	}
	return false
}

// A request asking for a format, or for how hard to think, goes only to a
// route declared to honour it. A route that is not is passed over, never
// tried as a last resort, and when none is, the request is refused with
// nothing sent and nothing rested.
func TestARouteThatCannotHonourARequestIsPassedOver(t *testing.T) {
	thinker := &chatty{name: "thinker", reply: said(`{"city":"Paris"}`)}
	shaper := &chatty{name: "shaper", reply: said(`{"city":"Paris"}`)}
	g := chatRig(t, []Route{
		{Name: "thinker", Model: "x", Params: RouteParams{ReasoningEffort: true}},
		{Name: "shaper", Model: "y", Params: RouteParams{StructuredOutput: true}},
	}, map[string]*chatty{"thinker": thinker, "shaper": shaper})
	chat := g.For("door:dana").(*bound)

	req := talk("the weather in Paris", 0)
	req.ResponseFormat = &assist.ResponseFormat{Type: "json_object"}
	if _, err := chat.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(thinker.got) != 0 || len(shaper.got) != 1 || shaper.got[0].ResponseFormat == nil {
		t.Fatalf("a format went to thinker %d times and shaper %d", len(thinker.got), len(shaper.got))
	}

	req = talk("think hard", 0)
	req.ReasoningEffort = "high"
	if _, err := chat.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(thinker.got) != 1 || thinker.got[0].ReasoningEffort != "high" || len(shaper.got) != 1 {
		t.Fatalf("an effort went to thinker %d times and shaper %d", len(thinker.got), len(shaper.got)-1)
	}

	req.ResponseFormat = &assist.ResponseFormat{Type: "json_object"}
	_, err := chat.Chat(context.Background(), req)
	if !errors.Is(err, assist.ErrCannotHonour) || errors.Is(err, ErrNoRoute) ||
		!strings.Contains(err.Error(), "thinker: it is not declared to honour a response format") ||
		!strings.Contains(err.Error(), "shaper: it is not declared to take a reasoning effort") {
		t.Fatalf("a request no route can honour: %v", err)
	}
	if _, err := g.ForRoute("thinker", "reviewer:x").(*bound).Chat(context.Background(), talkWithFormat()); !errors.Is(err, assist.ErrCannotHonour) {
		t.Fatalf("a pinned route that cannot honour a format: %v", err)
	}
	if len(thinker.got) != 1 || len(shaper.got) != 1 || rested(g, "thinker") || rested(g, "shaper") {
		t.Errorf("a request nothing could honour was sent or rested a route: thinker %d, shaper %d", len(thinker.got), len(shaper.got))
	}
}

func talkWithFormat() assist.ChatRequest {
	req := talk("x", 0)
	req.ResponseFormat = &assist.ResponseFormat{Type: "json_object"}
	return req
}

// An answer that is not what the request asked for goes back as an error,
// never as an answer: it is not asked again of the next route at the
// caller's expense, it does not rest the route that gave it, and it is
// charged, since the call was made.
func TestAnAnswerNotAsAskedIsAnErrorThatRestsNothing(t *testing.T) {
	hosted := &chatty{name: "hosted", reply: said(`{"town":"Paris"}`)}
	local := &chatty{name: "local", reply: said(`{"city":"Paris"}`)}
	routes := []Route{{Name: "hosted", Model: "x", Params: RouteParams{StructuredOutput: true}},
		{Name: "local", Model: "y", Params: RouteParams{StructuredOutput: true}}}
	g := chatRig(t, routes, map[string]*chatty{"hosted": hosted, "local": local})
	req := talk("the weather in Paris", 0)
	req.ResponseFormat = &assist.ResponseFormat{Type: "json_schema", Name: "weather", Schema: json.RawMessage(citySchema), Strict: true}
	for i := 0; i <= FailuresBeforeCooldown; i++ {
		r, err := g.For("door:dana").(*bound).Chat(context.Background(), req)
		if !errors.Is(err, assist.ErrNotHonoured) || !strings.Contains(err.Error(), "does not fit its schema") || r.Message.Text() != "" {
			t.Fatalf("an answer that does not fit its strict schema came back as %q, %v", r.Message.Text(), err)
		}
	}
	if len(local.got) != 0 || len(hosted.got) != FailuresBeforeCooldown+1 || rested(g, "hosted") {
		t.Errorf("hosted asked %d times, local %d, hosted rested %v", len(hosted.got), len(local.got), rested(g, "hosted"))
	}
	sum := g.ledger.Summary(Config{Routes: routes}, g.now())
	if len(sum) != 1 || sum[0].Failed != FailuresBeforeCooldown+1 || sum[0].Calls != 0 || sum[0].Chars == 0 {
		t.Errorf("answers not as asked were not on the ledger as failed and charged: %+v", sum)
	}

	hosted.reply = said(`{"city":"Paris"}`)
	if r, err := g.For("door:dana").(*bound).Chat(context.Background(), req); err != nil || r.Message.Text() != `{"city":"Paris"}` {
		t.Errorf("an answer that fits: %q %v", r.Message.Text(), err)
	}
}

// A route sent "auto" where the caller forced or named a tool is held to
// what the caller asked on what comes back: another tool, or none, is an
// error that rests nothing and is not asked of the next route.
func TestARouteSentAutoIsHeldToTheToolTheCallerNamed(t *testing.T) {
	auto := &chatty{name: "auto"}
	next := &chatty{name: "next", reply: called("click")}
	g := chatRig(t, []Route{{Name: "auto", Model: "x", Params: RouteParams{AutoToolChoice: true}}, {Name: "next", Model: "y"}},
		map[string]*chatty{"auto": auto, "next": next})
	req := talk("press it", 0)
	req.Tools = append(req.Tools, assist.ChatTool{Type: "function", Function: assist.ToolFunction{Name: "type"}})
	req.ToolChoice, req.ToolChoiceName = "required", "click"
	for _, reply := range []assist.ChatReply{called("type"), said("I would rather not"), called("click", "type")} {
		auto.reply = reply
		if _, err := g.For("agent:x").(*bound).Chat(context.Background(), req); !errors.Is(err, assist.ErrNotHonoured) {
			t.Errorf("%+v came back as %v", reply.Message, err)
		}
	}
	req.ToolChoiceName = ""
	auto.reply = said("done")
	if _, err := g.For("agent:x").(*bound).Chat(context.Background(), req); !errors.Is(err, assist.ErrNotHonoured) {
		t.Errorf("words where a call was required: %v", err)
	}
	if len(next.got) != 0 || rested(g, "auto") {
		t.Errorf("next asked %d times, auto rested %v", len(next.got), rested(g, "auto"))
	}
	req.ToolChoiceName = "click"
	auto.reply = called("click")
	if r, err := g.For("agent:x").(*bound).Chat(context.Background(), req); err != nil || r.Message.ToolCalls[0].Function.Name != "click" {
		t.Errorf("the named tool: %+v %v", r, err)
	}
}

// The model configured without the gateway has nobody to say what it can
// honour, so a format is refused there; what comes back is held to the
// request as it is through a route.
func TestTheModelWithoutTheGatewayIsHeldToo(t *testing.T) {
	m := &chatty{name: "only", reply: called("click")}
	g := Guarded{Model: m, Personal: true}
	if _, err := g.Chat(context.Background(), talkWithFormat()); !errors.Is(err, assist.ErrCannotHonour) {
		t.Errorf("a format: %v", err)
	}
	req := talk("hi", 0)
	req.ReasoningEffort = "low"
	if _, err := g.Chat(context.Background(), req); !errors.Is(err, assist.ErrCannotHonour) || len(m.got) != 0 {
		t.Errorf("an effort: %v, sent %d", err, len(m.got))
	}
	req = talk("hi", 0)
	req.ToolChoice = "none"
	if _, err := g.Chat(context.Background(), req); !errors.Is(err, assist.ErrNotHonoured) {
		t.Errorf("a call where none was allowed: %v", err)
	}
	req = talk("hi", 0)
	req.Stop = []string{"END"}
	m.reply = said("Paris END and more")
	if r, err := g.Chat(context.Background(), req); err != nil || r.Message.Text() != "Paris " {
		t.Errorf("a stop sequence: %q %v", r.Message.Text(), err)
	}
	if m.got[len(m.got)-1].Stop[0] != "END" {
		t.Error("the stop sequence was not sent")
	}
}

// What each shape asks of the answer reaches the route: read by the door,
// carried through the gateway, and held to on what comes back.
func TestWhatEachShapeAsksReachesTheRoute(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		shape  string
		read   func(io.Reader) (modelapi.Request, error)
		body   string
		stop   []string
		strict bool
	}{
		{"chat completions", modelapi.ReadOpenAI, `{"model":"quilzo","messages":[{"role":"user","content":"weather?"}],
			"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],"parallel_tool_calls":false,
			"response_format":{"type":"json_schema","json_schema":{"name":"weather","strict":true,"schema":` + citySchema + `}},
			"stop":["END"],"temperature":0.2,"top_p":0.9,"reasoning_effort":"high"}`, []string{"END"}, true},
		{"responses", modelapi.ReadResponses, `{"model":"quilzo","input":"weather?",
			"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],"parallel_tool_calls":false,
			"text":{"format":{"type":"json_schema","name":"weather","strict":true,"schema":` + citySchema + `}},
			"temperature":0.2,"top_p":0.9,"reasoning":{"effort":"high"}}`, nil, true},
		{"messages", modelapi.ReadAnthropic, `{"model":"quilzo","max_tokens":100,"messages":[{"role":"user","content":"weather?"}],
			"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"tool_choice":{"type":"auto","disable_parallel_tool_use":true},
			"output_config":{"format":{"type":"json_schema","schema":` + citySchema + `},"effort":"high"},
			"stop_sequences":["END"],"temperature":0.2,"top_p":0.9}`, []string{"END"}, true},
	} {
		in, err := c.read(strings.NewReader(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.shape, err)
		}
		m := &chatty{name: "able", reply: said(`{"city":"Paris"}`)}
		g := chatRig(t, []Route{{Name: "able", Model: "x", Params: RouteParams{StructuredOutput: true, ReasoningEffort: true}}},
			map[string]*chatty{"able": m})
		if _, err := g.For("door:dana").(*bound).Chat(context.Background(), in.Chat); err != nil {
			t.Fatalf("%s: %v", c.shape, err)
		}
		got := m.got[0]
		rf := got.ResponseFormat
		if rf == nil || rf.Type != "json_schema" || rf.Strict != c.strict || !strings.Contains(string(rf.Schema), `"city"`) {
			t.Errorf("%s: the format reached the route as %+v", c.shape, rf)
		}
		if strings.Join(got.Stop, "|") != strings.Join(c.stop, "|") || got.ReasoningEffort != "high" || !got.OneToolCall ||
			got.Temperature == nil || *got.Temperature != *f(0.2) || got.TopP == nil || *got.TopP != *f(0.9) {
			t.Errorf("%s: the route was sent stop %q, effort %q, one call %v, temperature %v, top_p %v",
				c.shape, got.Stop, got.ReasoningEffort, got.OneToolCall, got.Temperature, got.TopP)
		}
		m.reply = said(`{"city":"Paris","country":"France"}`)
		if _, err := g.For("door:dana").(*bound).Chat(context.Background(), in.Chat); !errors.Is(err, assist.ErrNotHonoured) {
			t.Errorf("%s: an answer outside its schema came back as %v", c.shape, err)
		}
	}
}
