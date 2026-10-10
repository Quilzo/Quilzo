// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentmodel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
)

func browserSession(caps ...string) *agent.Session {
	return agent.NewSession(agent.Manifest{
		Name: "buyer", Kind: agent.KindTask, Purpose: "test",
		Capabilities: caps, Autonomy: agent.AutonomyDraft,
		Browser: &agent.Browser{Read: []string{"docs.example.com"}, Write: []string{"shop.example.com"},
			Credentials: []agent.BrowserCredential{{Secret: "shop", Host: "shop.example.com"}}},
		Budget: agent.Budget{Steps: 10, Tools: 1, Duration: agent.Duration(time.Minute)},
	}, nil)
}

// A model holding the browser is told how each of its actions takes its
// input, which hosts it may open and which credentials it may use; one
// that does not hold it is told nothing about it.
func TestTheModelIsToldHowToUseItsBrowser(t *testing.T) {
	m := &fakeModel{reply: `{"op":"browser_open","input":{"url":"https://docs.example.com/"}}`}
	a, err := Decider{Model: m, Session: browserSession("browser_open", "browser_click", "browser_sign_in")}.Decide()(
		context.Background(), "order paper", nil)
	if err != nil || a.Op != "browser_open" || a.Input["url"] != "https://docs.example.com/" {
		t.Fatalf("%+v %v", a, err)
	}
	for _, want := range []string{`"ref": "e5"`, "docs.example.com, shop.example.com", "shop (on shop.example.com)",
		"never see the password", "waits for a person"} {
		if !strings.Contains(m.system, want) {
			t.Errorf("the prompt does not say %q:\n%s", want, m.system)
		}
	}
	if strings.Contains(m.system, "browser_type") {
		t.Error("an action it does not hold is described")
	}
	plain := &fakeModel{reply: `{"op":"done","say":"x"}`}
	_, _ = decide(t, plain, "read_page")(context.Background(), "x", nil)
	if strings.Contains(plain.system, "browser") {
		t.Error("a model without a browser was told about one")
	}
}

// The page the next action is chosen on is shown whole; a page already
// left is cut short.
func TestThePageNowIsShownWhole(t *testing.T) {
	long := strings.Repeat("[e1] button \"Add to basket\"\n", 400)
	p := userPrompt("x", []agent.Observation{
		{From: "browser_open", Body: "OLD " + long},
		{From: "browser_click", Body: "NOW " + long},
	})
	old := p[strings.Index(p, "OLD"):strings.Index(p, "NOW")]
	now := p[strings.Index(p, "NOW"):]
	if len(old) > MaxEarlierPage+200 || len(now) < 10000 {
		t.Errorf("the page left was %d bytes and the page now %d", len(old), len(now))
	}
	if p := userPrompt("x", []agent.Observation{{From: "read_page", Body: long}}); len(p) > MaxObservation+500 {
		t.Errorf("a stored page was shown at %d bytes", len(p))
	}
}

// chatModel takes a conversation and records it.
type chatModel struct {
	fakeModel
	req assist.ChatRequest
}

func (c *chatModel) Chat(_ context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
	c.req = req
	return assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
		Content: []assist.Part{{Type: "text", Text: `{"op":"browser_read"}`}}}}, nil
}

// A picture the agent asked for goes to the model with the next decision,
// and only to one that takes pictures.
func TestAPictureGoesWithTheNextDecision(t *testing.T) {
	m := &chatModel{}
	pics := [][]byte{[]byte("\x89PNG")}
	a, err := Decider{Model: m, Session: browserSession("browser_read", "browser_look"), Pictures: func() [][]byte {
		out := pics
		pics = nil
		return out
	}}.Decide()(context.Background(), "x", nil)
	if err != nil || a.Op != "browser_read" {
		t.Fatalf("%+v %v", a, err)
	}
	if m.req.Images() != 1 || m.calls != 0 {
		t.Errorf("%d pictures sent, %d text calls", m.req.Images(), m.calls)
	}
	text := &fakeModel{}
	_, err = Decider{Model: text, Session: browserSession("browser_look"),
		Pictures: func() [][]byte { return [][]byte{[]byte("x")} }}.Decide()(context.Background(), "x", nil)
	if err == nil || !strings.Contains(err.Error(), "reads text only") {
		t.Errorf("a picture went to a text model: %v", err)
	}
}
