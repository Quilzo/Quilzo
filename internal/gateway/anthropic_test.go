// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
)

// A request a model's safeguards decline goes back to the caller as
// declined. It rests nothing, since the route is well, and it is not sent
// on to the next route: routing round a provider's safeguard to whichever
// route has fewer is not a fallback.
func TestADeclinedRequestIsNotSentRoundTheSafeguard(t *testing.T) {
	hosted := &answering{name: "hosted", err: &assist.Declined{Model: "big", Category: "cyber"}}
	local := &answering{name: "local"}
	g, _ := rigWith(t, two, map[string]*answering{"hosted": hosted, "local": local})
	for i := 0; i <= FailuresBeforeCooldown; i++ {
		_, err := g.For("door:dana").Complete(context.Background(), "s", "u")
		var d *assist.Declined
		if !errors.As(err, &d) || d.Category != "cyber" {
			t.Fatalf("err = %v", err)
		}
	}
	if local.calls != 0 {
		t.Error("a declined request was sent on to the next route")
	}
	if hosted.calls != FailuresBeforeCooldown+1 {
		t.Error("declined requests put the route to rest")
	}
	if got := g.ledger.Summary(two, g.now()); len(got) != 1 || got[0].Failed != FailuresBeforeCooldown+1 || got[0].Chars == 0 {
		t.Errorf("declined calls were not counted: %+v", got)
	}
}

// What a route sends is checked against the protocol its provider speaks,
// where the route is made: a field the model refuses would fail every
// call through it.
func TestARoutesFieldsAreCheckedAgainstItsProtocol(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		params RouteParams
		draws  bool
		wire   string
		why    string
	}{
		{RouteParams{Effort: "high"}, false, WireOpenAI, "Anthropic"},
		{RouteParams{Geo: "us"}, false, "", "Anthropic"},
		{RouteParams{Fallback: true}, false, WireOpenAI, "Anthropic"},
		{RouteParams{Temperature: f(0.2)}, false, WireAnthropic, "temperature"},
		{RouteParams{TopP: f(0.9)}, false, WireAnthropic, "temperature"},
		{RouteParams{MaxTokens: "max_completion_tokens"}, false, WireAnthropic, "max_tokens"},
		{RouteParams{}, true, WireAnthropic, "draw"},
		{RouteParams{}, false, "carrier-pigeon", "does not"},
	} {
		r := Route{Name: "r", Params: c.params, Draws: c.draws}
		if err := r.CheckWire(c.wire); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%+v on %q: %v", c.params, c.wire, err)
		}
	}
	good := Route{Name: "r", Params: RouteParams{Effort: "xhigh", Geo: "us", Fallback: true, Timeout: "600s"}}
	if err := good.CheckWire(WireAnthropic); err != nil {
		t.Fatal(err)
	}
	if err := (Route{Name: "r", Params: RouteParams{Temperature: f(0.2)}}).CheckWire(WireOpenAI); err != nil {
		t.Fatal(err)
	}
	if got := good.Params.String(); got != "600s a call, effort xhigh, runs in the US, server fallback" {
		t.Errorf("String() = %q", got)
	}
	p, _ := good.Params.Model()
	if p.Effort != "xhigh" || p.Geo != "us" || !p.Fallback {
		t.Errorf("Model() = %+v", p)
	}
	for _, bad := range []RouteParams{{Effort: "huge"}, {Geo: "eu"}} {
		if bad.Check() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// A route with only an address speaks OpenAI's chat completions, which
	// the declaration itself can check.
	r := two.Routes[0]
	r.Params = RouteParams{Effort: "low"}
	if err := (Config{Routes: []Route{r}}).Validate(); err == nil || !strings.Contains(err.Error(), "Anthropic") {
		t.Errorf("a route with an address and an effort was accepted: %v", err)
	}
}
