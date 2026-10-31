// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
)

// answering is a route's model that fails with err when it is set.
type answering struct {
	name  string
	err   error
	calls int
}

func (a *answering) Name() string { return a.name }
func (a *answering) Complete(ctx context.Context, _, _ string) (string, error) {
	a.calls++
	if a.err != nil {
		return "", a.err
	}
	return "answer from " + a.name, nil
}

func rigWith(t *testing.T, cfg Config, models map[string]*answering) (*Gateway, *clock) {
	t.Helper()
	c := &clock{time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	l, err := OpenLedger(filepath.Join(t.TempDir(), "usage.jsonl"), c.t)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, func(r Route) (Model, error) { return models[r.Name], nil }, l).WithClock(c.now), c
}

func status(code int, body string) error { return &assist.StatusError{Code: code, Body: body} }

// A request the provider refuses as malformed goes back to the caller as
// it was refused. It is not sent to the other routes, which would refuse
// it alike, and it does not put the route to rest for everybody else.
func TestARequestEveryRouteWouldRefuseGoesBackAndRestsNothing(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		hosted := &answering{name: "hosted", err: status(code, "temperature is not supported")}
		local := &answering{name: "local"}
		g, _ := rigWith(t, two, map[string]*answering{"hosted": hosted, "local": local})
		for i := 0; i <= FailuresBeforeCooldown; i++ {
			_, err := g.For("door:dana").Complete(context.Background(), "s", "u")
			var se *assist.StatusError
			if !errors.As(err, &se) || se.Code != code {
				t.Fatalf("%d: err = %v", code, err)
			}
		}
		if local.calls != 0 {
			t.Errorf("%d: a refused request was sent on to the next route", code)
		}
		if hosted.calls != FailuresBeforeCooldown+1 {
			t.Errorf("%d: refused requests put the route to rest", code)
		}
		sum := g.ledger.Summary(two, g.now())
		if len(sum) != 1 || sum[0].Failed != FailuresBeforeCooldown+1 || sum[0].Chars == 0 {
			t.Errorf("%d: refused calls were not counted against the caller: %+v", code, sum)
		}
	}
}

// The route's own trouble still moves the call on and rests the route:
// a timeout, a rate limit, an outage, a key or an account refused, and a
// 400 that says the account is out of credit.
func TestARouteThatCannotAnswerStillFallsOver(t *testing.T) {
	for _, err := range []error{
		status(http.StatusTooManyRequests, "rate limited"),
		status(http.StatusServiceUnavailable, "overloaded"),
		status(http.StatusRequestTimeout, "timeout"),
		status(http.StatusUnauthorized, "invalid api key"),
		status(http.StatusPaymentRequired, "pay"),
		status(http.StatusNotFound, "no such model"),
		status(http.StatusBadRequest, "You have reached your specified API usage limits"),
		errors.New("dial tcp: connection refused"),
	} {
		hosted := &answering{name: "hosted", err: err}
		local := &answering{name: "local"}
		g, _ := rigWith(t, two, map[string]*answering{"hosted": hosted, "local": local})
		for i := 0; i <= FailuresBeforeCooldown; i++ {
			if out, err := g.For("assist").Complete(context.Background(), "s", "u"); err != nil || out != "answer from local" {
				t.Fatalf("%v: no fallback: %q %v", hosted.err, out, err)
			}
		}
		if hosted.calls != FailuresBeforeCooldown {
			t.Errorf("%v: the route was not rested after %d failures (%d calls)", hosted.err, FailuresBeforeCooldown, hosted.calls)
		}
	}
}

// A caller going away says nothing about the route.
func TestACallerGivingUpRestsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hosted := &answering{name: "hosted", err: context.Canceled}
	local := &answering{name: "local"}
	g, _ := rigWith(t, two, map[string]*answering{"hosted": hosted, "local": local})
	for i := 0; i <= FailuresBeforeCooldown; i++ {
		if _, err := g.For("assist").Complete(ctx, "s", "u"); err == nil {
			t.Fatal("a cancelled call answered")
		}
	}
	if local.calls != 0 || hosted.calls != FailuresBeforeCooldown+1 {
		t.Errorf("a cancelled call moved on or rested the route: hosted %d, local %d", hosted.calls, local.calls)
	}
}

// A binding to one route is answered by that route or not at all, and is
// charged to everybody it names.
func TestAPinnedRouteHasNoFallback(t *testing.T) {
	hosted := &answering{name: "hosted", err: status(http.StatusServiceUnavailable, "down")}
	local := &answering{name: "local"}
	cfg := Config{Routes: two.Routes, Budgets: []Budget{{Consumer: "person:dana@quilzo.io", CharsPerDay: 10}}}
	g, _ := rigWith(t, cfg, map[string]*answering{"hosted": hosted, "local": local})
	if _, err := g.ForRoute("hosted", "reviewer:triage").Complete(context.Background(), "s", "u"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("err = %v", err)
	}
	if local.calls != 0 {
		t.Fatal("a pinned call fell back to another route, so a second opinion came from the first model")
	}
	if _, err := g.ForRoute("nowhere", "reviewer:triage").Complete(context.Background(), "s", "u"); !errors.Is(err, ErrNoRoute) ||
		!strings.Contains(err.Error(), "not declared") {
		t.Fatalf("an undeclared route: %v", err)
	}
	if out, err := g.ForRoute("local", "reviewer:triage", "person:dana@quilzo.io").Complete(context.Background(), "s", "u"); err != nil ||
		out != "answer from local" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := g.ForRoute("local", "reviewer:triage", "person:dana@quilzo.io").Complete(context.Background(), "s", "u"); !errors.Is(err, ErrBudget) {
		t.Fatalf("a review was not charged to the person it was made for: %v", err)
	}
	if !g.HasRoute("local") || g.HasRoute("nowhere") || g.FirstRoute() != "hosted" {
		t.Error("HasRoute or FirstRoute")
	}
}

// A route's fields are checked when it is declared, so a value no model
// could be sent, or one that could not be written back, is refused there.
func TestARoutesFieldsAreChecked(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for _, bad := range []RouteParams{
		{MaxTokens: "max_output"},
		{Temperature: f(2.5)},
		{Temperature: f(-0.1)},
		{Temperature: f(math.NaN())},
		{TopP: f(0)},
		{TopP: f(math.NaN())},
		{Timeout: "5ms"},
		{Timeout: "2h"},
		{Timeout: "soon"},
	} {
		r := two.Routes[0]
		r.Params = bad
		if (Config{Routes: []Route{r}}).Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	good := RouteParams{MaxTokens: "max_completion_tokens", Temperature: f(0), TopP: f(1), Timeout: "300s", AutoToolChoice: true,
		StructuredOutput: true, ReasoningEffort: true}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	if got := good.String(); got != "max_completion_tokens, temperature 0, top_p 1, 300s a call, auto tool choice, "+
		"structured output, reasoning effort" {
		t.Errorf("String() = %q", got)
	}
	if (RouteParams{}).String() != "" {
		t.Error("a route that sends nothing more said it did")
	}
	p, d := good.Model()
	if p.MaxTokensField != "max_completion_tokens" || *p.Temperature != 0 || !p.AutoToolChoice || d != 300*time.Second {
		t.Errorf("Model() = %+v %v", p, d)
	}
}

// A caller's name may be what single sign-on gives a person.
func TestABudgetMayNameAPersonByEmail(t *testing.T) {
	for _, ok := range []string{"door:dana@quilzo.io", "today:dana.k+ops@quilzo.io", "person:dana", "agent:triage", "*"} {
		if err := (Config{Routes: two.Routes, Budgets: []Budget{{Consumer: ok, PerMinute: 1}}}).Validate(); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"door:dana smith", "door:", "Door:dana", "door:a/b", "door:dana\n"} {
		if (Config{Routes: two.Routes, Budgets: []Budget{{Consumer: bad, PerMinute: 1}}}).Validate() == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A conversation is classified the same way: a refused request goes back
// and is not tried on the next route.
func TestARefusedConversationIsNotSentOn(t *testing.T) {
	hosted := &chatty{name: "hosted", err: status(http.StatusBadRequest, "tool_choice is not supported")}
	local := &chatty{name: "local", reply: assist.ChatReply{Message: assist.ChatMessage{Role: "assistant"}}}
	g := chatGateway(two.Routes, map[string]*chatty{"hosted": hosted, "local": local})
	var se *assist.StatusError
	if _, err := g.For("agent:x").(*bound).Chat(context.Background(), talk("hi", 0)); !errors.As(err, &se) {
		t.Fatalf("err = %v", err)
	}
	if len(local.got) != 0 {
		t.Error("a refused conversation was sent to the next route")
	}
	hosted.err = status(http.StatusInternalServerError, "oops")
	if _, err := g.For("agent:x").(*bound).Chat(context.Background(), talk("hi", 0)); err != nil || len(local.got) != 1 {
		t.Fatalf("a failing route did not fall over: %v", err)
	}
	if _, err := g.ForRoute("hosted", "reviewer:x").(*bound).Chat(context.Background(), talk("hi", 0)); !errors.Is(err, ErrNoRoute) ||
		len(local.got) != 1 {
		t.Fatalf("a pinned conversation fell back: %v", err)
	}
}
