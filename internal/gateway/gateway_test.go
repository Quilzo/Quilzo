// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fake struct {
	name  string
	fail  bool
	calls int
}

func (f *fake) Name() string { return f.name }
func (f *fake) Complete(context.Context, string, string) (string, error) {
	f.calls++
	if f.fail {
		return "", errors.New(f.name + " is down")
	}
	return "answer from " + f.name, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func rig(t *testing.T, cfg Config, models map[string]*fake) (*Gateway, *clock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "usage.jsonl")
	c := &clock{time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}
	l, err := OpenLedger(path, c.t)
	if err != nil {
		t.Fatal(err)
	}
	g := New(cfg, func(r Route) (Model, error) { return models[r.Name], nil }, l).WithClock(c.now)
	return g, c, path
}

var two = Config{Routes: []Route{
	{Name: "hosted", URL: "https://api.example/v1", Model: "big", KeyEnv: "HOSTED_KEY"},
	{Name: "local", URL: "http://localhost:11434/v1", Model: "small"},
}}

func TestAFailingRouteFallsBackAndRests(t *testing.T) {
	hosted, local := &fake{name: "hosted", fail: true}, &fake{name: "local"}
	g, c, _ := rig(t, two, map[string]*fake{"hosted": hosted, "local": local})
	m := g.For("chatbot:help")
	for i := 0; i < FailuresBeforeCooldown; i++ {
		out, err := m.Complete(context.Background(), "s", "u")
		if err != nil || out != "answer from local" {
			t.Fatalf("no fallback: %q %v", out, err)
		}
	}
	// Resting: the failing route is not tried again for a while.
	before := hosted.calls
	m.Complete(context.Background(), "s", "u")
	if hosted.calls != before {
		t.Fatal("a resting route was called")
	}
	// And comes back.
	c.t = c.t.Add(Cooldown + time.Second)
	hosted.fail = false
	if out, _ := m.Complete(context.Background(), "s", "u"); out != "answer from hosted" {
		t.Fatalf("a recovered route was not used again: %q", out)
	}
}

func TestEveryRouteFailingIsAnError(t *testing.T) {
	g, _, _ := rig(t, two, map[string]*fake{"hosted": {name: "hosted", fail: true},
		"local": {name: "local", fail: true}})
	if _, err := g.For("assist").Complete(context.Background(), "s", "u"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("err = %v", err)
	}
}

// TestAPublicChatbotCannotSpendWithoutLimit — the budget is the bill.
func TestAPublicChatbotCannotSpendWithoutLimit(t *testing.T) {
	cfg := two
	cfg.Budgets = []Budget{{Consumer: "chatbot:help", CharsPerDay: 100}}
	local := &fake{name: "local"}
	g, c, path := rig(t, cfg, map[string]*fake{"hosted": {name: "hosted"}, "local": local})
	m := g.For("chatbot:help")
	var refused error
	for i := 0; i < 20 && refused == nil; i++ {
		_, refused = m.Complete(context.Background(), "system prompt", "question")
	}
	if !errors.Is(refused, ErrBudget) {
		t.Fatal("a chatbot spent past its daily budget")
	}
	// Survives a restart: a new process does not get a new budget.
	l2, err := OpenLedger(path, c.t)
	if err != nil {
		t.Fatal(err)
	}
	g2 := New(cfg, func(r Route) (Model, error) { return local, nil }, l2).WithClock(c.now)
	if _, err := g2.For("chatbot:help").Complete(context.Background(), "s", "q"); !errors.Is(err, ErrBudget) {
		t.Fatal("a restart refilled the budget")
	}
	// A new day does.
	c.t = c.t.Add(24 * time.Hour)
	if _, err := g2.For("chatbot:help").Complete(context.Background(), "s", "q"); err != nil {
		t.Fatalf("the next day is still refused: %v", err)
	}
	// Somebody else was never limited by it.
	if _, err := g.For("assist").Complete(context.Background(), "s", "q"); err != nil {
		t.Fatal(err)
	}
}

func TestCallsPerMinute(t *testing.T) {
	cfg := two
	cfg.Budgets = []Budget{{Consumer: "*", PerMinute: 3}}
	g, c, _ := rig(t, cfg, map[string]*fake{"hosted": {name: "hosted"}, "local": {name: "local"}})
	m := g.For("agent:triage")
	for i := 0; i < 3; i++ {
		if _, err := m.Complete(context.Background(), "s", "u"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Complete(context.Background(), "s", "u"); !errors.Is(err, ErrBudget) {
		t.Fatal("a fourth call in the minute was allowed")
	}
	c.t = c.t.Add(61 * time.Second)
	if _, err := m.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal("the next minute is still refused")
	}
}

func TestTheLedgerHoldsNoPrompt(t *testing.T) {
	g, _, path := rig(t, two, map[string]*fake{"hosted": {name: "hosted"}, "local": {name: "local"}})
	g.For("chatbot:help").Complete(context.Background(), "SYSTEM-SECRET", "my card is 4111")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SYSTEM-SECRET") || strings.Contains(string(b), "4111") ||
		strings.Contains(string(b), "answer from") {
		t.Fatalf("the ledger holds content: %s", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm()&0o077 != 0 {
		t.Fatal("the ledger is readable by others")
	}
}

func TestAKeyIsNeverWrittenDown(t *testing.T) {
	for _, bad := range []Route{
		{Name: "a", URL: "https://x.example/v1", Model: "m", KeyEnv: "sk-live-abc123"},
		{Name: "a", URL: "https://user:pass@x.example/v1", Model: "m"},
		{Name: "a", URL: "ftp://x.example", Model: "m"},
		{Name: "A B", URL: "https://x.example", Model: "m"},
	} {
		if (Config{Routes: []Route{bad}}).Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := two.Validate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gateway.json")
	t.Setenv("HOSTED_KEY", "sk-real-secret")
	if err := Save(path, &two); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "sk-real-secret") {
		t.Fatal("a key was written to the declaration")
	}
	back, err := Load(path)
	if err != nil || len(back.Routes) != 2 {
		t.Fatalf("%v %+v", err, back)
	}
	if missing, _ := Load(filepath.Join(t.TempDir(), "none.json")); missing != nil {
		t.Fatal("a missing declaration was not nil")
	}
}

func TestSummaryIsByCaller(t *testing.T) {
	cfg := two
	cfg.Budgets = []Budget{{Consumer: "chatbot:help", CharsPerDay: 1000}}
	g, c, _ := rig(t, cfg, map[string]*fake{"hosted": {name: "hosted"}, "local": {name: "local"}})
	g.For("chatbot:help").Complete(context.Background(), "s", "u")
	g.For("chatbot:help").Complete(context.Background(), "s", "u")
	g.For("assist").Complete(context.Background(), "s", "u")
	sum := g.ledger.Summary(cfg, c.t)
	if len(sum) != 2 || sum[0].Consumer != "chatbot:help" || sum[0].Calls != 2 || sum[0].Budget != 1000 {
		t.Fatalf("%+v", sum)
	}
}

type refusing struct{ err error }

func (r refusing) Name() string { return "refusing" }
func (r refusing) Complete(context.Context, string, string) (string, error) {
	return "", r.err
}

func TestTheShieldCutsARouteAndHearsWhatItShould(t *testing.T) {
	local := &fake{name: "local"}
	hosted := &fake{name: "hosted"}
	g, _, _ := rig(t, two, map[string]*fake{"hosted": hosted, "local": local})
	g.Cut = func(route string) bool { return route == "hosted" }
	var told []string
	g.OnTrouble = func(kind, subject string) { told = append(told, kind+" "+subject) }
	if out, err := g.For("assist").Complete(context.Background(), "s", "u"); err != nil || out != "answer from local" || hosted.calls != 0 {
		t.Fatalf("a cut route was used: %q %v", out, err)
	}
	// A budget spent is told, once per refused call.
	b := Config{Routes: two.Routes, Budgets: []Budget{{Consumer: "agent:triage", PerMinute: 1}}}
	g2, _, _ := rig(t, b, map[string]*fake{"hosted": hosted, "local": local})
	g2.OnTrouble = g.OnTrouble
	g2.For("agent:triage").Complete(context.Background(), "s", "u")
	if _, err := g2.For("agent:triage").Complete(context.Background(), "s", "u"); !errors.Is(err, ErrBudget) {
		t.Fatal(err)
	}
	if len(told) != 1 || told[0] != "spent agent:triage" {
		t.Fatalf("told %v", told)
	}
}

func TestOnlyAProvidersSpendCapOrKeyIsTrouble(t *testing.T) {
	cases := map[string]string{
		`model returned 401: {"error":"invalid api key"}`:                                  "route-auth",
		`model returned 429: {"error":{"code":"organization_spend_limit_exceeded"}}`:       "route-spent",
		`model returned 400: {"error":"You have reached your specified API usage limits"}`: "route-spent",
		`model returned 429: {"error":"rate limited, retry after 3s"}`:                     "",
		`model returned 503: overloaded`:                                                   "",
		`dial tcp: connection refused`:                                                     "",
	}
	for msg, want := range cases {
		if got := Trouble(errors.New(msg)); got != want {
			t.Errorf("%s: %q, want %q", msg, got, want)
		}
	}
	if Trouble(nil) != "" {
		t.Fatal("no error is trouble")
	}
}
