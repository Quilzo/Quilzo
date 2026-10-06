// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
)

// metered reports usage, as a provider that sends a usage block does.
type metered struct{ in, out int }

func (m *metered) Name() string { return "metered" }
func (m *metered) Complete(ctx context.Context, s, u string) (string, error) {
	out, _, err := m.CompleteMetered(ctx, s, u)
	return out, err
}
func (m *metered) CompleteMetered(context.Context, string, string) (string, assist.Usage, error) {
	return "ok", assist.Usage{In: m.in, Out: m.out, Reported: true}, nil
}

func TestMoneyIsExactAndReadable(t *testing.T) {
	for in, want := range map[string]Money{"5": 5_000_000, "5.00": 5_000_000, "0.15": 150_000, "0.000001": 1, "12.5": 12_500_000} {
		got, err := ParseMoney(in)
		if err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "1.0000001", "1e3", "$5", "5,00", "99999999999"} {
		if _, err := ParseMoney(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for m, want := range map[Money]string{5_000_000: "5.00", 150_000: "0.15", 1: "0.000001", 12_345_678: "12.345678", 0: "0.00"} {
		if m.String() != want {
			t.Errorf("%d: %s", m, m.String())
		}
	}
	// Rounded up, never down: a ledger that says less than was spent is
	// one that cannot be reconciled with the invoice.
	if c := costOf(150_000, 600_000, 1, 0); c != 1 {
		t.Fatalf("a single token cost %d", c)
	}
	if c := costOf(150_000, 600_000, 1_000_000, 1_000_000); c != 750_000 {
		t.Fatalf("a million each way cost %d", c)
	}
}

func TestPricesAndMoneyBudgetsNeedACurrency(t *testing.T) {
	priced := Config{Routes: []Route{{Name: "hosted", URL: "https://api.example/v1", Model: "m", KeyEnv: "K", PriceIn: "0.15"}}}
	if priced.Validate() == nil {
		t.Fatal("prices with no currency")
	}
	priced.Currency = "USD"
	if err := priced.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{
		{Currency: "usd"},
		{Currency: "USD", Budgets: []Budget{{Consumer: "agent:x", MoneyPerDay: "five"}}},
		{Budgets: []Budget{{Consumer: "agent:x", MoneyPerMonth: "5"}}},
		{Currency: "USD", Budgets: []Budget{{Consumer: "agent:x", TokensPerDay: -1}}},
		{Currency: "USD", Routes: []Route{{Name: "r", URL: "https://a.example", Model: "m", KeyEnv: "K", PriceOut: "1.2.3"}}},
	} {
		if cfg.Validate() == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
	ok := Config{Currency: "EUR", Budgets: []Budget{{Consumer: "person:dana@example.com", MoneyPerDay: "2.50"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a person's budget: %v", err)
	}
}

func TestSpendingIsChargedToEveryPayerAndCapped(t *testing.T) {
	cfg := Config{Currency: "USD",
		Routes: []Route{{Name: "hosted", URL: "https://api.example/v1", Model: "m", KeyEnv: "K", PriceIn: "1.00", PriceOut: "2.00"}},
		Budgets: []Budget{
			{Consumer: "agent:triage", MoneyPerDay: "0.005"},
			{Consumer: "person:dana", MoneyPerMonth: "0.009", TokensPerDay: 100000},
		}}
	path := t.TempDir() + "/usage.jsonl"
	c := &clock{time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
	l, _ := OpenLedger(path, c.t)
	m := &metered{in: 1000, out: 1000}
	g := New(cfg, func(Route) (Model, error) { return m, nil }, l).WithClock(c.now)
	call := g.For("agent:triage", "person:dana").(*bound)
	// Each call: 1000 in at 1.00/M and 1000 out at 2.00/M = 0.003.
	_, u, cost, err := call.CompleteCosted(context.Background(), "s", "u")
	if err != nil || cost != 3000 || u.In != 1000 || !u.Reported {
		t.Fatalf("%v %d %+v", err, cost, u)
	}
	if l.TodayCost("agent:triage", c.t) != 3000 || l.TodayCost("person:dana", c.t) != 3000 || l.TodayTokens("person:dana", c.t) != 2000 {
		t.Fatal("not charged to both payers")
	}
	// The agent's day reaches 0.006 on the next call; the one after is refused.
	if _, err := call.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := call.Complete(context.Background(), "s", "u"); !errors.Is(err, ErrBudget) {
		t.Fatalf("the agent spent past its day: %v", err)
	}
	// A new day: the agent may spend again, and the person's month stops it.
	c.t = c.t.Add(24 * time.Hour)
	if _, err := call.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("a new day: %v", err)
	}
	if _, err := call.Complete(context.Background(), "s", "u"); !errors.Is(err, ErrBudget) {
		t.Fatalf("the person spent past their month: %v", err)
	}
	// Another agent of the same person is stopped by the person's month too.
	if _, err := g.For("agent:other", "person:dana").Complete(context.Background(), "s", "u"); !errors.Is(err, ErrBudget) {
		t.Fatalf("another agent spent the person's money: %v", err)
	}
	// The month turns over.
	c.t = time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC)
	if _, err := call.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("a new month: %v", err)
	}
	// A restart reads the month back rather than refilling it.
	l2, _ := OpenLedger(path, c.t)
	if l2.MonthCost("person:dana", c.t) != 3000 {
		t.Fatalf("after a restart: %d", l2.MonthCost("person:dana", c.t))
	}
	for _, s := range l2.Summary(cfg, c.t) {
		if s.Consumer == "person:dana" && (s.Cost != 3000 || s.MonthBudget != 9000 || s.TokensBudget != 100000) {
			t.Fatalf("%+v", s)
		}
	}
}

func TestAProviderThatSaysNothingIsEstimated(t *testing.T) {
	cfg := Config{Currency: "USD", Routes: []Route{{Name: "local", URL: "http://localhost:11434/v1", Model: "m", PriceIn: "1"}}}
	f := &fake{name: "local"}
	g, c, _ := rig(t, cfg, map[string]*fake{"local": f})
	_, u, cost, err := g.For("assist").(*bound).CompleteCosted(context.Background(), "12345678", "")
	if err != nil || u.Reported || u.In != 2 || cost != 2 {
		t.Fatalf("%+v %d %v", u, cost, err)
	}
	if g.ledger.TodayTokens("assist", c.t) == 0 {
		t.Fatal("an estimate was not counted")
	}
}
