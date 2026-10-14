// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spend

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Amounts are read exactly, in each currency's own minor units, and one
// with more places than the currency has is refused rather than rounded.
func TestAmountsAreReadExactlyInTheCurrencysUnits(t *testing.T) {
	for _, c := range []struct {
		in       any
		currency string
		minor    bool
		want     int64
		ok       bool
	}{
		{"12.50", "USD", false, 1250, true},
		{"12.5", "EUR", false, 1250, true},
		{12.5, "GBP", false, 1250, true},
		{"500", "JPY", false, 500, true},
		{"1.234", "KWD", false, 1234, true},
		{"1250", "USD", true, 1250, true},
		{1250.0, "USD", true, 1250, true},
		{"12.555", "USD", false, 0, false},
		{"5.5", "JPY", false, 0, false},
		{"-3", "USD", false, 0, false},
		{"1e3", "USD", false, 0, false},
		{12.5, "USD", true, 0, false},
		{true, "USD", false, 0, false},
	} {
		got, err := AmountOf(c.in, c.currency, c.minor)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%v %s minor=%v: %d %v", c.in, c.currency, c.minor, got, err)
		}
	}
	if Format(1250, "USD") != "12.50 USD" || Format(500, "JPY") != "500 JPY" || Format(1234, "KWD") != "1.234 KWD" {
		t.Error("amounts are not written back the way people read them")
	}
}

func book(t *testing.T, now time.Time) (*Book, Mandate) {
	t.Helper()
	b := &Book{}
	m, err := b.Grant(Mandate{Agent: "buyer", Currency: "USD", PerPayment: 5000, Budget: 12000,
		Payees: []string{"acct_supplies"}, Tools: []string{"pay_invoice"}, Purpose: "office supplies",
		GrantedBy: "dana", Expires: now.Add(30 * 24 * time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	return b, m
}

// A payment is covered only by a mandate that names its agent, payee,
// tool and currency, within the per-payment limit and what is left.
func TestAMandateCoversOnlyWhatItSays(t *testing.T) {
	now := time.Now()
	b, m := book(t, now)
	ok := Payment{Agent: "buyer", Tool: "pay_invoice", Payee: "acct_supplies", Currency: "USD", Amount: 4000}
	if got, why := b.Cover(ok, now); got == nil || got.ID != m.ID {
		t.Fatalf("not covered: %s", why)
	}
	for name, edit := range map[string]func(*Payment){
		"another agent":    func(p *Payment) { p.Agent = "other" },
		"another payee":    func(p *Payment) { p.Payee = "acct_attacker" },
		"another tool":     func(p *Payment) { p.Tool = "wire_transfer" },
		"another currency": func(p *Payment) { p.Currency = "EUR" },
		"too much at once": func(p *Payment) { p.Amount = 5001 },
	} {
		p := ok
		edit(&p)
		if got, why := b.Cover(p, now); got != nil || why == "" {
			t.Errorf("%s was covered", name)
		}
	}
	if got, _ := b.Cover(ok, now.Add(31*24*time.Hour)); got != nil {
		t.Error("an ended mandate covered a payment")
	}
}

// Payments are debited until the budget runs out; one outside every
// mandate is made only on a person's approval, and a failed payment still
// counts.
func TestPaymentsAreDebitedAndReceipted(t *testing.T) {
	now := time.Now()
	b, m := book(t, now)
	p := Payment{Agent: "buyer", Tool: "pay_invoice", Payee: "acct_supplies", Currency: "USD", Amount: 5000}
	for i := 0; i < 2; i++ {
		r, err := b.Charge(p, "run-1", false, now)
		if err != nil || r.Mandate != m.ID {
			t.Fatalf("%+v %v", r, err)
		}
		b.Settle(r.ID, nil)
	}
	if _, err := b.Charge(p, "run-1", false, now); !errors.Is(err, ErrNotCovered) {
		t.Errorf("the budget was overspent: %v", err)
	}
	r, err := b.Charge(p, "run-1", true, now)
	if err != nil || r.Mandate != "" || !r.Approved {
		t.Fatalf("a person's approval did not pay: %+v %v", r, err)
	}
	small := p
	small.Amount = 1000
	r, _ = b.Charge(small, "run-2", false, now)
	b.Settle(r.ID, errors.New("timeout"))
	if b.Mandates[0].Spent != 11000 || !strings.HasPrefix(b.Receipts[len(b.Receipts)-1].Outcome, "failed") {
		t.Errorf("a failed payment gave its money back, or was not recorded: %d %+v", b.Mandates[0].Spent, b.Receipts)
	}
	b.Revoke(m.ID)
	if _, err := b.Charge(small, "run-3", false, now); !errors.Is(err, ErrNotCovered) {
		t.Error("a revoked mandate paid")
	}
}

func TestAMandateIsBoundedByDeclaration(t *testing.T) {
	now := time.Now()
	good := Mandate{Agent: "buyer", Currency: "USD", PerPayment: 100, Budget: 1000, Payees: []string{"x"},
		Purpose: "p", Expires: now.Add(time.Hour)}
	if err := good.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Mandate){
		"no payee":            func(m *Mandate) { m.Payees = nil },
		"a limit over budget": func(m *Mandate) { m.PerPayment = 2000 },
		"no currency":         func(m *Mandate) { m.Currency = "dollars" },
		"no purpose":          func(m *Mandate) { m.Purpose = "" },
		"forever":             func(m *Mandate) { m.Expires = now.Add(2 * 365 * 24 * time.Hour) },
		"already over":        func(m *Mandate) { m.Expires = now.Add(-time.Hour) },
	} {
		m := good
		edit(&m)
		if err := m.Validate(now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
