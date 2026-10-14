// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// paidCalls is the far side of a payments API: it records what was paid.
type paidCalls struct{ paid []map[string]any }

func (p *paidCalls) Call(_ context.Context, _ agent.Integration, tool string, args map[string]any) (string, error) {
	p.paid = append(p.paid, args)
	return `{"status":"paid"}`, nil
}

// payingStore is a store with a payments API whose pay_invoice operation
// pays, and an agent that may call it.
func payingStore(t *testing.T) (string, agent.Manifest) {
	t.Helper()
	root, _ := identityStore(t)
	set := agent.Integrations{Declared: []agent.Integration{{
		Name: "payments", Kind: agent.IntegrationKind("http"), Enabled: true, Purpose: "pay suppliers' invoices",
		Endpoint: "pay.example.com", Uses: []string{"pay_invoice"}, Writes: true,
		Operations: []agent.Operation{{Name: "pay_invoice", Method: "POST", Path: "/payments",
			Body: json.RawMessage(`{"type":"object"}`),
			Pays: &agent.Pays{Amount: "body.amount", Minor: true, Currency: "body.currency", Payee: "body.payee"}}},
	}}}
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		t.Fatal(err)
	}
	m := agent.Manifest{Name: "buyer", Kind: agent.KindTask, Purpose: "pays the supplies invoices",
		Autonomy: agent.AutonomyDraft, Capabilities: []string{"read_page"},
		Tools:  []agent.Tool{{Name: "pay_invoice", Host: "pay.example.com", Purpose: "pay invoices", Writes: true}},
		Budget: agent.Budget{Steps: 10, Tools: 5, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root, m
}

func invoice(amount float64, payee string) agent.Action {
	return agent.Action{Tool: "pay_invoice", Input: map[string]any{
		"body": map[string]any{"amount": amount, "currency": "usd", "payee": payee}}}
}

// A mandate is given by a person who may approve the agent's actions, and
// a payment within one that does not ask goes ahead and is debited, while
// one beyond it waits for a person.
func TestAnAgentPaysWithinItsMandateAndAsksBeyondIt(t *testing.T) {
	root, m := payingStore(t)
	model := asAdmin("helper")
	model.Kind = audit.KindAI
	grant := []string{"buyer", "--currency", "USD", "--per", "50", "--budget", "120", "--payee", "acct_supplies",
		"--purpose", "office supplies", "--without-asking"}
	if err := spendGrant(root, grant, model); err == nil {
		t.Fatal("a model gave an agent spending authority")
	}
	if err := spendGrant(root, grant, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	asks := paymentAsks(root, "buyer")
	if why := asks(invoice(4000, "acct_supplies")); why != "" {
		t.Errorf("a payment within the mandate was held: %s", why)
	}
	for _, a := range []agent.Action{invoice(5001, "acct_supplies"), invoice(100, "acct_attacker")} {
		if why := asks(a); !strings.HasPrefix(why, agent.PaysPrefix) {
			t.Errorf("a payment beyond the mandate went ahead: %v", a.Input)
		}
	}
	if agent.CommitOf(invoice(5001, "acct_supplies"), asks(invoice(5001, "acct_supplies")), agent.WaitAsk, true) != "pays" {
		t.Error("a held payment is not classed as paying, so it could be earned")
	}

	far := &paidCalls{}
	tools := agentexec.Tools{
		Installed: func() (agent.Integrations, error) { set, err := loadIntegrations(root); return *set, err },
		Call:      far, Pay: payer{root: root, run: func() string { return "run-1" }},
	}
	sess := agent.NewSession(m, time.Now)
	perform := tools.Perform(sess)
	for i := 0; i < 3; i++ {
		_, err := perform(context.Background(), invoice(5000, "acct_supplies"))
		if i < 2 && err != nil {
			t.Fatalf("payment %d: %v", i, err)
		}
		if i == 2 && err == nil {
			t.Error("the budget was overspent")
		}
	}
	if len(far.paid) != 2 {
		t.Errorf("%d payments reached the far side", len(far.paid))
	}
	approved := agent.WithPersonApproval(context.Background())
	if _, err := perform(approved, invoice(9000, "acct_supplies")); err != nil {
		t.Errorf("a person's approval of one payment beyond the mandate did not pay: %v", err)
	}
	b, _ := readBook(root)
	if len(b.Receipts) != 3 || b.Mandates[0].Spent != 10000 || b.Receipts[2].Mandate != "" || !b.Receipts[2].Approved {
		t.Errorf("receipts %+v, spent %d", b.Receipts, b.Mandates[0].Spent)
	}
	for _, r := range b.Receipts {
		if r.Outcome != "paid" || r.Run != "run-1" {
			t.Errorf("%+v", r)
		}
	}
}

// A mandate that asks still holds each payment for a person, and
// revoking a mandate stops it paying.
func TestAMandateThatAsksHoldsAndARevokedOnePaysNothing(t *testing.T) {
	root, _ := payingStore(t)
	if err := spendGrant(root, []string{"buyer", "--currency", "USD", "--per", "50", "--budget", "500",
		"--payee", "acct_supplies", "--purpose", "supplies"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	asks := paymentAsks(root, "buyer")
	if why := asks(invoice(1000, "acct_supplies")); !strings.Contains(why, "which asks first") {
		t.Errorf("%q", why)
	}
	b, _ := readBook(root)
	if err := spendRevoke(root, []string{b.Mandates[0].ID}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	p := payer{root: root}
	set, _ := loadIntegrations(root)
	in, _ := set.Resolve("pay_invoice")
	op, _ := in.Operation("pay_invoice")
	if _, err := p.Charge(context.Background(), "buyer", in, op, invoice(1000, "acct_supplies").Input); err == nil {
		t.Error("a revoked mandate paid")
	}
	if err := spendRevoke(root, []string{"md_none"}, asAdmin("dana")); err == nil {
		t.Error("an unknown mandate was revoked")
	}
	reader := &Caller{Name: "rae", Role: auth.RoleReader, Kind: audit.KindHuman, Verified: true}
	if err := spendGrant(root, []string{"buyer", "--currency", "USD", "--per", "5", "--budget", "5",
		"--payee", "x", "--purpose", "y"}, reader); err == nil {
		t.Error("somebody who may not approve the agent gave it spending authority")
	}
}
