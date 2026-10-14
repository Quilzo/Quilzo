// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/spend"
)

// What agents may pay, and what they paid (see internal/spend).

func spendPath(root string) string { return filepath.Join(root, "spending.json") }

// withBook reads the book, lets f change it, and writes it back, holding a
// lock across processes so two runs cannot both spend the last of a budget.
func withBook(root string, f func(*spend.Book) error) error {
	unlock, err := atomicfile.Lock(spendPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	var b spend.Book
	if err := loadJSON(spendPath(root), &b); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := f(&b); err != nil {
		return err
	}
	return saveJSON(spendPath(root), b)
}

func readBook(root string) (spend.Book, error) {
	var b spend.Book
	err := loadJSON(spendPath(root), &b)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return b, err
}

// paymentOf reads the payment a paying call would make.
func paymentOf(agentName string, in agent.Integration, op agent.Operation, args map[string]any) (spend.Payment, error) {
	raw, currency, payee, err := op.Pays.Read(args, hostOf(in.Endpoint))
	if err != nil {
		return spend.Payment{}, err
	}
	if !spend.ValidCurrency(currency) {
		return spend.Payment{}, fmt.Errorf("%q is not a currency code", currency)
	}
	amount, err := spend.AmountOf(raw, currency, op.Pays.Minor)
	if err != nil {
		return spend.Payment{}, err
	}
	if amount <= 0 {
		return spend.Payment{}, errors.New("the amount is nothing")
	}
	return spend.Payment{Agent: agentName, Tool: op.Name, Payee: payee, Currency: currency, Amount: amount}, nil
}

func hostOf(endpoint string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	h, _, _ = strings.Cut(h, "/")
	return h
}

// payingOperation is the declared paying operation a tool action calls,
// when it calls one.
func payingOperation(root string, a agent.Action) (agent.Integration, agent.Operation, bool) {
	if a.Tool == "" {
		return agent.Integration{}, agent.Operation{}, false
	}
	set, err := loadIntegrations(root)
	if err != nil || set == nil {
		return agent.Integration{}, agent.Operation{}, false
	}
	in, err := set.Resolve(a.Tool)
	if err != nil {
		return agent.Integration{}, agent.Operation{}, false
	}
	op, ok := in.Operation(a.Tool)
	if !ok || op.Pays == nil {
		return agent.Integration{}, agent.Operation{}, false
	}
	return in, op, true
}

// paymentAsks is why a paying call waits for a person: it is beyond every
// mandate, or its mandate asks first. Empty is a payment that goes ahead
// within a mandate that does not ask.
func paymentAsks(root, agentName string) func(agent.Action) string {
	return func(a agent.Action) string {
		in, op, ok := payingOperation(root, a)
		if !ok {
			return ""
		}
		p, err := paymentOf(agentName, in, op, a.Input)
		if err != nil {
			return agent.PaysPrefix + "an amount that could not be read: " + err.Error()
		}
		what := agent.PaysPrefix + spend.Format(p.Amount, p.Currency) + " to " + p.Payee
		b, err := readBook(root)
		if err != nil {
			return what + "; the mandates could not be read"
		}
		m, why := b.Cover(p, time.Now())
		switch {
		case m == nil:
			return what + "; " + why
		case m.Ask:
			return what + ", within mandate " + m.ID + ", which asks first"
		}
		return ""
	}
}

// payer charges paying calls for one run, whose id it reads when it
// charges: a run is given its id after its executors are wired.
type payer struct {
	root string
	run  func() string
}

func (p payer) runID() string {
	if p.run == nil {
		return ""
	}
	return p.run()
}

func (p payer) Charge(ctx context.Context, agentName string, in agent.Integration, op agent.Operation,
	args map[string]any) (func(error), error) {
	pay, err := paymentOf(agentName, in, op, args)
	if err != nil {
		return nil, fmt.Errorf("%s pays and %w", op.Name, err)
	}
	approved := agent.ApprovedByPerson(ctx)
	var rc spend.Receipt
	err = withBook(p.root, func(b *spend.Book) error {
		if m, _ := b.Cover(pay, time.Now()); m != nil && m.Ask && !approved {
			return fmt.Errorf("mandate %s asks a person about each payment", m.ID)
		}
		var cerr error
		rc, cerr = b.Charge(pay, p.runID(), approved, time.Now())
		return cerr
	})
	if err != nil {
		return nil, err
	}
	detail := map[string]string{"agent": agentName, "tool": op.Name, "payee": pay.Payee,
		"amount": spend.Format(pay.Amount, pay.Currency), "receipt": rc.ID, "run": p.runID()}
	if rc.Mandate != "" {
		detail["mandate"] = rc.Mandate
	} else {
		detail["approved"] = "a person, for this payment"
	}
	record(p.root, audit.Record{Action: "agent.paying", Resource: auth.AgentResource(agentName), Outcome: audit.Success,
		Principal: "agent/" + agentName, Kind: audit.KindAI, Model: "agent", Verified: true, Detail: detail})
	return func(cerr error) {
		_ = withBook(p.root, func(b *spend.Book) error { b.Settle(rc.ID, cerr); return nil })
		outcome := audit.Success
		if cerr != nil {
			outcome = audit.Failure
		}
		record(p.root, audit.Record{Action: "agent.paid", Resource: auth.AgentResource(agentName), Outcome: outcome,
			Principal: "agent/" + agentName, Kind: audit.KindAI, Model: "agent", Verified: true,
			Detail: map[string]string{"receipt": rc.ID, "amount": detail["amount"], "payee": pay.Payee}})
	}, nil
}

func spendUsage() error {
	fmt.Print(`quilzo spend — what agents may pay, and what they paid

  grant AGENT --currency USD --per 50 --budget 500 --payee PAYEE [--payee ...]
              --purpose "what for" [--tool TOOL] [--until YYYY-MM-DD] [--without-asking]
  list [AGENT]
  revoke ID
  receipts [AGENT]

A paying tool declares where its amount, currency and payee are ("pays" on
a REST operation). Within a mandate granted --without-asking a payment goes
ahead; otherwise a person decides, as paying always has. Every payment leaves
a receipt.
`)
	return nil
}

func cmdSpend(root string, args []string) error {
	if len(args) == 0 {
		return spendUsage()
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "grant":
		return spendGrant(root, args[1:], caller)
	case "list":
		return spendList(root, args[1:])
	case "revoke":
		return spendRevoke(root, args[1:], caller)
	case "receipts":
		return spendReceipts(root, args[1:])
	}
	return spendUsage()
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, strings.TrimSpace(v)); return nil }

// mayGrantSpending is whether a caller may give an agent spending
// authority: a person who may approve what the agent does.
func mayGrantSpending(root string, caller *Caller, agentName string) error {
	if caller.Kind == audit.KindAI {
		return errors.New("spending authority is given by a person, never by a model")
	}
	if err := authorise(root, caller, auth.ActApprove, auth.AgentResource(agentName)); err != nil {
		return fmt.Errorf("letting %s pay is approving what it does: %w", agentName, err)
	}
	return nil
}

func spendGrant(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("spend grant", flag.ContinueOnError)
	currency := fs.String("currency", "", "the currency, such as USD")
	per := fs.String("per", "", "the most one payment may be, such as 50 or 49.99")
	budget := fs.String("budget", "", "the most all payments together may come to")
	purpose := fs.String("purpose", "", "what the money is for")
	until := fs.String("until", "", "the last day it may pay, YYYY-MM-DD; thirty days by default")
	without := fs.Bool("without-asking", false, "pay within the mandate without a person deciding each payment")
	var payees, tools listFlag
	fs.Var(&payees, "payee", "who may be paid, as the paying tool names them; repeat for more")
	fs.Var(&tools, "tool", "a paying tool the mandate covers; repeat for more; any by default")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: quilzo spend grant AGENT --currency USD --per 50 --budget 500 --payee PAYEE --purpose WHY")
	}
	agentName := rest[0]
	if err := mayGrantSpending(root, caller, agentName); err != nil {
		return err
	}
	if agents, err := loadAgents(root); err != nil {
		return err
	} else if _, ok := agents.Agents[agentName]; !ok {
		return fmt.Errorf("no agent called %s is declared", agentName)
	}
	cur := strings.ToUpper(strings.TrimSpace(*currency))
	perAmt, err := spend.ParseAmount(*per, cur)
	if err != nil {
		return fmt.Errorf("--per: %w", err)
	}
	budAmt, err := spend.ParseAmount(*budget, cur)
	if err != nil {
		return fmt.Errorf("--budget: %w", err)
	}
	now := time.Now()
	ends := now.Add(30 * 24 * time.Hour)
	if *until != "" {
		d, err := time.Parse("2006-01-02", *until)
		if err != nil {
			return fmt.Errorf("--until is a day, like 2026-12-31: %v", err)
		}
		ends = d.Add(24 * time.Hour)
	}
	var m spend.Mandate
	err = withBook(root, func(b *spend.Book) error {
		var gerr error
		m, gerr = b.Grant(spend.Mandate{Agent: agentName, Currency: cur, PerPayment: perAmt, Budget: budAmt,
			Payees: payees, Tools: tools, Ask: !*without, Purpose: strings.TrimSpace(*purpose),
			GrantedBy: caller.Name, Expires: ends}, now)
		return gerr
	})
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("spend.granted", auth.AgentResource(agentName), audit.Success, map[string]string{
		"mandate": m.ID, "agent": agentName, "per": spend.Format(perAmt, cur), "budget": spend.Format(budAmt, cur),
		"payees": strings.Join(payees, " "), "asks": fmt.Sprint(m.Ask), "ends": m.Expires.Format("2006-01-02")}))
	how := "a person decides each payment, shown it is within this mandate"
	if !m.Ask {
		how = "it pays without asking. What it reads can steer it, within these limits: keep the payees and amounts tight"
	}
	w.Human("%s may pay %s to %s, at most %s a payment, %s in all, until %s: %s\n  %s%s%s\n",
		agentName, cur, strings.Join(payees, ", "), spend.Format(perAmt, cur), spend.Format(budAmt, cur),
		m.Expires.Format("2 Jan 2006"), m.ID, dim, how, reset)
	return nil
}

func spendList(root string, args []string) error {
	b, err := readBook(root)
	if err != nil {
		return err
	}
	var out []spend.Mandate
	for _, m := range b.Mandates {
		if len(args) == 0 || m.Agent == args[0] {
			out = append(out, m)
		}
	}
	if w.JSON(map[string]any{"mandates": out}) {
		return nil
	}
	if len(out) == 0 {
		w.Human("no mandates; paying tools wait for a person each time\n")
		return nil
	}
	now := time.Now()
	for _, m := range out {
		state := "until " + m.Expires.Format("2 Jan 2006")
		switch {
		case m.Revoked:
			state = "revoked"
		case !now.Before(m.Expires):
			state = "ended"
		}
		ask := "asks each time"
		if !m.Ask {
			ask = "pays without asking"
		}
		w.Human("%s%s%s  %s  %s spent of %s, at most %s a payment, to %s; %s, %s\n    %s%s%s\n", bold, m.ID, reset,
			m.Agent, spend.Format(m.Spent, m.Currency), spend.Format(m.Budget, m.Currency),
			spend.Format(m.PerPayment, m.Currency), strings.Join(m.Payees, ", "), ask, state, dim, m.Purpose, reset)
	}
	return nil
}

func spendRevoke(root string, args []string, caller *Caller) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo spend revoke ID")
	}
	b, err := readBook(root)
	if err != nil {
		return err
	}
	agentName := ""
	for _, m := range b.Mandates {
		if m.ID == args[0] {
			agentName = m.Agent
		}
	}
	if agentName == "" {
		return fmt.Errorf("no mandate %s", args[0])
	}
	if err := mayGrantSpending(root, caller, agentName); err != nil {
		return err
	}
	if err := withBook(root, func(b *spend.Book) error { return b.Revoke(args[0]) }); err != nil {
		return err
	}
	record(root, caller.auditRecord("spend.revoked", auth.AgentResource(agentName), audit.Success,
		map[string]string{"mandate": args[0], "agent": agentName}))
	w.Human("revoked %s; %s pays nothing more under it\n", args[0], agentName)
	return nil
}

func spendReceipts(root string, args []string) error {
	b, err := readBook(root)
	if err != nil {
		return err
	}
	var out []spend.Receipt
	for _, r := range b.Receipts {
		if len(args) == 0 || r.Agent == args[0] {
			out = append(out, r)
		}
	}
	if w.JSON(map[string]any{"receipts": out}) {
		return nil
	}
	if len(out) == 0 {
		w.Human("no payments\n")
		return nil
	}
	for _, r := range out {
		under := "mandate " + r.Mandate
		if r.Mandate == "" {
			under = "approved on its own"
		}
		w.Human("%s  %s  %s paid %s to %s with %s, %s: %s\n", r.ID, r.At.Format("2 Jan 15:04"), r.Agent,
			spend.Format(r.Amount, r.Currency), r.Payee, r.Tool, under, r.Outcome)
	}
	return nil
}
