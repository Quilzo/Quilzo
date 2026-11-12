// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package spend is what an agent may pay, and the record of what it paid.
//
// An agent that buys, tops up credit or pays an invoice is spending
// somebody's money, and the question afterwards is always the same: who
// allowed this, within what limits, and what exactly was paid to whom. AP2,
// the agent payments protocol, answers it with mandates: a person approves,
// on a surface no agent drives, the constraints an agent may pay within
// (an amount range, a budget, the payees, an expiry), and each payment is
// checked against them by code, not judged by a model.
//
// A mandate here is that open mandate, kept by Quilzo for one agent. A
// paying tool declares where in its arguments the amount, the currency and
// the payee are (agent.Pays), so a payment is read from the call itself.
// Within a mandate that does not ask, the payment goes ahead and is
// debited; otherwise a person decides, as paying always has. Every payment
// leaves a receipt naming its mandate, or the person who approved it alone.
//
// What an agent reads can steer it, so a mandate is not a judgement about
// the run: it is the most the person accepts being spent however the run
// went, in amounts, payees, total and time, which is how AP2 and the card
// networks' agent tokens bound an agent that may have been misled.
package spend

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Mandate is what one agent may pay without a person deciding each time.
type Mandate struct {
	ID       string `json:"id"`
	Agent    string `json:"agent"`
	Currency string `json:"currency"`
	// PerPayment and Budget are in the currency's minor units: the most
	// one payment may be, and the most all of them together may come to.
	PerPayment int64 `json:"per_payment"`
	Budget     int64 `json:"budget"`
	Spent      int64 `json:"spent"`
	// Payees are who may be paid, exactly as the paying tool names them.
	Payees []string `json:"payees"`
	// Tools narrows the mandate to these paying tools; empty is any.
	Tools []string `json:"tools,omitempty"`
	// Ask keeps a person deciding each payment; the mandate then bounds
	// what they are shown as within it.
	Ask       bool      `json:"ask,omitempty"`
	Purpose   string    `json:"purpose"`
	GrantedBy string    `json:"granted_by"`
	GrantedAt time.Time `json:"granted_at"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// Payment is one payment a tool call would make.
type Payment struct {
	Agent, Tool, Payee, Currency string
	Amount                       int64
}

// Receipt is one payment made.
type Receipt struct {
	ID       string    `json:"id"`
	At       time.Time `json:"at"`
	Agent    string    `json:"agent"`
	Run      string    `json:"run,omitempty"`
	Tool     string    `json:"tool"`
	Payee    string    `json:"payee"`
	Currency string    `json:"currency"`
	Amount   int64     `json:"amount"`
	// Mandate is the mandate it was paid within, or empty when a person
	// approved it on its own.
	Mandate  string `json:"mandate,omitempty"`
	Approved bool   `json:"approved,omitempty"`
	// Outcome is "paid", or what the far side answered when it failed.
	Outcome string `json:"outcome"`
}

// Book is every mandate and receipt.
type Book struct {
	Mandates []Mandate `json:"mandates"`
	Receipts []Receipt `json:"receipts"`
}

// MaxReceipts is how many receipts are kept here; the audit log keeps
// every one.
const MaxReceipts = 5000

// Four places is the most ISO 4217 gives a currency (CLF, UYW).
var reAmount = regexp.MustCompile(`^[0-9]{1,15}(\.[0-9]{1,4})?$`)

// iso4217 is the list a currency is checked against: see the file.
//
//go:embed iso4217.txt
var iso4217 string

// currencies are the ISO 4217 codes, each with how many places its amounts
// have.
//
// It used to be the pattern ^[A-Z]{3}$ and a table of the exceptions to two
// places, so any three capital letters were a currency: a mandate in ETH,
// BTC or SOL was granted, shown as "1.00 ETH" and counted in hundredths of
// whatever the paying tool counted, which for a token is neither its own
// unit nor its smallest.
var currencies = func() map[string]int {
	out := map[string]int{}
	for n, line := range strings.Split(iso4217, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			panic(fmt.Sprintf("iso4217.txt line %d is not CODE PLACES NAME: %q", n+1, line))
		}
		places, err := strconv.Atoi(f[1])
		if len(f[0]) != 3 || strings.ToUpper(f[0]) != f[0] || err != nil || places < 0 || places > 4 {
			panic(fmt.Sprintf("iso4217.txt line %d is not CODE PLACES NAME: %q", n+1, line))
		}
		if _, twice := out[f[0]]; twice {
			panic(fmt.Sprintf("iso4217.txt lists %s twice", f[0]))
		}
		out[f[0]] = places
	}
	return out
}()

// Decimals is how many places a currency's amounts have. A code that is
// not a currency is written back with two, as it always was; ParseAmount
// and AmountOf refuse to count in one.
func Decimals(currency string) int {
	if d, ok := currencies[currency]; ok {
		return d
	}
	return 2
}

// ValidCurrency reports whether a currency is one ISO 4217 lists.
func ValidCurrency(c string) bool { _, ok := currencies[c]; return ok }

// CheckCurrency says why a code is not a currency, or nothing. The words
// name the crypto case, because that is the one that looked like a
// currency: three capital letters, and a ticker people write after an
// amount.
func CheckCurrency(c string) error {
	if ValidCurrency(c) {
		return nil
	}
	return fmt.Errorf("%q is not an ISO 4217 currency, such as USD or EUR. A crypto asset such as ETH, "+
		"BTC or SOL is not a currency here: its amounts are not counted in a currency's minor units, "+
		"and Quilzo holds no wallet and signs no transaction", c)
}

// ParseAmount reads a written amount, such as 12.50, in minor units, and
// refuses one with more places than the currency has, or in something that
// is not a currency.
func ParseAmount(s, currency string) (int64, error) {
	if err := CheckCurrency(currency); err != nil {
		return 0, err
	}
	s = strings.TrimSpace(s)
	if !reAmount.MatchString(s) {
		return 0, fmt.Errorf("%q is not an amount, such as 12.50", s)
	}
	whole, frac, _ := strings.Cut(s, ".")
	places := Decimals(currency)
	if len(frac) > places {
		return 0, fmt.Errorf("%s has %d decimal places, and %s has %d", s, len(frac), currency, places)
	}
	frac += strings.Repeat("0", places-len(frac))
	n, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok || !n.IsInt64() {
		return 0, fmt.Errorf("%s is too large", s)
	}
	return n.Int64(), nil
}

// AmountOf reads an amount from a tool's argument: a written amount, or a
// number, in major units, or a whole number of minor units.
func AmountOf(v any, currency string, minor bool) (int64, error) {
	if err := CheckCurrency(currency); err != nil {
		return 0, err
	}
	switch x := v.(type) {
	case string:
		if minor {
			n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
			if err != nil || n < 0 || n > 1e15 {
				return 0, fmt.Errorf("%q is not a whole number of minor units", x)
			}
			return n, nil
		}
		return ParseAmount(x, currency)
	case float64:
		if minor {
			if x != math.Trunc(x) || x < 0 || x > 1e15 {
				return 0, fmt.Errorf("%v is not a whole number of minor units", x)
			}
			return int64(x), nil
		}
		return ParseAmount(strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", x), "0"), "."), currency)
	case int:
		if minor {
			return int64(x), nil
		}
		return ParseAmount(fmt.Sprint(x), currency)
	}
	return 0, fmt.Errorf("the amount is a %T, not a number", v)
}

// Format writes an amount in minor units the way people read it.
func Format(amount int64, currency string) string {
	places := Decimals(currency)
	if places == 0 {
		return fmt.Sprintf("%d %s", amount, currency)
	}
	unit := int64(math.Pow10(places))
	return fmt.Sprintf("%d.%0*d %s", amount/unit, places, amount%unit, currency)
}

// Validate checks a mandate on its own.
func (m Mandate) Validate(now time.Time) error {
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if strings.TrimSpace(m.Agent) == "" {
		bad("a mandate is for one agent")
	}
	if err := CheckCurrency(m.Currency); err != nil {
		bad("%v", err)
	}
	if m.PerPayment <= 0 || m.Budget <= 0 || m.PerPayment > m.Budget {
		bad("a payment's limit and the budget are both more than nothing, the limit no more than the budget")
	}
	if len(m.Payees) == 0 {
		bad("a mandate names who may be paid")
	}
	if strings.TrimSpace(m.Purpose) == "" {
		bad("a mandate says what the money is for")
	}
	if !m.Expires.After(now) || m.Expires.Sub(now) > 366*24*time.Hour {
		bad("a mandate ends within a year")
	}
	if len(errs) > 0 {
		return fmt.Errorf("the mandate is not usable: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Grant adds a mandate, with a new id.
func (b *Book) Grant(m Mandate, now time.Time) (Mandate, error) {
	if err := m.Validate(now); err != nil {
		return Mandate{}, err
	}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return Mandate{}, err
	}
	m.ID, m.Spent, m.GrantedAt, m.Revoked = "md_"+hex.EncodeToString(id), 0, now.UTC(), false
	b.Mandates = append(b.Mandates, m)
	return m, nil
}

// Revoke ends a mandate.
func (b *Book) Revoke(id string) error {
	for i := range b.Mandates {
		if b.Mandates[i].ID == id {
			b.Mandates[i].Revoked = true
			return nil
		}
	}
	return fmt.Errorf("no mandate %s", id)
}

// live reports whether a mandate can still cover anything.
func (m Mandate) live(now time.Time) bool {
	return !m.Revoked && now.Before(m.Expires) && m.Spent < m.Budget
}

// misfit says why a mandate does not cover a payment, or nothing.
func (m Mandate) misfit(p Payment, now time.Time) string {
	switch {
	case m.Agent != p.Agent:
		return "it is for another agent"
	case m.Revoked:
		return "it was revoked"
	case !now.Before(m.Expires):
		return "it has ended"
	case m.Currency != p.Currency:
		return "it is in " + m.Currency
	case !slices.Contains(m.Payees, p.Payee):
		return "it does not name " + p.Payee
	case len(m.Tools) > 0 && !slices.Contains(m.Tools, p.Tool):
		return "it does not cover the tool " + p.Tool
	case p.Amount > m.PerPayment:
		return "it allows at most " + Format(m.PerPayment, m.Currency) + " a payment"
	case m.Spent+p.Amount > m.Budget:
		return "it has " + Format(m.Budget-m.Spent, m.Currency) + " left"
	}
	return ""
}

// Cover finds the mandate a payment falls within, or says why none does.
func (b *Book) Cover(p Payment, now time.Time) (*Mandate, string) {
	var why []string
	for i := range b.Mandates {
		m := &b.Mandates[i]
		if m.Agent != p.Agent || !m.live(now) {
			continue
		}
		if miss := m.misfit(p, now); miss != "" {
			why = append(why, m.ID+": "+miss)
			continue
		}
		return m, ""
	}
	if len(why) == 0 {
		return nil, "no mandate lets " + p.Agent + " pay"
	}
	return nil, "no mandate covers it (" + strings.Join(why, "; ") + ")"
}

// ErrNotCovered is a payment no mandate covers and no person approved.
var ErrNotCovered = errors.New("no mandate covers this payment and no person approved it")

// Charge records a payment about to be made: debited from the mandate that
// covers it, or, when none does, made on a person's approval alone. The
// receipt is completed with Settle once the far side answers.
func (b *Book) Charge(p Payment, run string, approved bool, now time.Time) (Receipt, error) {
	m, _ := b.Cover(p, now)
	if m == nil && !approved {
		return Receipt{}, ErrNotCovered
	}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return Receipt{}, err
	}
	r := Receipt{ID: "rc_" + hex.EncodeToString(id), At: now.UTC(), Agent: p.Agent, Run: run, Tool: p.Tool,
		Payee: p.Payee, Currency: p.Currency, Amount: p.Amount, Approved: approved, Outcome: "pending"}
	if m != nil {
		m.Spent += p.Amount
		r.Mandate = m.ID
	}
	b.Receipts = append(b.Receipts, r)
	if len(b.Receipts) > MaxReceipts {
		b.Receipts = b.Receipts[len(b.Receipts)-MaxReceipts:]
	}
	return r, nil
}

// Settle completes a receipt with what the far side answered. A payment
// that failed still counts against its mandate: a call that timed out may
// have been paid, and a budget that refilled on every error is one a
// failing loop could spend twice. A person who knows it was not paid
// grants a new mandate.
func (b *Book) Settle(id string, err error) {
	for i := range b.Receipts {
		r := &b.Receipts[i]
		if r.ID != id {
			continue
		}
		if err == nil {
			r.Outcome = "paid"
			return
		}
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		r.Outcome = "failed: " + msg
		return
	}
}
