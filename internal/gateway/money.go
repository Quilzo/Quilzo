// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Money, so a budget can say what the organisation actually cares about.
//
// Characters were the unit because every provider counts tokens its own
// way. Providers now report the tokens they bill, and an operator knows
// what each route costs per million of them, so a call's cost is known
// from what was really used, and a day's or a month's spending can be
// capped in the currency the invoice is in.
//
// Amounts are kept in millionths of the currency's unit, as integers: a
// float that rounds a little each call is a total nobody can reconcile
// with the invoice. A call's cost is rounded up, so the ledger never says
// less than was spent.

// Money is an amount in millionths of the configured currency's unit.
type Money int64

const microsPerUnit = 1_000_000

// maxMoney bounds what a setting can say: a billion units is not a budget.
const maxMoney = Money(1_000_000_000) * microsPerUnit

var reMoney = regexp.MustCompile(`^[0-9]{1,10}(\.[0-9]{1,6})?$`)

// ParseMoney reads "5", "5.00" or "0.000150".
func ParseMoney(s string) (Money, error) {
	s = strings.TrimSpace(s)
	if !reMoney.MatchString(s) {
		return 0, fmt.Errorf("%q is not an amount like 12.50", s)
	}
	whole, frac, _ := strings.Cut(s, ".")
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	frac += strings.Repeat("0", 6-len(frac))
	f, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, err
	}
	m := Money(w)*microsPerUnit + Money(f)
	if m > maxMoney {
		return 0, errors.New("that amount is more than any budget means")
	}
	return m, nil
}

// String is the amount with at least two decimals.
func (m Money) String() string {
	neg := ""
	if m < 0 {
		neg, m = "-", -m
	}
	s := fmt.Sprintf("%s%d.%06d", neg, m/microsPerUnit, m%microsPerUnit)
	for strings.HasSuffix(s, "0") && len(s)-strings.Index(s, ".") > 3 {
		s = s[:len(s)-1]
	}
	return s
}

var reCurrency = regexp.MustCompile(`^[A-Z]{3}$`)

// costOf is what a call cost on a route: tokens times the route's prices
// per million, rounded up to the next millionth.
func costOf(priceIn, priceOut Money, in, out int) Money {
	total := int64(priceIn)*int64(in) + int64(priceOut)*int64(out)
	return Money((total + 999_999) / 1_000_000)
}

// prices are a route's, parsed; zero when it declares none.
func (r Route) prices() (in, out Money, err error) {
	if r.PriceIn != "" {
		if in, err = ParseMoney(r.PriceIn); err != nil {
			return 0, 0, fmt.Errorf("route %s's input price: %w", r.Name, err)
		}
	}
	if r.PriceOut != "" {
		if out, err = ParseMoney(r.PriceOut); err != nil {
			return 0, 0, fmt.Errorf("route %s's output price: %w", r.Name, err)
		}
	}
	return in, out, nil
}

// caps are a budget's money limits, parsed; zero is none.
func (b Budget) caps() (day, month Money, err error) {
	if b.MoneyPerDay != "" {
		if day, err = ParseMoney(b.MoneyPerDay); err != nil {
			return 0, 0, fmt.Errorf("%s's daily budget: %w", b.Consumer, err)
		}
	}
	if b.MoneyPerMonth != "" {
		if month, err = ParseMoney(b.MoneyPerMonth); err != nil {
			return 0, 0, fmt.Errorf("%s's monthly budget: %w", b.Consumer, err)
		}
	}
	return day, month, nil
}
