// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package pay

import (
	"context"
	"testing"
)

// A row with an interval is a subscription: shown with how often, made a
// recurring price, and a different offer from the same price paid once.
// An interval nobody can read is no offer at all.
func TestARowWithAnIntervalIsASubscription(t *testing.T) {
	row := map[string]any{"slug": "bread-club", "name": "Bread club", "price": float64(1200), "currency": "GBP", "interval": "Month"}
	o, ok := OfferOf(row)
	if !ok || o.Interval != "month" || o.Display() != "£12.00 a month" {
		t.Fatalf("%+v %v %q", o, ok, o.Display())
	}
	once := o
	once.Interval = ""
	if once.Terms() == o.Terms() {
		t.Fatal("monthly and once are the same terms")
	}
	row["interval"] = "fortnight"
	if _, ok := OfferOf(row); ok {
		t.Fatal("an interval nobody can read")
	}
	s, f := stripeAt(t)
	if _, err := s.Make(context.Background(), o, Options{}); err != nil {
		t.Fatal(err)
	}
	if f.forms[0]["recurring[interval]"] != "month" {
		t.Fatalf("not a recurring price: %v", f.forms[0])
	}
	if _, err := s.Make(context.Background(), once, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, set := f.forms[2]["recurring[interval]"]; set {
		t.Fatal("a single payment made recurring")
	}
}
