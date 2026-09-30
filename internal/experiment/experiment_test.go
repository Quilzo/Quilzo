// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package experiment

import (
	"math"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
)

var pricing = Experiment{Name: "pricing-cta", Page: "pricing", Goal: "form:contact", Running: true,
	Variants: []Variant{{Name: "a", Page: "pricing", Weight: 50}, {Name: "b", Page: "pricing-b", Weight: 50}}}

func day(seenA, wonA, seenB, wonB int) analytics.Day {
	return analytics.Day{Goals: map[string]int{
		SeenKey("pricing-cta", "a"): seenA, WonKey("pricing-cta", "a"): wonA,
		SeenKey("pricing-cta", "b"): seenB, WonKey("pricing-cta", "b"): wonB}}
}

func TestTooEarlyIsSaidAsTooEarly(t *testing.T) {
	r := Measure(pricing, []analytics.Day{day(50, 1, 50, 20)})
	if r.Ready || !strings.Contains(r.Verdict, "Too early") {
		t.Fatalf("a verdict at 50 visitors: %s", r.Verdict)
	}
}

func TestASignificantDifferenceIsReported(t *testing.T) {
	// 10% against 15% on 1000 each: z ≈ 3.38, p ≈ 0.0007.
	r := Measure(pricing, []analytics.Day{day(600, 60, 600, 90), day(400, 40, 400, 60)})
	b := r.Arms[1]
	if !r.Ready || b.Seen != 1000 || b.Won != 150 {
		t.Fatalf("%+v", r)
	}
	if math.Abs(b.Lift-0.5) > 1e-9 || b.P > 0.001 || b.P < 0.0005 {
		t.Fatalf("lift %.3f p %.5f", b.Lift, b.P)
	}
	if !strings.Contains(r.Verdict, "b converts better than a") {
		t.Fatalf("verdict %q", r.Verdict)
	}
}

func TestNoDifferenceIsNotAWinner(t *testing.T) {
	r := Measure(pricing, []analytics.Day{day(1000, 100, 1000, 104)})
	if !strings.Contains(r.Verdict, "No difference detected") {
		t.Fatalf("a 4-conversion gap was called: %s", r.Verdict)
	}
}

func TestExperimentsAreChecked(t *testing.T) {
	bad := []Experiment{
		{Name: "x", Page: "p", Goal: "form:c", Variants: []Variant{{Name: "a", Page: "p", Weight: 1}}},
		{Name: "x", Page: "p", Goal: "form:c", Variants: []Variant{{Name: "a", Page: "p", Weight: 1}, {Name: "b", Page: "p", Weight: 1}}},
		{Name: "x", Page: "p", Goal: "anything", Variants: pricing.Variants},
		{Name: "x", Page: "../etc", Goal: "form:c", Variants: pricing.Variants},
		{Name: "x", Page: "p", Goal: "form:c", Variants: []Variant{{Name: "a", Page: "p", Weight: 0}, {Name: "b", Page: "q", Weight: 1}}},
	}
	for i, e := range bad {
		if e.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	s := &Set{}
	if err := s.Put(pricing); err != nil {
		t.Fatal(err)
	}
	other := pricing
	other.Name = "pricing-headline"
	other.Variants = []Variant{{Name: "a", Page: "pricing", Weight: 1}, {Name: "c", Page: "pricing-c", Weight: 1}}
	if err := s.Put(other); err == nil {
		t.Fatal("two running experiments on one page were allowed")
	}
}
