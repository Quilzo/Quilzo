// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package baseline

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

const country = Dimension("country")

func seen(p *Profile, d Dimension, value string, n int) {
	for i := range n {
		p.Observe(d, value, at.Add(time.Duration(i)*time.Hour))
	}
}

// The failure that makes UEBA unusable at small scale.
//
// Not wrong answers — confident answers from no data. An entity seen four
// times has no baseline, and the fifth thing it does is new, which is true of
// every fifth thing and therefore says nothing.
func TestNoBaselineIsNotAnAnomaly(t *testing.T) {
	p := NewProfile("okta:u-1")
	seen(p, country, "GB", 4)

	v := p.Judge(country, "BR")
	if v.Enough {
		t.Fatalf("four observations were treated as a baseline")
	}
	if !strings.Contains(v.Why(), "no opinion") {
		t.Errorf("the verdict reads as a finding: %s", v.Why())
	}
	// And it is not "normal" either. A caller that reads Enough=false as
	// either verdict is inventing the part this refused to answer.
	if !v.New() {
		t.Error("the value is genuinely new and the verdict says otherwise")
	}
}

func TestABaselineArrivesWithTheDenominator(t *testing.T) {
	p := NewProfile("okta:u-1")
	seen(p, country, "GB", MinObservations)

	v := p.Judge(country, "BR")
	if !v.Enough {
		t.Fatalf("%d observations is not enough for a baseline", MinObservations)
	}
	if !v.New() {
		t.Error("BR has never been seen and is not reported as new")
	}
	// The denominator is the whole point: "never before" means something
	// different against 12 than against 12,000.
	if v.Total != MinObservations {
		t.Errorf("the verdict compares against %d", v.Total)
	}
	if !strings.Contains(v.Why(), fmt.Sprint(MinObservations)) {
		t.Errorf("the explanation omits what it was computed from: %s", v.Why())
	}
}

func TestAKnownValueReportsHowOftenAndSinceWhen(t *testing.T) {
	p := NewProfile("okta:u-1")
	seen(p, country, "GB", 40)
	seen(p, country, "IE", 2)

	v := p.Judge(country, "IE")
	if v.New() {
		t.Fatal("IE has been seen twice and is reported as new")
	}
	if v.Seen != 2 || v.Total != 42 {
		t.Errorf("IE is %d of %d", v.Seen, v.Total)
	}
	if got := v.Share(); got < 0.04 || got > 0.05 {
		t.Errorf("IE is %.3f of the history", got)
	}
	if v.First.IsZero() {
		t.Error("the verdict does not say when it was first seen")
	}
}

// -- the thing that makes a patient attacker normal --------------------------

func TestJudgingDoesNotTeach(t *testing.T) {
	// Self-baselining that folds in the event under examination is how an
	// attacker who moves slowly becomes normal: the profile follows whoever
	// is patient enough to match its pace.
	p := NewProfile("okta:u-1")
	seen(p, country, "GB", MinObservations)

	for range 10 {
		v := p.Judge(country, "BR")
		if !v.New() {
			t.Fatal("judging a value taught the profile about it, so the " +
				"tenth attempt from a new country looks established")
		}
	}
	if p.Total(country) != MinObservations {
		t.Errorf("the history grew to %d by being read", p.Total(country))
	}
}

// -- stacking, which is the part that works at small scale -------------------

func TestTheRarestValuesComeFirst(t *testing.T) {
	// Malicious activity is rare by definition, and rarity here is absolute
	// within whatever data exists rather than relative to a peer group —
	// which is exactly why it works at a size where peer comparison does not.
	p := NewProfile("okta:u-1")
	seen(p, "user_agent", "Chrome/140", 500)
	seen(p, "user_agent", "Safari/19", 60)
	seen(p, "user_agent", "python-requests/2.32", 1)

	got := p.Values("user_agent")
	if len(got) != 3 {
		t.Fatalf("%d value(s)", len(got))
	}
	if got[0].Value != "python-requests/2.32" {
		t.Errorf("the rarest value is %q", got[0].Value)
	}
	if got[2].Value != "Chrome/140" {
		t.Errorf("the commonest value is %q", got[2].Value)
	}
}

func TestTheOrderIsStable(t *testing.T) {
	// A hunt list that reorders between runs is one nobody can work through.
	p := NewProfile("okta:u-1")
	for _, v := range []string{"a", "b", "c", "d", "e"} {
		seen(p, country, v, 3)
	}
	first := fmt.Sprint(p.Values(country))
	for range 20 {
		if got := fmt.Sprint(p.Values(country)); got != first {
			t.Fatal("the list reordered between identical runs")
		}
	}
}

func TestAMissingValueIsNotAnObservation(t *testing.T) {
	// Counting it would make "the field was absent" the commonest value of
	// every dimension, and quietly make the real values look rarer.
	p := NewProfile("okta:u-1")
	seen(p, country, "GB", 10)
	p.Observe(country, "", at)
	p.Observe(country, "   ", at)
	if p.Total(country) != 10 {
		t.Errorf("an absent value was counted; total is %d", p.Total(country))
	}
}

// -- peers, and refusing to pretend there are any ----------------------------

func TestNoPeerComparisonWithoutPeers(t *testing.T) {
	// A "peer group" of eleven is not a peer group. A comparison against one
	// reads as evidence while being noise.
	pop := NewPopulation()
	for i := range 11 {
		p := pop.For(fmt.Sprintf("okta:u-%d", i))
		seen(p, country, "GB", MinObservations)
	}
	v := pop.Judge("okta:u-0", country, "BR")
	if v.Population != 0 {
		t.Errorf("a population of %d was compared against", v.Population)
	}
	if strings.Contains(v.Why(), "population") {
		t.Errorf("the explanation claims a comparison it did not make: %s",
			v.Why())
	}
	// The entity's own history still answers, which is the point: the small
	// case gets a real verdict rather than a degraded one.
	if !v.Enough || !v.New() {
		t.Errorf("the entity's own history was not consulted: %+v", v)
	}
}

func TestPeersAreComparedOnceThereAreEnough(t *testing.T) {
	pop := NewPopulation()
	for i := range MinPopulation + 10 {
		p := pop.For(fmt.Sprintf("okta:u-%d", i))
		seen(p, country, "GB", MinObservations)
	}
	// Half the population has also been to Ireland.
	for i := range 30 {
		pop.For(fmt.Sprintf("okta:u-%d", i)).Observe(country, "IE", at)
	}

	// Nobody has been to Brazil: novel for the entity and for everyone.
	v := pop.Judge("okta:u-0", country, "BR")
	if v.Population < MinPopulation {
		t.Fatalf("population is %d", v.Population)
	}
	if v.Peers != 0 {
		t.Errorf("%d peer(s) have been to BR", v.Peers)
	}
	if !strings.Contains(v.Why(), "none of") {
		t.Errorf("the explanation does not say the population agrees: %s",
			v.Why())
	}

	// New for this entity and ordinary for everyone else, which is a much
	// weaker finding and has to read as one.
	v = pop.Judge("okta:u-55", country, "IE")
	if v.Peers == 0 {
		t.Fatal("30 peers have been to IE and none was counted")
	}
	if !strings.Contains(v.Why(), "though") {
		t.Errorf("a finding the population contradicts reads as: %s", v.Why())
	}
}

func TestAnEntityIsNotItsOwnPeer(t *testing.T) {
	pop := NewPopulation()
	for i := range MinPopulation + 1 {
		seen(pop.For(fmt.Sprintf("okta:u-%d", i)), country, "GB", MinObservations)
	}
	v := pop.Judge("okta:u-0", country, "GB")
	// u-0 has been to GB, and counting itself would make every value look
	// one peer more ordinary than it is.
	if v.Peers != MinPopulation {
		t.Errorf("%d peer(s) counted out of a population of %d including "+
			"the entity itself", v.Peers, v.Population)
	}
}

func TestRareAcrossThePopulationNeedsAPopulation(t *testing.T) {
	pop := NewPopulation()
	for i := range 10 {
		seen(pop.For(fmt.Sprintf("okta:u-%d", i)), "user_agent", "Chrome/140", 5)
	}
	if got := pop.Rare("user_agent", 2); got != nil {
		t.Errorf("a population of 10 produced a rarity list: %v", got)
	}

	for i := 10; i < MinPopulation+5; i++ {
		seen(pop.For(fmt.Sprintf("okta:u-%d", i)), "user_agent", "Chrome/140", 5)
	}
	pop.For("okta:u-3").Observe("user_agent", "python-requests/2.32", at)

	got := pop.Rare("user_agent", 2)
	if len(got) != 1 || got[0].Value != "python-requests/2.32" {
		t.Fatalf("the rarity list is %v", got)
	}
	if got[0].Seen != 1 {
		t.Errorf("one account presented it and %d was reported", got[0].Seen)
	}
}

// An entity with no history still supports a claim about the population.
//
// "A three-day-old account did something nobody here has ever done" is among
// the most useful sentences available, and it is exactly the case an
// entity-only baseline throws away as "no opinion".
func TestANewEntityStillGetsThePopulationsOpinion(t *testing.T) {
	pop := NewPopulation()
	for i := range MinPopulation + 5 {
		seen(pop.For(fmt.Sprintf("okta:u-%d", i)), country, "GB", MinObservations)
	}

	// A brand-new account, from somewhere nobody has been.
	v := pop.Judge("okta:new", country, "BR")
	if v.Enough {
		t.Fatal("an account with no history was given a baseline")
	}
	if v.Peers != 0 || v.Population < MinPopulation {
		t.Fatalf("peers %d of population %d", v.Peers, v.Population)
	}
	if !strings.Contains(v.Why(), "none of") {
		t.Errorf("the population's opinion was discarded: %s", v.Why())
	}

	// And the same account doing the ordinary thing reads as ordinary,
	// rather than as an anomaly because the account is young.
	v = pop.Judge("okta:new", country, "GB")
	if !strings.Contains(v.Why(), "ordinary") {
		t.Errorf("a new account doing the normal thing reads as: %s", v.Why())
	}
}
