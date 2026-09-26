// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package proving

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

// aRule is a detection with fixtures both ways, so it loads.
func aRule(id, field, value string) detect.Rule {
	return detect.Rule{
		ID: id, Title: id,
		Why:     "a test detection",
		Blind:   "anything not in " + field,
		Sources: []string{"test"},
		When: detect.Predicate{Match: &detect.Match{
			Field: field, Op: detect.Contains, Values: []string{value}}},
		Severity: telemetry.SeverityMedium,
		Fixtures: []detect.Fixture{
			{Name: "the thing it looks for", Match: true,
				Event: ev("test", map[string]string{raw(field): value})},
			{Name: "something adjacent", Match: false,
				Event: ev("test", map[string]string{raw(field): "unrelated"})},
		},
	}
}

// raw strips the prefix Fields adds, so a rule that reads "raw.cmd" is
// given an event whose Raw map has the key "cmd".
func raw(field string) string {
	return strings.TrimPrefix(field, "raw.")
}

func ev(src string, r map[string]string) telemetry.Event {
	// Received as well as Time: internal/telemetry keeps them apart
	// because the gap between them is what tells a late delivery from a
	// quiet period.
	return telemetry.Event{
		Source: src, Raw: r, Time: t0, Received: t0,
		Class: telemetry.ClassProcessActivity, Activity: 1,
		Severity: telemetry.SeverityLow,
	}
}

// recording builds n events over a window, of which hits contain the
// needle. Deliberately mostly benign, which is the shape of real telemetry
// and the thing a rule has to survive.
func recording(n, hits int, field, needle string) []telemetry.Event {
	out := make([]telemetry.Event, 0, n)
	for i := range n {
		v := fmt.Sprintf("ordinary activity %d", i)
		if i%max(1, n/max(1, hits)) == 0 && hits > 0 {
			v = "something " + needle + " happened"
			hits--
		}
		e := ev("test", map[string]string{raw(field): v})
		e.Time = t0.Add(time.Duration(i) * 30 * time.Second)
		e.Received = e.Time
		out = append(out, e)
	}
	return out
}

func proposed(t *testing.T, r detect.Rule, o Origin) *Candidate {
	t.Helper()
	c, err := Propose(r, o, t0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func byPerson() Origin {
	return Origin{Kind: ByPerson, Who: "ada", At: t0}
}

// TestEverythingStartsInShadow, including a signed feed.
func TestEverythingStartsInShadow(t *testing.T) {
	for _, o := range []Origin{
		byPerson(),
		{Kind: ByFeed, Who: "sigmahq", Version: "r2026-09-01",
			Signed: true, At: t0},
		{Kind: ByAgent, Who: "assistant", Asked: "ada", At: t0},
	} {
		c := proposed(t, aRule("r", "raw.cmd", "needle"), o)
		if c.Ring != Shadow {
			t.Fatalf("%s started in %s", o.Kind, c.Ring)
		}
	}
}

func TestAnOriginHasToSayEnough(t *testing.T) {
	for _, c := range []struct {
		name string
		o    Origin
	}{
		{"no kind", Origin{Who: "ada"}},
		{"nobody", Origin{Kind: ByPerson}},
		{"a feed with no version", Origin{Kind: ByFeed, Who: "sigmahq"}},
		{"an agent with nobody who asked",
			Origin{Kind: ByAgent, Who: "assistant"}},
	} {
		if _, err := Propose(aRule("r", "raw.cmd", "x"), c.o, t0); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// TestNothingSkipsARing.
func TestNothingSkipsARing(t *testing.T) {
	c := proposed(t, aRule("r", "raw.cmd", "needle"), byPerson())
	err := c.May(Live, "grace", t0)
	if err == nil {
		t.Fatal("shadow went straight to live")
	}
	if !strings.Contains(err.Error(), "canary") {
		t.Fatalf("the refusal does not say what comes next: %v", err)
	}
}

// TestPromotionNeedsAReplayAndTheReplayHasToBeBigEnough.
func TestPromotionNeedsAReplayAndTheReplayHasToBeBigEnough(t *testing.T) {
	r := aRule("r", "raw.cmd", "needle")
	c := proposed(t, r, byPerson())
	soaked := t0.Add(MinSoak + time.Hour)

	err := c.May(Canary, "grace", soaked)
	if err == nil {
		t.Fatal("promoted with nothing replayed")
	}
	if !strings.Contains(err.Error(), "how often it would fire") {
		t.Fatalf("the refusal is not about the missing number: %v", err)
	}

	// A small replay is not enough to decide on.
	small := Run(r, recording(500, 5, "raw.cmd", "needle"), "a day", t0)
	if err := c.Prove(small); err != nil {
		t.Fatal(err)
	}
	if err := c.May(Canary, "grace", soaked); err == nil {
		t.Fatal("promoted on 500 events")
	}

	// A big one over a long enough window is.
	big := Run(r, recording(20_000, 40, "raw.cmd", "needle"), "a week", t0)
	if err := big.Enough(); err != nil {
		t.Fatalf("a 20,000 event replay was not enough: %v", err)
	}
	if err := c.Prove(big); err != nil {
		t.Fatal(err)
	}
	if err := c.May(Canary, "grace", soaked); err != nil {
		t.Fatalf("still refused: %v", err)
	}
}

// TestSoakTime.
func TestSoakTime(t *testing.T) {
	r := aRule("r", "raw.cmd", "needle")
	c := proposed(t, r, byPerson())
	if err := c.Prove(Run(r, recording(20_000, 40, "raw.cmd", "needle"),
		"a week", t0)); err != nil {
		t.Fatal(err)
	}
	if err := c.May(Canary, "grace", t0.Add(time.Hour)); err == nil {
		t.Fatal("promoted after an hour")
	} else if !strings.Contains(err.Error(), "soak") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if err := c.May(Canary, "grace", t0.Add(MinSoak)); err != nil {
		t.Fatalf("refused at exactly the soak: %v", err)
	}
}

// TestARuleThatMatchesEverythingIsRefused is the Channel File 291 shape.
func TestARuleThatMatchesEverythingIsRefused(t *testing.T) {
	// A rule whose value appears in every event, which is what a wildcard
	// in the test data hides.
	wide := aRule("wide", "raw.cmd", "activity")
	wide.Fixtures[1].Event = ev("test",
		map[string]string{"cmd": "nothing like it"})
	c := proposed(t, wide, byPerson())
	p := Run(wide, recording(20_000, 0, "raw.cmd", "needle"), "a week", t0)
	if !p.Indiscriminate() {
		t.Fatalf("matched %.0f%% and was not called indiscriminate",
			p.Share()*100)
	}
	if err := c.Prove(p); err != nil {
		t.Fatal(err)
	}
	err := c.May(Canary, "grace", t0.Add(MinSoak+time.Hour))
	if err == nil {
		t.Fatal("a rule matching everything was promoted")
	}
	if !strings.Contains(err.Error(), "291") {
		t.Fatalf("the refusal does not say where this comes from: %v", err)
	}
}

// TestTheModelCannotBeItsOwnReviewer.
func TestTheModelCannotBeItsOwnReviewer(t *testing.T) {
	r := aRule("r", "raw.cmd", "needle")
	c := proposed(t, r, Origin{Kind: ByAgent, Who: "assistant",
		Asked: "ada", At: t0})
	if err := c.Prove(Run(r, recording(20_000, 40, "raw.cmd", "needle"),
		"a week", t0)); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(MinSoak + time.Hour)
	err := c.May(Canary, "ada", at)
	if err == nil {
		t.Fatal("the person who asked for it accepted it")
	}
	if !strings.Contains(err.Error(), "reviewed by the request") {
		t.Fatalf("the refusal does not explain: %v", err)
	}
	if err := c.May(Canary, "grace", at); err != nil {
		t.Fatalf("somebody else was refused: %v", err)
	}
	// And a rule from a model is held to the same gates as anybody's: no
	// replay, no promotion, regardless of who accepts it.
	bare := proposed(t, r, Origin{Kind: ByAgent, Who: "assistant",
		Asked: "ada", At: t0})
	if err := bare.May(Canary, "grace", at); err == nil {
		t.Fatal("a model's rule was promoted without a replay")
	}
}

// TestARuleWithNoFixturesCannotBePromoted — an imported Sigma rule.
func TestARuleWithNoFixturesCannotBePromoted(t *testing.T) {
	r := aRule("imported", "raw.cmd", "needle")
	r.Fixtures = nil
	c := proposed(t, r, Origin{Kind: ByFeed, Who: "sigmahq",
		Version: "r2026-09-01", At: t0})
	if err := c.Prove(Run(r, recording(20_000, 40, "raw.cmd", "needle"),
		"a week", t0)); err != nil {
		t.Fatal(err)
	}
	err := c.May(Canary, "grace", t0.Add(MinSoak+time.Hour))
	if err == nil {
		t.Fatal("a rule with no fixtures was promoted")
	}
	if !strings.Contains(err.Error(), "discriminate") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestPromotionRecordsTheVolumeThatWasAccepted.
func TestPromotionRecordsTheVolumeThatWasAccepted(t *testing.T) {
	r := aRule("r", "raw.cmd", "needle")
	c := proposed(t, r, byPerson())
	p := Run(r, recording(20_000, 40, "raw.cmd", "needle"), "a week", t0)
	if err := c.Prove(p); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(MinSoak + time.Hour)
	if err := c.Promote(Canary, "grace", "looks right", at); err != nil {
		t.Fatal(err)
	}
	if c.Ring != Canary {
		t.Fatalf("ring = %s", c.Ring)
	}
	last := c.Promotions[len(c.Promotions)-1]
	if last.Volume <= 0 || last.Volume != p.PerDay() {
		t.Fatalf("volume recorded as %v, replay says %v", last.Volume,
			p.PerDay())
	}
	if last.By != "grace" {
		t.Fatalf("by = %q", last.By)
	}
}

// TestAQuietRuleCanReachLiveOnlyWithAStatedReason.
func TestAQuietRuleCanReachLiveOnlyWithAStatedReason(t *testing.T) {
	r := aRule("quiet", "raw.cmd", "neverhappens")
	c := proposed(t, r, byPerson())
	p := Run(r, recording(20_000, 0, "raw.cmd", "needle"), "a week", t0)
	if p.Fired() {
		t.Fatal("the fixture is not quiet")
	}
	if err := c.Prove(p); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(MinSoak + time.Hour)
	if err := c.Promote(Canary, "grace", "", at); err != nil {
		t.Fatal(err)
	}
	later := at.Add(MinSoak + time.Hour)
	if err := c.Promote(Live, "grace", "", later); err == nil {
		t.Fatal("a rule that never fired went live silently")
	}
	if err := c.Promote(Live, "grace",
		"correct and quiet; the technique is rare here", later); err != nil {
		t.Fatalf("a stated reason was still refused: %v", err)
	}
	if c.Ring != Live {
		t.Fatalf("ring = %s", c.Ring)
	}
}

// TestABadBatchIsRecalledAsABatch.
func TestABadBatchIsRecalledAsABatch(t *testing.T) {
	e := &Estate{}
	for i := range 4 {
		o := Origin{Kind: ByFeed, Who: "sigmahq", Version: "r2026-09-01",
			At: t0}
		if i == 3 {
			o.Version = "r2026-08-01"
		}
		e.Add(proposed(t, aRule(fmt.Sprintf("r%d", i), "raw.cmd", "x"), o))
	}
	batch := e.FromBatch("sigmahq", "r2026-09-01")
	if len(batch) != 3 {
		t.Fatalf("%d in the batch", len(batch))
	}
	got, err := e.Recall("sigmahq", "r2026-09-01", "ada",
		"the release matched everything", t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("recalled %d", len(got))
	}
	for _, c := range got {
		if c.Ring != Retired {
			t.Fatalf("%s is %s", c.Rule.ID, c.Ring)
		}
	}
	if len(e.In(Shadow)) != 1 {
		t.Fatal("the older release was recalled too")
	}
	if _, err := e.Recall("sigmahq", "nosuch", "ada", "x", t0); err == nil {
		t.Fatal("recalled a release that is not here")
	}
}

func TestRetiringNeedsAReason(t *testing.T) {
	c := proposed(t, aRule("r", "raw.cmd", "x"), byPerson())
	if err := c.Retire("ada", "", t0); err == nil {
		t.Fatal("a detection vanished without a reason")
	}
	if err := c.Retire("ada", "replaced by r2", t0); err != nil {
		t.Fatal(err)
	}
	if err := c.May(Canary, "grace", t0); err == nil {
		t.Fatal("a retired candidate was revived")
	}
}

// TestCompareShowsWhatATuningChangeStoppedCatching.
func TestCompareShowsWhatATuningChangeStoppedCatching(t *testing.T) {
	events := recording(2_000, 200, "raw.cmd", "needle")
	was := aRule("v1", "raw.cmd", "needle")
	// A "tuning" edit that is really a narrowing.
	now := aRule("v2", "raw.cmd", "needle happened at")
	c := Compare(was, now, events, "a week", t0)
	if c.Lost == 0 {
		t.Fatal("the fixture does not lose anything")
	}
	if !c.Quieter() {
		t.Fatal("the narrowed rule is not quieter")
	}
	if len(c.LostSamples) == 0 {
		t.Fatal("nothing was kept to show what stopped being caught")
	}
	why := c.Why()
	if !strings.Contains(why, "stops catching") {
		t.Fatalf("why = %q", why)
	}
	// And a change that does nothing says so.
	same := Compare(was, aRule("v3", "raw.cmd", "needle"), events, "x", t0)
	if same.Why() != "this changes nothing about what it matches" {
		t.Fatalf("why = %q", same.Why())
	}
}

// TestAnUnlabelledReplayDoesNotClaimPrecision.
func TestAnUnlabelledReplayDoesNotClaimPrecision(t *testing.T) {
	r := aRule("r", "raw.cmd", "needle")
	p := Run(r, recording(20_000, 40, "raw.cmd", "needle"), "a week", t0)
	if _, ok := p.Precision(); ok {
		t.Fatal("precision was reported for unlabelled events")
	}
	if !strings.Contains(p.Why(), "nothing about whether it is right") {
		t.Fatalf("why = %q", p.Why())
	}

	// With labels it reports both, and gets them right.
	events := recording(2_000, 100, "raw.cmd", "needle")
	bad := func(e telemetry.Event) bool {
		return strings.Contains(e.Raw["cmd"], "needle")
	}
	l := Labelled(r, events, bad, "a week", t0)
	got, ok := l.Precision()
	if !ok {
		t.Fatal("no precision from a labelled replay")
	}
	if got != 1 {
		t.Fatalf("precision = %v; every match was genuinely bad", got)
	}
	if !strings.Contains(l.Why(), "100% of the labelled matches were real") {
		t.Fatalf("why = %q", l.Why())
	}
}

// TestTheEstateKnowsHowLoudItIs.
func TestTheEstateKnowsHowLoudItIs(t *testing.T) {
	e := &Estate{}
	at := t0.Add(MinSoak + time.Hour)
	for i, hits := range []int{40, 400, 4} {
		r := aRule(fmt.Sprintf("r%d", i), "raw.cmd", "needle")
		c := proposed(t, r, byPerson())
		p := Run(r, recording(20_000, hits, "raw.cmd", "needle"), "a week",
			t0)
		p.Matched = hits // the recording approximates; be exact here
		if err := c.Prove(p); err != nil {
			t.Fatal(err)
		}
		if err := c.Promote(Canary, "grace", "", at); err != nil {
			t.Fatalf("r%d: %v", i, err)
		}
		e.Add(c)
	}
	n := e.Noise()
	if n.Rules != 3 {
		t.Fatalf("%d loud rule(s)", n.Rules)
	}
	if n.Worst != "r1" {
		t.Fatalf("worst = %q", n.Worst)
	}
	if n.PerDay < 50 {
		t.Fatalf("per day = %v", n.PerDay)
	}
	loudest := e.Loudest()
	if len(loudest) != 3 || loudest[0].Rule.ID != "r1" {
		t.Fatalf("loudest = %s", loudest[0].Rule.ID)
	}
	// A candidate in shadow makes no noise, because it wakes nobody.
	quiet := proposed(t, aRule("r9", "raw.cmd", "needle"), byPerson())
	if err := quiet.Prove(Run(quiet.Rule,
		recording(20_000, 900, "raw.cmd", "needle"), "a week", t0)); err != nil {
		t.Fatal(err)
	}
	e.Add(quiet)
	if e.Noise().Rules != 3 {
		t.Fatal("a shadow rule was counted as noise")
	}
}
