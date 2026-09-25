// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func one(kind Kind, source string, sev telemetry.Severity) Finding {
	return Finding{
		// An id, because Validate requires one and only Register assigns
		// them. A finding constructed by hand and never recorded still has
		// to be identifiable, or an error about it names nothing.
		ID:   Key(kind, source, telemetry.ID{Issuer: "okta", Value: "u-1"}),
		Kind: kind, Title: "something is wrong", Source: source,
		Entity:   telemetry.ID{Issuer: "okta", Value: "u-1"},
		Severity: sev, State: Open, Owner: "dana",
		First: now, Last: now, Seen: 1,
	}
}

// -- one type, five origins --------------------------------------------------

func TestEveryKindIsTheSameShape(t *testing.T) {
	// The point of the package. Five products sell these as five things with
	// five queues and five definitions of closed; a small team then spends
	// its attention on the seams.
	for _, k := range Kinds() {
		f := one(k, "scanner", telemetry.SeverityHigh)
		if err := f.Validate(); err != nil {
			t.Errorf("%s is not workable: %v", k, err)
		}
	}
	if err := (one("invented", "s", telemetry.SeverityLow)).Validate(); err == nil {
		t.Error("an unknown kind was accepted")
	}
}

// -- deduplication -----------------------------------------------------------

func TestTheSameProblemIsOneRowWithACount(t *testing.T) {
	// The difference between a register somebody reads and a queue nobody
	// does.
	r := NewRegister()
	for i := range 700 {
		r.Record(one(FromControl, "posture/tls", telemetry.SeverityMedium),
			now.Add(time.Duration(i)*time.Hour))
	}
	if r.Len() != 1 {
		t.Fatalf("%d row(s) for one repeated problem", r.Len())
	}
	f := r.All(now)[0]
	if f.Seen != 700 {
		t.Errorf("seen %d times", f.Seen)
	}
}

func TestRewordingAMessageDoesNotSplitAFinding(t *testing.T) {
	// Scanners reword between versions. A register that split a finding
	// because a vendor improved their phrasing would double-count every
	// upgrade.
	r := NewRegister()
	a := one(FromVulnerability, "sca", telemetry.SeverityHigh)
	b := a
	b.Title = "CVE-2026-1234 in libfoo (updated wording)"
	r.Record(a, now)
	r.Record(b, now.Add(time.Hour))
	if r.Len() != 1 {
		t.Fatalf("a reworded title produced %d rows", r.Len())
	}
}

func TestTwoDirectoriesAreTwoEntities(t *testing.T) {
	// The identifier-provenance argument from internal/telemetry, arriving
	// where it pays: the same string from two systems is two people.
	r := NewRegister()
	a := one(FromControl, "mdm", telemetry.SeverityMedium)
	b := a
	b.Entity = telemetry.ID{Issuer: "kandji", Value: "u-1"}
	r.Record(a, now)
	r.Record(b, now)
	if r.Len() != 2 {
		t.Fatalf("okta:u-1 and kandji:u-1 merged into %d row(s)", r.Len())
	}
}

func TestSeverityRisesAndDoesNotDriftDown(t *testing.T) {
	r := NewRegister()
	r.Record(one(FromControl, "posture", telemetry.SeverityLow), now)
	r.Record(one(FromControl, "posture", telemetry.SeverityCritical), now)
	if got := r.All(now)[0].Severity; got != telemetry.SeverityCritical {
		t.Errorf("severity is %d after rising", got)
	}
	// A flapping scanner must not be able to talk a finding down.
	r.Record(one(FromControl, "posture", telemetry.SeverityInfo), now)
	if got := r.All(now)[0].Severity; got != telemetry.SeverityCritical {
		t.Errorf("a lower report reduced severity to %d", got)
	}
}

func TestSomethingReportedAgainIsNotFixed(t *testing.T) {
	r := NewRegister()
	f, _ := r.Record(one(FromControl, "posture", telemetry.SeverityHigh), now)
	f.State = Fixed
	r.Record(one(FromControl, "posture", telemetry.SeverityHigh), now.Add(time.Hour))
	if got := r.All(now)[0].State; got != Open {
		t.Errorf("a finding reported again is %s, whatever anybody ticked", got)
	}
}

// -- acceptance is a decision, not a delete ----------------------------------

func TestAnAcceptanceNeedsAReasonAndAnExpiry(t *testing.T) {
	f := one(FromVulnerability, "sca", telemetry.SeverityHigh)
	f.State = Accepted
	if err := f.Validate(); err == nil {
		t.Error("a risk was accepted with no reason")
	}
	f.Because = "no exploit path; the component is not reachable"
	if err := f.Validate(); err == nil {
		t.Error("a risk was accepted for ever")
	}
	f.Until = now.Add(90 * 24 * time.Hour)
	if err := f.Validate(); err != nil {
		t.Errorf("a properly recorded acceptance was refused: %v", err)
	}
}

func TestAnExpiredAcceptanceOutranksAnOpenFinding(t *testing.T) {
	// It is an open finding that the register is reporting as handled, which
	// is worse than one reported as open.
	open := one(FromControl, "a", telemetry.SeverityMedium)
	open.ID = "open"

	lapsed := one(FromControl, "b", telemetry.SeverityMedium)
	lapsed.ID = "lapsed"
	lapsed.State, lapsed.Because = Accepted, "compensating control"
	lapsed.Until = now.Add(-24 * time.Hour)

	got := Rank([]Finding{open, lapsed}, now)
	if got[0].ID != "lapsed" {
		t.Errorf("the list starts with %q", got[0].ID)
	}
	if !strings.Contains(got[0].Why(now), "expired") {
		t.Errorf("the reason does not mention it: %s", got[0].Why(now))
	}
}

// -- ranking, not thresholds -------------------------------------------------

func TestNothingIsHiddenByAThreshold(t *testing.T) {
	// There is no threshold to tune, drift, or argue about. Rank orders what
	// exists and the team works down.
	var in []Finding
	for i, sev := range []telemetry.Severity{
		telemetry.SeverityInfo, telemetry.SeverityLow, telemetry.SeverityHigh,
	} {
		f := one(FromControl, string(rune('a'+i)), sev)
		f.ID = string(rune('a' + i))
		in = append(in, f)
	}
	if got := Rank(in, now); len(got) != len(in) {
		t.Fatalf("ranking returned %d of %d findings", len(got), len(in))
	}
}

func TestAgeCountsAndSaturates(t *testing.T) {
	// An old finding is evidence of a decision not made. Beyond a month the
	// signal stops growing: ignored for a year is not twelve times ignored
	// for a month, it is the same problem with a worse story.
	fresh := one(FromControl, "a", telemetry.SeverityMedium)
	old := one(FromControl, "b", telemetry.SeverityMedium)
	old.First = now.Add(-20 * 24 * time.Hour)
	if old.Weight(now) <= fresh.Weight(now) {
		t.Error("an older finding does not outrank an identical fresh one")
	}

	ancient := old
	ancient.First = now.Add(-400 * 24 * time.Hour)
	capped := old
	capped.First = now.Add(-30 * 24 * time.Hour)
	if ancient.Weight(now) != capped.Weight(now) {
		t.Errorf("age did not saturate: %.1f at 400 days vs %.1f at 30",
			ancient.Weight(now), capped.Weight(now))
	}
}

func TestANoisySourceCannotDominateTheList(t *testing.T) {
	// Without saturation a source that fires constantly takes the whole top
	// of the list purely by being noisy, which is the failure that makes
	// people switch ranking off.
	noisy := one(FromDetection, "chatty", telemetry.SeverityLow)
	noisy.Seen = 10000
	serious := one(FromControl, "real", telemetry.SeverityCritical)

	if noisy.Weight(now) >= serious.Weight(now) {
		t.Errorf("ten thousand low-severity sightings (%.1f) outrank one "+
			"critical finding (%.1f)", noisy.Weight(now), serious.Weight(now))
	}
}

func TestAnUnownedFindingSurfaces(t *testing.T) {
	// Not a severity judgement: it will still be here next month whatever
	// its severity, so it needs to surface while somebody can pick it up.
	owned := one(FromControl, "a", telemetry.SeverityMedium)
	unowned := one(FromControl, "a", telemetry.SeverityMedium)
	unowned.Owner = ""
	if unowned.Weight(now) <= owned.Weight(now) {
		t.Error("an unowned finding does not outrank an identical owned one")
	}
	if !strings.Contains(unowned.Why(now), "unowned") {
		t.Errorf("the reason does not say so: %s", unowned.Why(now))
	}
}

func TestSomethingFixedLeavesTheList(t *testing.T) {
	f := one(FromControl, "a", telemetry.SeverityCritical)
	f.State = Fixed
	if f.Weight(now) != 0 {
		t.Errorf("a fixed finding weighs %.1f", f.Weight(now))
	}
	// And stale is not fixed. A scanner that stopped mentioning something may
	// have been patched, or broken, or lost the asset.
	f.State = Stale
	if f.Weight(now) != 0 {
		t.Errorf("a stale finding weighs %.1f", f.Weight(now))
	}
	if Stale == Fixed {
		t.Error("stale and fixed are the same state")
	}
}

func TestTheOrderIsStable(t *testing.T) {
	var in []Finding
	for i := range 40 {
		f := one(FromControl, "s", telemetry.SeverityMedium)
		f.ID = string(rune('a' + i%26))
		in = append(in, f)
	}
	first := Rank(in, now)
	for range 20 {
		got := Rank(in, now)
		for i := range got {
			if got[i].ID != first[i].ID {
				t.Fatal("the ranked list reordered between identical runs")
			}
		}
	}
}

// -- taint -------------------------------------------------------------------

func TestAFindingBuiltOnLogTextNeedsAPerson(t *testing.T) {
	// An attacker who can write a log line can write a prompt, and a finding
	// resting on that line is one they had a hand in composing. It may be
	// entirely correct and still must not be actioned automatically.
	f := one(FromDetection, "okta-mfa-disabled", telemetry.SeverityHigh)
	f.Evidence = []Evidence{
		{At: now, What: "MFA factor removed", Source: "okta/system",
			Tainted: true},
		{At: now, What: "control check failed", Source: "posture"},
	}
	if !f.Tainted() {
		t.Fatal("evidence from a log source is not marked tainted")
	}
	why := f.NeedsAPerson()
	if why == "" {
		t.Fatal("a finding built on attacker-controlled input may be actioned")
	}
	if !strings.Contains(why, "okta/system") {
		t.Errorf("the reason does not name the source: %s", why)
	}
	// And it names only the tainted one. Saying a clean source is tainted
	// would send a reviewer to check something that is fine.
	if strings.Contains(why, "posture") {
		t.Errorf("a clean source was named as tainted: %s", why)
	}
}

func TestACleanFindingNeedsNobody(t *testing.T) {
	f := one(FromControl, "posture", telemetry.SeverityHigh)
	f.Evidence = []Evidence{{At: now, What: "TLS 1.0 enabled", Source: "posture"}}
	if f.NeedsAPerson() != "" {
		t.Error("a finding from configuration this program read itself was " +
			"marked as needing a person")
	}
}

func TestAFindingWithNoSourceIsRefused(t *testing.T) {
	f := one(FromControl, "", telemetry.SeverityHigh)
	if err := f.Validate(); err == nil {
		t.Error("a finding nobody can trace to what raised it was accepted")
	}
}
