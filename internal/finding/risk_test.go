// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var riskNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func rf(issuer, who, rule string, sev telemetry.Severity, state State,
	age time.Duration) Finding {
	return Finding{ID: issuer + who + rule, Kind: FromDetection, Source: rule,
		Title: rule, Entity: telemetry.ID{Issuer: issuer, Value: who},
		Severity: sev, State: state, Last: riskNow.Add(-age),
		First: riskNow.Add(-age)}
}

func aliases(m map[string]string) func(telemetry.ID) string {
	return func(id telemetry.ID) string { return m[id.String()] }
}

// Three medium findings about one person, from three rules on two
// platforms, outrank one high finding about somebody else.
func TestSeveralSmallFindingsAboutOnePersonAddUp(t *testing.T) {
	med, high := telemetry.SeverityMedium, telemetry.SeverityHigh
	all := []Finding{
		rf("okta", "00u1", "okta.api-token-created", med, Open, time.Hour),
		rf("okta", "00u1", "okta.signin-through-proxy", med, Open, 2*time.Hour),
		rf("github", "dana-gh", "github.deploy-key-added", med, Triaged, 3*time.Hour),
		rf("okta", "00u2", "okta.mfa-reset", high, Open, time.Hour),
	}
	got := Risk(all, aliases(map[string]string{"okta:00u1": "dana@acme.com",
		"github:dana-gh": "dana@acme.com"}), riskNow)
	if len(got) != 2 || got[0].Entity != "dana@acme.com" || !got[0].Person {
		t.Fatalf("%+v", got)
	}
	dana, other := got[0], got[1]
	// 3 × 15 = 45, three rules ×1.5 = 67.5; the single high is 40.
	if math.Abs(dana.Score-67.5) > 1e-9 || math.Abs(other.Score-40) > 1e-9 {
		t.Errorf("scores %.1f and %.1f", dana.Score, other.Score)
	}
	if dana.Rules != 3 || strings.Join(dana.Identifiers, ",") != "github:dana-gh,okta:00u1" {
		t.Errorf("rules %d, identifiers %v", dana.Rules, dana.Identifiers)
	}
	// The number is its parts and the breadth, and says so.
	sum := 0.0
	for _, p := range dana.Parts {
		sum += p.Points
	}
	if math.Abs(sum*breadth(dana.Rules)-dana.Score) > 1e-9 ||
		!strings.Contains(dana.Why(), "3 findings worth 45") ||
		!strings.Contains(dana.Why(), "3 different rules") {
		t.Errorf("why: %s", dana.Why())
	}
	if other.Person || other.Entity != "okta:00u2" || other.Band != "medium" {
		t.Errorf("an unknown identifier: %+v", other)
	}
	// Without the alias table the same findings are two strangers.
	if apart := Risk(all, nil, riskNow); len(apart) != 3 {
		t.Errorf("%d rows with nobody joined", len(apart))
	}
}

func TestWhatWasRuledAwayOrIsOldOrOnTrialIsNotRisk(t *testing.T) {
	high := telemetry.SeverityHigh
	trial := rf("okta", "a", "r1", high, Open, time.Hour)
	trial.Trial = true
	nobody := rf("", "", "r1", high, Open, time.Hour)
	all := []Finding{
		rf("okta", "a", "r2", high, FalsePositive, time.Hour),
		rf("okta", "a", "r3", high, Benign, time.Hour),
		rf("okta", "a", "r4", high, Fixed, time.Hour),
		rf("okta", "a", "r5", high, Stale, time.Hour),
		rf("okta", "a", "r6", high, Open, 20*24*time.Hour),
		trial, nobody,
	}
	if got := Risk(all, nil, riskNow); len(got) != 0 {
		t.Fatalf("risk from what was ruled away, old, on trial or about nobody: %+v", got)
	}
	// It fades: the same finding is worth less a week on, and less again.
	for age, want := range map[time.Duration]float64{
		time.Hour: 40, 3 * 24 * time.Hour: 20, 10 * 24 * time.Hour: 10,
	} {
		got := Risk([]Finding{rf("okta", "a", "r", high, Open, age)}, nil, riskNow)
		if len(got) != 1 || got[0].Score != want {
			t.Errorf("at %s: %+v, want %.0f", age, got, want)
		}
	}
	// One rule firing five times is not five rules: no breadth.
	var same []Finding
	for _, who := range []string{"a"} {
		for i := 0; i < 5; i++ {
			f := rf("okta", who, "r", telemetry.SeverityMedium, Open, time.Hour)
			f.ID += string(rune('a' + i))
			same = append(same, f)
		}
	}
	if got := Risk(same, nil, riskNow); got[0].Rules != 1 || got[0].Score != 75 {
		t.Errorf("one rule five times: %+v", got[0])
	}
	// Breadth is capped.
	if breadth(20) != 2 || breadth(1) != 1 {
		t.Error("breadth")
	}
	// A correlation grouped by person is already about the person.
	person := rf("person", "dana@acme.com", "corr.x", high, Open, time.Hour)
	own := rf("okta", "00u1", "okta.mfa-reset", high, Open, time.Hour)
	got := Risk([]Finding{person, own}, aliases(map[string]string{
		"okta:00u1": "dana@acme.com"}), riskNow)
	if len(got) != 1 || got[0].Band != "high" || got[0].Score != 100 {
		t.Errorf("%+v", got)
	}
}
