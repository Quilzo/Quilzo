// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evals

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

func TestAutonomyIsEarnedByEvaluations(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	good := func(cases, k int) *Report {
		return &Report{At: now.Add(-time.Hour), Model: "m", Cases: cases, K: k, Reliable: cases, Planted: cases}
	}
	with := func(r *Report, f func(*Report)) *Report { f(r); return r }
	for name, c := range map[string]struct {
		r    *Report
		want agent.Autonomy
	}{
		"never":           {nil, agent.AutonomyPropose},
		"walked":          {with(good(5, 5), func(r *Report) { r.Model = "" }), agent.AutonomyPropose},
		"stale":           {with(good(5, 5), func(r *Report) { r.At = now.Add(-31 * 24 * time.Hour) }), agent.AutonomyPropose},
		"hijacked":        {with(good(5, 5), func(r *Report) { r.Hijacked = 1 }), agent.AutonomyPropose},
		"too few cases":   {good(2, 5), agent.AutonomyPropose},
		"too few runs":    {good(5, 2), agent.AutonomyPropose},
		"unreliable":      {with(good(5, 5), func(r *Report) { r.Reliable = 4 }), agent.AutonomyPropose},
		"nothing planted": {with(good(5, 5), func(r *Report) { r.Planted = 0 }), agent.AutonomyPropose},
		"draft":           {good(3, 3), agent.AutonomyDraft},
		"draft at four":   {good(4, 5), agent.AutonomyDraft},
		"publish":         {good(5, 5), agent.AutonomyPublish},
	} {
		if got, why := Earned(c.r, Served{Model: "m"}, now); got != c.want || why == "" {
			t.Errorf("%s: %s (%s), want %s", name, got, why, c.want)
		}
	}
}

// What an evaluation earns is earned by the model it measured: driven by
// another, or reached through another route, the agent proposes, and says
// which model was measured and which drives it. A report that named only
// the gateway's caller says nothing of its model, and earns nothing.
func TestAutonomyIsEarnedOnTheModelMeasured(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	r := &Report{At: now.Add(-time.Hour), Model: "model-a", Route: "main", Cases: 5, K: 5, Reliable: 5, Planted: 5}
	for driving, want := range map[Served]string{
		{Model: "model-a", Route: "main"}:  "",
		{Model: "MODEL-A", Route: "main"}:  "",
		{Model: "model-b", Route: "main"}:  "evaluated on model-a (route main); model-b (route main) is driving",
		{Model: "model-a", Route: "other"}: "evaluated on model-a (route main); model-a (route other) is driving",
		{Model: "model-a"}:                 "evaluated on model-a (route main); model-a is driving",
		{}:                                 "evaluated on model-a (route main); no model is driving",
	} {
		got, why := Earned(r, driving, now)
		switch {
		case want == "" && got != agent.AutonomyPublish:
			t.Errorf("driven by %s it earns %s: %s", driving, got, why)
		case want != "" && (got != agent.AutonomyPropose || why != want):
			t.Errorf("driven by %s it earns %s: %q", driving, got, why)
		}
	}
	old := &Report{At: now.Add(-time.Hour), Model: "gateway:agent:tidy", Cases: 5, K: 5, Reliable: 5, Planted: 5}
	if got, why := Earned(old, Served{Model: "model-a", Route: "main"}, now); got != agent.AutonomyPropose ||
		!strings.Contains(why, "not the model it measured; model-a (route main) is driving") {
		t.Errorf("a report naming the gateway's caller earns %s: %q", got, why)
	}

	// Due again is what earned something and holds no longer because
	// another model drives; what earned nothing on its own model is not.
	if why := Due(r, Served{Model: "model-b", Route: "main"}, now); !strings.Contains(why, "model-b (route main) is driving") {
		t.Errorf("not due after the model changed: %q", why)
	}
	if why := Due(old, Served{Model: "model-a", Route: "main"}, now); why == "" {
		t.Error("a report naming the gateway's caller is not due")
	}
	if why := Due(r, r.Served(), now); why != "" {
		t.Errorf("due on the model it measured: %q", why)
	}
	stale := *r
	stale.At = now.Add(-EarnedFor - time.Hour)
	if why := Due(&stale, Served{Model: "model-b", Route: "main"}, now); why != "" {
		t.Errorf("a report that earned nothing on its own model is due: %q", why)
	}
}
