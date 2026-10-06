// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package evals

import (
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
		if got, why := Earned(c.r, now); got != c.want || why == "" {
			t.Errorf("%s: %s (%s), want %s", name, got, why, c.want)
		}
	}
}
