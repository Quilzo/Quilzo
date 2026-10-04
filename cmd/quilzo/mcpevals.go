// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"sort"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
)

// How each agent last did, for an agent: the numbers, never the goals. A
// test set's goals are prompts somebody wrote to probe an agent, and a
// model reading them is a model being taught the test.
func registerEvalOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "eval_results", NeedsRole: "admin",
		Summary: "how each agent did in its last evaluation: pass^k, and how many " +
			"cases followed an instruction planted in what they read",
		Detail: "One row per agent with a test set: when it was last evaluated, by " +
			"how many runs of each case (k), how many cases passed every run, how " +
			"many were run with planted instructions and how many followed them. " +
			"Read-only. The cases themselves are not returned.",
		Keywords: []string{"agents", "evaluation", "tests", "reliability", "injection", "pass^k"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		set, err := loadAgents(root)
		if err != nil {
			return nil, err
		}
		type row struct {
			Agent    string  `json:"agent"`
			Cases    int     `json:"cases"`
			At       string  `json:"evaluated_at,omitempty"`
			K        int     `json:"k,omitempty"`
			PassK    float64 `json:"pass_k"`
			Reliable int     `json:"reliable"`
			Planted  int     `json:"planted"`
			Hijacked int     `json:"hijacked"`
			Verdict  string  `json:"verdict"`
		}
		var out []row
		for name := range set.Agents {
			cases, _ := loadEvalCases(root, name)
			r := row{Agent: name, Cases: len(cases), Verdict: "not evaluated"}
			if reps, _ := evalReports(root, name, 1); len(reps) > 0 {
				rep := reps[0]
				r.At, r.K, r.PassK = rep.At.Format("2006-01-02T15:04:05Z"), rep.K, rep.PassK
				r.Reliable, r.Planted, r.Hijacked, r.Verdict = rep.Reliable, rep.Planted, rep.Hijacked, rep.Verdict()
			}
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Agent < out[j].Agent })
		return map[string]any{"agents": out}, nil
	})
}
