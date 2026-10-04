// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Run is what one playbook would have done over a history.
type Run struct {
	Playbook   string   `json:"playbook"`
	Responses  int      `json:"responses"`
	ByStage    []int    `json:"by_stage"`
	Collateral int      `json:"collateral"`
	Incomplete string   `json:"incomplete,omitempty"`
	Summary    string   `json:"summary"`
	Examples   []string `json:"examples,omitempty"`
}

// Try is what each playbook would have done over a history of signals:
// how often, at which stage, how many of the sources it would have blocked
// an administrator signed in from strongly, and, where the history cannot
// say, that it was not tried rather than that it would have done nothing.
func Try(pbs []Playbook, sigs []Signal, st *State, now time.Time) []Run {
	if st == nil {
		st = &State{}
	}
	var out []Run
	for _, pb := range pbs {
		run := Run{Playbook: pb.Name, ByStage: make([]int, len(pb.Stages))}
		switch pb.On.Per {
		case "provider":
			run.Incomplete = "the log keeps no provider for these signals, so this playbook cannot be tried against it"
		}
		if pb.On.Signal == "form-spam" || pb.On.Signal == "chatbot-injection" && pb.On.Per == "subject" {
			run.Incomplete = "the log does not say which form or chatbot these signals were about"
		}
		rs := DryRun(pb, sigs)
		run.Responses = len(rs)
		for _, r := range rs {
			if r.Stage >= 1 && r.Stage <= len(run.ByStage) {
				run.ByStage[r.Stage-1]++
			}
			if pb.On.Per == "source" && st.IsVouched([]string{r.Key}, now) {
				run.Collateral++
			}
			if len(run.Examples) < 5 {
				run.Examples = append(run.Examples, r.At.UTC().Format("2 Jan 15:04")+": "+strings.Join(r.Did, "; "))
			}
		}
		switch {
		case run.Incomplete != "":
			run.Summary = "not tried: " + run.Incomplete
		case run.Responses == 0:
			run.Summary = "would have done nothing"
		default:
			parts := []string{}
			for i, n := range run.ByStage {
				if n > 0 {
					parts = append(parts, fmt.Sprintf("stage %d ×%d", i+1, n))
				}
			}
			run.Summary = fmt.Sprintf("would have responded %s (%s)", countWord(run.Responses, "time", "times"), strings.Join(parts, ", "))
			if run.Collateral > 0 {
				run.Summary += fmt.Sprintf("; %s an administrator signed in from strongly", countWord(run.Collateral, "of them was a source", "of them were sources"))
			}
		}
		out = append(out, run)
	}
	return out
}

func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
