// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"fmt"
	"slices"

	"github.com/quilzo/quilzo/internal/register"
)

// Replay: a run, done again.
//
// A run names the register commit it read. The store keeps every commit,
// so the facts the run read, its test and its population can be read again
// exactly as they were, and evaluated by the same code (Evaluate). A replay
// says whether that gives the run that was recorded: the same members, the
// same failures, the same digest of what was read. What the facts were read
// from, the sealed raw files, is named by each fact's own digest among what
// is read, so a fact changed since is a different snapshot.

// Replayed is a recorded run and the same run done again.
type Replayed struct {
	RunID    register.ID      `json:"run_id"`
	Recorded register.TestRun `json:"recorded"`
	Again    register.TestRun `json:"again"`
	// Same says the replay gave the recorded run; Differences says, in
	// lines code writes, where it did not.
	Same        bool     `json:"same"`
	Differences []string `json:"differences,omitempty"`
}

// Replay does a recorded run again, from the commit it read.
func (p *Programme) Replay(runID register.ID) (Replayed, error) {
	e, err := p.Reg.Get(runID)
	if err != nil {
		return Replayed{}, err
	}
	rec, ok := e.Record.(register.TestRun)
	if !ok {
		return Replayed{}, fmt.Errorf("%w: %s is not a run of a control test", register.ErrNotFound, runID)
	}
	if rec.Commit == "" {
		return Replayed{}, fmt.Errorf("%w: the run does not name the commit it read, so there is nothing to read again",
			register.ErrNotFound)
	}
	v, err := p.Reg.At(rec.Commit)
	if err != nil {
		return Replayed{}, err
	}
	run, err := Evaluate(v, rec.Test, rec.Ran.At())
	if err != nil {
		return Replayed{}, err
	}
	out := Replayed{RunID: runID, Recorded: rec, Again: run.Record}
	again := run.Record
	if again.Outcome != rec.Outcome {
		out.Differences = append(out.Differences, fmt.Sprintf("it came out %s, and was recorded as %s", again.Outcome, rec.Outcome))
	}
	if again.Size != rec.Size || again.Population != rec.Population {
		out.Differences = append(out.Differences, fmt.Sprintf("it ran over %d members, and was recorded over %d", again.Size, rec.Size))
	}
	if !slices.Equal(again.Failing, rec.Failing) {
		out.Differences = append(out.Differences, fmt.Sprintf("%d members failed, and %d were recorded as failing",
			len(again.Failing), len(rec.Failing)))
	}
	if again.Snapshot != rec.Snapshot {
		out.Differences = append(out.Differences, "what it read is not what the run recorded reading")
	}
	out.Same = len(out.Differences) == 0
	return out, nil
}
