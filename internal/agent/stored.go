// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"regexp"
	"time"
)

// A run, kept.
//
// A Trace existed for as long as the command that produced it. The receipt
// went into the audit log and the spans to a collector if there was one,
// and what the agent actually did — each action, whether it was allowed,
// what came back — was printed and gone. Nothing could be compared with
// the run before, and "why did it do that" had no answer a day later.
//
// A Record is the trace with who asked and what decided, in a shape that
// can be stored and read back. What a step returned is bounded: a record is
// for seeing what happened, and is not a second copy of the content.

// MaxStored is how much of one step's result is kept.
const MaxStored = 4000

// Record is one run as it is kept.
type Record struct {
	ID    string `json:"id"`
	Agent string `json:"agent"`
	Kind  Kind   `json:"kind"`
	Goal  string `json:"goal"`
	// By is who started it, and Model what chose the actions. An empty
	// model means the manifest was walked and nothing chose.
	By      string    `json:"by"`
	Model   string    `json:"model,omitempty"`
	Started time.Time `json:"started"`
	Trace   Trace     `json:"trace"`
	Receipt Receipt   `json:"receipt"`
}

var recordID = regexp.MustCompile(`^run-[0-9]{8}-[0-9a-f]{8}$`)

// ValidRecordID reports whether s can name a kept run. It becomes a file
// name, so it is checked wherever one arrives from outside.
func ValidRecordID(s string) bool { return recordID.MatchString(s) }

// Keep makes the record of a run, with each step's result bounded.
func Keep(id, by, model string, started time.Time, t Trace, r Receipt) Record {
	kept := t
	kept.Steps = append([]Step(nil), t.Steps...)
	for i := range kept.Steps {
		if len(kept.Steps[i].Result) > MaxStored {
			kept.Steps[i].Result = kept.Steps[i].Result[:MaxStored] + "…"
		}
	}
	if len(kept.Answer) > MaxStored {
		kept.Answer = kept.Answer[:MaxStored] + "…"
	}
	return Record{ID: id, Agent: t.Agent, Kind: r.Kind, Goal: t.Goal, By: by,
		Model: model, Started: started.UTC(), Trace: kept, Receipt: r}
}

// Outcome is a run in a word, for a list.
func (r Record) Outcome() string {
	switch {
	case r.Receipt.Refused > 0 && r.Receipt.Did == 0:
		return "refused"
	case r.Receipt.Failed > 0:
		return "failed"
	case !r.Trace.Complete:
		return "stopped"
	}
	return "complete"
}
