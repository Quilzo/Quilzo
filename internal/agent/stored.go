// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/quilzo/quilzo/internal/plaintext"
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

	// State is "running" while a process is working on it, and empty once
	// that stretch has ended. Beat is when it was last written: a run that
	// says it is running and has not been written for longer than its
	// budget was interrupted.
	State string    `json:"state,omitempty"`
	Beat  time.Time `json:"beat,omitzero"`
	// Held says the process working on the run holds a lock on it that the
	// kernel lets go of when that process ends, however it ends, and Gone is
	// set by whoever read the record and found it let go of. A run killed
	// half way through said it was running until StaleAfter had passed, so
	// for five minutes it was listed as running and could not be resumed.
	Held bool `json:"held,omitempty"`
	Gone bool `json:"-"`
	// From is the run and step this one was run again from.
	From string `json:"from,omitempty"`
	// Trigger is what started it when no person did: a schedule, or an
	// event and what it was about.
	Trigger string `json:"trigger,omitempty"`
	// Answers are what people decided about the actions it stopped at.
	Answers []Answer `json:"answers,omitempty"`
	// Eval names the evaluation this run was made for, and Plant the
	// instruction planted in what it read. An evaluation's runs write
	// nothing, call no tool and start no other agent; see internal/evals.
	Eval  string `json:"eval,omitempty"`
	Plant string `json:"plant,omitempty"`
}

// Answer is one person's decision on one pending action, kept.
type Answer struct {
	N       int       `json:"n"`
	Approve bool      `json:"approve"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	// Answers are what a person answered a decider's question with.
	Answers map[string]string `json:"answers,omitempty"`
}

// Running is the state of a run a process is working on.
const Running = "running"

// StaleAfter is how long past its last write a running run is taken to
// have been interrupted.
const StaleAfter = 5 * time.Minute

var recordID = regexp.MustCompile(`^run-[0-9]{8}-[0-9a-f]{8}$`)

// ValidRecordID reports whether s can name a kept run. It becomes a file
// name, so it is checked wherever one arrives from outside.
func ValidRecordID(s string) bool { return recordID.MatchString(s) }

// Keep makes the record of a run, with each step's result bounded.
func Keep(id, by, model string, started time.Time, t Trace, r Receipt) Record {
	kept := t
	kept.Steps = append([]Step(nil), t.Steps...)
	for i := range kept.Steps {
		kept.Steps[i].Result = plaintext.Clip(kept.Steps[i].Result, MaxStored, "…")
		kept.Steps[i].Action = keptAction(kept.Steps[i].Action)
	}
	if kept.Waiting != nil {
		w := *kept.Waiting
		w.Action = keptAction(w.Action)
		kept.Waiting = &w
	}
	kept.Answer = plaintext.Clip(kept.Answer, MaxStored, "…")
	return Record{ID: id, Agent: t.Agent, Kind: r.Kind, Goal: t.Goal, By: by,
		Model: model, Started: started.UTC(), Trace: kept, Receipt: r}
}

// keptAction is an action as a run's record keeps it: a file's whole text
// (up to a megabyte, which a few writes would make a record too large to
// read back) kept as its size and digest. A question about a write is
// always answered live, in the process holding the whole action.
func keptAction(a Action) Action {
	text, ok := a.Input["text"].(string)
	if a.Op != "file_write" || !ok || len(text) <= MaxStored {
		return a
	}
	in := make(map[string]any, len(a.Input))
	for k, v := range a.Input {
		in[k] = v
	}
	sum := sha256.Sum256([]byte(text))
	in["text"] = fmt.Sprintf("[%d bytes, sha256:%s]", len(text), hex.EncodeToString(sum[:]))
	a.Input = in
	return a
}

// Ended reports whether the process a run was in has gone: it finished
// the stretch, its lock was let go of, or it has not written the run for
// StaleAfter. What is left for a process that has ended is never read.
func (r Record) Ended(now time.Time) bool {
	return r.State != Running || r.Gone || now.Sub(r.Beat) > StaleAfter
}

// Outcome is a run in a word, for a list.
func (r Record) Outcome() string {
	return r.OutcomeAt(time.Time{})
}

// OutcomeAt is Outcome for a list that can also say a run is still going
// or was cut off, which depends on when it is asked.
func (r Record) OutcomeAt(now time.Time) string {
	switch {
	case r.Trace.Waiting != nil:
		return "waiting"
	case r.State == Running && (r.Gone || !now.IsZero() && now.Sub(r.Beat) > StaleAfter):
		return "interrupted"
	case r.State == Running:
		return "running"
	case r.Receipt.Refused > 0 && r.Receipt.Did == 0:
		return "refused"
	case r.Receipt.Failed > 0:
		return "failed"
	case !r.Trace.Complete:
		return "stopped"
	}
	return "complete"
}
