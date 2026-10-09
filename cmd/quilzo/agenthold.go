// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
)

// A program's run waiting for a person.
//
// A run decided by a model stops at an action that asks first and is
// continued later from its record. A program's cannot be: its program is
// blocked on that very call and will have ended by the time anybody
// continues anything. So it waits where it is. Its record carries the
// question, marked live, and the person answers it the usual way, on the
// run's page or with `quilzo agent approve`. The answer is left beside the
// record for the waiting process, which picks it up, and nothing else
// continues the run.
//
// It waits as long as the run may last and no longer: a program's run has
// a wall clock, and a question nobody answered in time is refused, with
// that reason, to the program.

// heldAnswer is a person's answer to a live question, left for the process
// that asked it.
type heldAnswer struct {
	N       int       `json:"n"`
	Approve bool      `json:"approve"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

func heldAnswerPath(root, id string) string {
	return filepath.Join(agentRunsDir(root), id+".answer")
}

// holdPoll is how often a waiting run looks for its answer, and holdBeat
// how often it says it is still alive. The beat is well inside StaleAfter,
// so a run waiting for a person never reads as interrupted.
const (
	holdPoll = 300 * time.Millisecond
	holdBeat = 30 * time.Second
)

// programHold is the Hold of a program's run kept as id. said is told when
// it starts waiting, so somebody running it from a terminal knows how to
// answer; answered records the answer on the run; gone closes when the
// program has ended, after which nothing is waiting for the answer.
func programHold(root, id string, gone <-chan struct{}, said func(string), answered func(agent.Answer)) func(context.Context, agent.Pending, func()) (agent.Verdict, error) {
	return func(ctx context.Context, w agent.Pending, beat func()) (agent.Verdict, error) {
		if !agent.ValidRecordID(id) {
			return agent.Verdict{}, fmt.Errorf("%q is not a run", id)
		}
		path := heldAnswerPath(root, id)
		// An answer left from an earlier question is not this one's.
		_ = os.Remove(path)
		if said != nil {
			what := w.Action.Op
			if w.Action.Tool != "" {
				what = w.Action.Tool
			}
			said(fmt.Sprintf("waiting for a person to decide on %s: the run's page, or "+
				"quilzo agent approve %s %d (decline the same way)", what, id, w.N))
		}
		poll := time.NewTicker(holdPoll)
		defer poll.Stop()
		lastBeat := time.Now()
		for {
			select {
			case <-ctx.Done():
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return agent.Verdict{}, errors.New("nobody decided before the run's time ran out")
				}
				return agent.Verdict{}, ctx.Err()
			case <-gone:
				return agent.Verdict{}, errors.New("the program ended while it waited")
			case <-poll.C:
			}
			if time.Since(lastBeat) >= holdBeat {
				beat()
				lastBeat = time.Now()
			}
			b, err := readBounded(path, 4<<10)
			if os.IsNotExist(err) {
				continue
			}
			_ = os.Remove(path)
			var a heldAnswer
			if err != nil || json.Unmarshal(b, &a) != nil {
				continue
			}
			if a.N != w.N {
				continue
			}
			if answered != nil {
				answered(agent.Answer{N: a.N, Approve: a.Approve, By: a.By, At: a.At})
			}
			return agent.Verdict{N: a.N, Approve: a.Approve, By: a.By}, nil
		}
	}
}

// answerLive leaves a person's answer for the process a live question is
// waiting in. Refused when that process has gone: the run's record stops
// being written when it does, and an answer nobody will read is not one.
func answerLive(root string, rec agent.Record, v agent.Verdict, by string, now time.Time) error {
	w := rec.Trace.Waiting
	switch {
	case w == nil || !w.Live:
		return agent.ErrNotWaiting
	case v.N != w.N:
		return fmt.Errorf("the run is waiting at step %d and this answers step %d", w.N, v.N)
	case rec.State != agent.Running || now.Sub(rec.Beat) > agent.StaleAfter:
		return fmt.Errorf("%s was waiting in a process that has ended, so nothing would act on "+
			"this answer; run it again", rec.ID)
	}
	b, err := json.Marshal(heldAnswer{N: v.N, Approve: v.Approve, By: by, At: now})
	if err != nil {
		return err
	}
	return atomicfile.Write(heldAnswerPath(root, rec.ID), b, 0o600)
}
