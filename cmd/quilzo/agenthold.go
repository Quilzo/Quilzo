// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/browser"
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
	N       int               `json:"n"`
	Approve bool              `json:"approve"`
	By      string            `json:"by"`
	At      time.Time         `json:"at"`
	Answers map[string]string `json:"answers,omitempty"`
	// Asked is the question's, as the record offered it (Pending.Asked).
	Asked time.Time `json:"asked,omitzero"`
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

// personNote is one thing a person did to a run's browser while taking it
// over, left for the process that holds the page. A line each, appended:
// a person works faster than a file is replaced, and inputs lost between
// a read and a removal would be hands that did nothing.
type personNote struct {
	browser.PersonInput
	By string    `json:"by"`
	At time.Time `json:"at"`
}

func personPath(root, id string) string {
	return filepath.Join(agentRunsDir(root), id+".person")
}

// appendPersonNote leaves one input for the process a live question is
// waiting in. Like an answer, refused when that process has gone: hands
// on a page nobody is holding touch nothing.
func appendPersonNote(root string, rec agent.Record, n personNote, now time.Time) error {
	w := rec.Trace.Waiting
	switch {
	case w == nil || !w.Live:
		return agent.ErrNotWaiting
	case rec.State != agent.Running || now.Sub(rec.Beat) > agent.StaleAfter:
		return fmt.Errorf("%s was waiting in a process that has ended, so nothing would act on "+
			"what you did; run it again", rec.ID)
	}
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	path := personPath(root, rec.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// watchPerson reads what a person has done to the page since the last
// look, and hands each thing to act. Offset is where the last look ended.
// Nothing a person did is a reason to end the wait: their hands are on the
// page, and the question still wants its answer.
func watchPerson(root, id string, offset int64, act func(browser.PersonInput, string)) int64 {
	f, err := os.Open(personPath(root, id))
	if err != nil {
		return offset
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() < offset {
		// Replaced, or smaller than where the last look ended: start over
		// rather than read from a place that no longer means anything.
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var n personNote
		if json.Unmarshal(line, &n) != nil {
			continue
		}
		if act != nil {
			act(n.PersonInput, n.By)
		}
	}
	// Only whole lines count: a half-written one is read again whole next
	// time, never acted on as it lies.
	return offset + int64(len(b)-len(lastPartial(b)))
}

func lastPartial(b []byte) []byte {
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}

// programHold is the Hold of a program's run kept as id. said is told when
// it starts waiting, so somebody running it from a terminal knows how to
// answer; answered records the answer on the run; gone closes when the
// program has ended, after which nothing is waiting for the answer.
// person, for a run whose browser is open while it waits, is handed each
// thing a person does to the page while taking it over.
func programHold(root, id string, gone <-chan struct{}, said func(string), answered func(agent.Answer),
	person func(browser.PersonInput, string)) func(context.Context, agent.Pending, func()) (agent.Verdict, error) {
	// Where the last look at the person's hands ended, kept across the
	// run's questions: a second question must not replay the first one's
	// hands from the top of the file.
	var read int64
	return func(ctx context.Context, w agent.Pending, beat func()) (agent.Verdict, error) {
		if !agent.ValidRecordID(id) {
			return agent.Verdict{}, fmt.Errorf("%q is not a run", id)
		}
		path := heldAnswerPath(root, id)
		// An answer left from an earlier question is not this one's, and
		// is told apart by what it answers, below, not removed here: the
		// record has already offered this question when this is called, so
		// a quick answer may be in the file already, and removing it left
		// the run waiting for one that had been given until its time ran
		// out.
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
			if person != nil {
				read = watchPerson(root, id, read, person)
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
			if a.N != w.N || !a.Asked.Equal(w.Asked) {
				continue
			}
			if answered != nil {
				answered(agent.Answer{N: a.N, Approve: a.Approve, By: a.By, At: a.At, Answers: a.Answers})
			}
			return agent.Verdict{N: a.N, Approve: a.Approve, By: a.By, Answers: a.Answers}, nil
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
	if err := checkAnswers(w, v); err != nil {
		return err
	}
	b, err := json.Marshal(heldAnswer{N: v.N, Asked: w.Asked, Approve: v.Approve, By: by, At: now, Answers: v.Answers})
	if err != nil {
		return err
	}
	return atomicfile.Write(heldAnswerPath(root, rec.ID), b, 0o600)
}
