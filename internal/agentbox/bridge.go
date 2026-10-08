// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/quilzo/quilzo/internal/agent"
)

// Bridge makes a program the run's decider.
//
// A model run asks the model what to do next; a program's run asks the
// program, by waiting for its next call. Each call the program makes is
// handed to the run as the next action and goes through everything a
// model's would: the manifest, the budget, asking a person first, the
// audit record, the receipt. The call returns when the step has, with what
// the step returned. So a program has no way of acting that a model run
// does not have, and nothing it does is recorded any differently.
type Bridge struct {
	calls   chan call
	done    chan struct{}
	stopped chan struct{}

	mu      sync.Mutex
	waiting *call
	said    string
	why     string
	once    sync.Once
	finish  sync.Once
}

type call struct {
	action agent.Action
	reply  chan Reply
}

// Reply is what a step returned to the program.
type Reply struct {
	Body    string
	Refused bool
	Failed  bool
}

// ErrRunEnded is a call made after its run stopped.
var ErrRunEnded = errors.New("the run has ended")

// NewBridge is a bridge with nothing asked yet.
func NewBridge() *Bridge {
	return &Bridge{calls: make(chan call), done: make(chan struct{}), stopped: make(chan struct{})}
}

// Decide is the runner's decider. It hands back the result of the action
// it last returned, then waits for the program's next call.
func (b *Bridge) Decide(ctx context.Context, _ string, seen []agent.Observation) (agent.Action, error) {
	b.mu.Lock()
	w := b.waiting
	b.waiting = nil
	b.mu.Unlock()
	if w != nil {
		w.reply <- replyOf(seen)
	}
	select {
	case c := <-b.calls:
		b.mu.Lock()
		b.waiting = &c
		b.mu.Unlock()
		return c.action, nil
	case <-b.done:
		b.mu.Lock()
		said := b.said
		b.mu.Unlock()
		if said == "" {
			said = "the program finished"
		}
		return agent.Action{Say: said}, nil
	case <-ctx.Done():
		return agent.Action{}, ctx.Err()
	}
}

func replyOf(seen []agent.Observation) Reply {
	if len(seen) == 0 {
		return Reply{Failed: true, Body: "the step returned nothing"}
	}
	o := seen[len(seen)-1]
	switch {
	case o.Err != nil:
		return Reply{Body: o.Body, Failed: true}
	case strings.HasPrefix(o.Body, "refused: ") && o.Trusted:
		return Reply{Body: o.Body, Refused: true}
	}
	return Reply{Body: o.Body}
}

// Call is one action the program asked for. It returns when the step has.
func (b *Bridge) Call(ctx context.Context, a agent.Action) (Reply, error) {
	c := call{action: a, reply: make(chan Reply, 1)}
	select {
	case b.calls <- c:
	case <-b.stopped:
		return Reply{}, b.ended()
	case <-b.done:
		return Reply{}, ErrRunEnded
	case <-ctx.Done():
		return Reply{}, ctx.Err()
	}
	select {
	case r := <-c.reply:
		return r, nil
	case <-b.stopped:
		// The run stopped on this very step: a budget spent, or a person's
		// approval needed and nobody to ask.
		return Reply{Refused: true, Body: "refused: " + b.why}, nil
	case <-ctx.Done():
		return Reply{}, ctx.Err()
	}
}

func (b *Bridge) ended() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.why == "" {
		return ErrRunEnded
	}
	return errors.New("the run has ended: " + b.why)
}

// Finish says the program has ended, with what it said last: the run's
// next decision is that it is done.
func (b *Bridge) Finish(said string) {
	b.finish.Do(func() {
		b.mu.Lock()
		b.said = said
		b.mu.Unlock()
		close(b.done)
	})
}

// Stop says the run has ended, and why; every call still waiting is told.
func (b *Bridge) Stop(why string) {
	b.once.Do(func() {
		b.mu.Lock()
		b.why = why
		b.mu.Unlock()
		close(b.stopped)
	})
}
