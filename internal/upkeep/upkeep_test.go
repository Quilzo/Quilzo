// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package upkeep

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Work happens at the start, not only on the first tick.
//
// This is the property the whole thing turns on. A ticker-only loop works on
// the machine that stays up and never runs at all on the deployment that
// restarts more often than the interval — and a quarter of an hour is shorter
// than plenty of release cycles. The bug it would reintroduce is the one this
// package exists for: a retention period nothing enforces.
func TestTheFirstSweepDoesNotWaitForTheFirstTick(t *testing.T) {
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Run(ctx, time.Hour, nil, Job{
		Name: "sweep",
		Do: func(time.Time) (int, error) {
			close(done)
			return 0, nil
		},
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nothing ran within two seconds, so the first sweep is " +
			"waiting for a tick an hour away; a process that restarts more " +
			"often than the interval would never sweep at all")
	}
}

// A failing job does not end the loop.
//
// These sweep a directory other processes write to, so a failure is usually a
// file that moved underneath. A loop that exits on the first one stops doing
// the job it exists for, and stops silently.
func TestAFailingJobDoesNotStopTheLoop(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Run(ctx, 10*time.Millisecond, nil, Job{
		Name: "sweep",
		Do: func(time.Time) (int, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return 0, errors.New("a file moved")
		},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("ran %d times; an error ended the loop, so one moved file stops "+
		"retention for the life of the process", calls)
}

// Cancelling stops it.
func TestCancellingTheContextStopsTheLoop(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())

	go Run(ctx, 5*time.Millisecond, nil, Job{
		Name: "sweep",
		Do: func(time.Time) (int, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return 0, nil
		},
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	atStop := calls
	mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != atStop {
		t.Errorf("ran %d more times after the context was cancelled; a server "+
			"shutting down leaves a goroutine writing to its store",
			calls-atStop)
	}
}

// Nothing to report is nothing printed.
//
// A line every quarter of an hour saying that nothing happened is a log nobody
// reads, and this has to be legible on the day it says something.
func TestASweepWithNothingToDoIsSilent(t *testing.T) {
	reported := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan struct{})
	go Run(ctx, time.Hour, func(Job, int, error) { reported++ }, Job{
		Name: "sweep",
		Do: func(time.Time) (int, error) {
			defer close(stop)
			return 0, nil
		},
	})
	<-stop
	time.Sleep(20 * time.Millisecond)

	if reported != 0 {
		t.Errorf("a sweep that did nothing reported %d times", reported)
	}
}
