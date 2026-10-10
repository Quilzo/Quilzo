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
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
)

// Stopping a run that is going on: from its page, or quilzo agent stop.
//
// The run is in whatever process started it (the server, for a run started
// on the screen; a terminal, for one started there), so it is asked to stop
// the way a question it is waiting on is answered: with a note beside its
// record, which that process looks for twice a second. The run's context is
// cancelled: an action in progress is cut off where it is, a question it is
// waiting on is withdrawn, its browser is closed, and its record says who
// stopped it.

// stopNote is who asked a run to stop, and when.
type stopNote struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

func stopPath(root, id string) string { return filepath.Join(agentRunsDir(root), id+".stop") }

// stopRun asks a run that is going on to stop.
func stopRun(root, id string, caller *Caller, now time.Time) error {
	if caller.Kind == audit.KindAI {
		return errors.New("a person stops a run; a model that could would be choosing which work happens")
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		return err
	}
	switch o := rec.OutcomeAt(now); {
	case o == "waiting" && (rec.Trace.Waiting == nil || !rec.Trace.Waiting.Live):
		return fmt.Errorf("%s is not going on: it stopped to ask a person, and declining that is how it ends", id)
	case o != "running" && o != "waiting":
		return fmt.Errorf("%s is not going on; it is %s", id, o)
	}
	b, err := json.Marshal(stopNote{By: caller.Name, At: now.UTC()})
	if err != nil {
		return err
	}
	if err := atomicfile.Write(stopPath(root, id), b, 0o600); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("agent.stop", "/", audit.Success,
		map[string]string{"agent": rec.Agent, "run": id}))
}

// watchStop is ctx, cancelled when a person asks the run to stop, and what
// says who did once the run is over.
func watchStop(ctx context.Context, root, id string) (context.Context, func() string) {
	ctx, cancel := context.WithCancel(ctx)
	path := stopPath(root, id)
	// A note left from before this stretch of the run is not about it.
	_ = os.Remove(path)
	done := make(chan struct{})
	var by string
	go func() {
		defer close(done)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				b, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				var n stopNote
				if json.Unmarshal(b, &n) != nil || n.By == "" {
					n.By = "somebody"
				}
				by = n.By
				cancel()
				return
			}
		}
	}()
	var once sync.Once
	return ctx, func() string {
		once.Do(func() {
			cancel()
			<-done
			_ = os.Remove(path)
		})
		return by
	}
}

// agentStop is quilzo agent stop RUN.
func agentStop(root string, args []string) error {
	if len(args) != 1 || !agent.ValidRecordID(args[0]) {
		return errors.New("usage: quilzo agent stop RUN")
	}
	if err := stopRun(root, args[0], resolveCaller(root, ""), time.Now()); err != nil {
		return err
	}
	fmt.Printf("%sasked %s to stop%s; it stops within a second, wherever it is\n", green, args[0], reset)
	return nil
}
