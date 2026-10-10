// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package browser is an agent's browser: Chromium inside the agent's box,
// driven from outside it, by Quilzo, over a pipe only Quilzo holds.
//
// The browser and the pages it renders are inside the box, so a page that
// breaks the renderer is in the box: its namespaces, Landlock, the system
// call filter, a network whose only way out is Quilzo's proxy. The driver is
// outside, in this process: an agent asks for one action at a time and never
// holds the DevTools connection, so a hijacked model has no way to send the
// browser a raw command, read its cookies or evaluate script in a page.
package browser

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/cdp"
	"github.com/quilzo/quilzo/internal/sandbox"
)

// Box is where a browser runs: an agent box, and the run it belongs to.
type Box struct {
	Backend agentbox.Backend
	Run     string
	Agent   string
	// Workdir is the box's own directory; the profile is made inside it.
	Workdir string
	// Services are handed into the box: the proxy, for one.
	Services []agentbox.Service
	// Wall is how long the browser may run.
	Wall time.Duration
	// MemoryMB bounds what it writes; 2048 when zero.
	MemoryMB int
}

// ErrNoBox is a browser asked for where no box can be made.
var ErrNoBox = errors.New("an agent's browser runs only in an agent box, and none is available here")

// Start is a cdp start function that runs the browser in the box.
func (bx Box) Start(stderr io.Writer) func(ctx context.Context, argv, env []string, in, out *os.File) (cdp.Process, error) {
	return func(ctx context.Context, argv, env []string, in, out *os.File) (cdp.Process, error) {
		if bx.Backend == nil {
			return nil, ErrNoBox
		}
		if a := bx.Backend.Check(); !a.OK {
			return nil, errors.New(ErrNoBox.Error() + ": " + a.Why)
		}
		mem := bx.MemoryMB
		if mem <= 0 {
			mem = 2048
		}
		rctx, cancel := context.WithCancel(context.Background())
		p := &boxed{cancel: cancel, done: make(chan struct{})}
		started := make(chan struct{})
		var once sync.Once
		go func() {
			defer close(p.done)
			_, p.err = bx.Backend.Run(rctx, agentbox.Spec{
				Run: bx.Run, Agent: bx.Agent, Program: argv[0], Args: argv[1:], Env: env,
				Workdir: bx.Workdir, Read: []string{filepath.Dir(argv[0])}, Services: bx.Services,
				Limits: sandbox.Limits{CPUSeconds: 3600, DataBytes: uint64(mem) << 20,
					FileBytes: 512 << 20, OpenFiles: 2048, Processes: 4096},
				Wall: bx.Wall, Stderr: stderr,
				Files:   []*os.File{in, out},
				Started: func() { once.Do(func() { close(started) }) },
			})
			once.Do(func() { close(started) })
		}()
		select {
		case <-started:
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
		select {
		case <-p.done:
			if p.err != nil {
				return nil, p.err
			}
			return nil, errors.New("the browser ended as it started")
		default:
		}
		return p, nil
	}
}

type boxed struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func (p *boxed) Wait() error { <-p.done; return p.err }
func (p *boxed) Kill() error { p.cancel(); return nil }
