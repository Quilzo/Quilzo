// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// A maker's process lives as long as the cell does, not as long as the
// call that started it: the context a Start is given bounds the start, and
// only Stop ends the process. Stop asks the maker to end the guest first
// and kills the process when it has not ended within the grace, because a
// guest that ignores its shutdown must not keep a virtual machine running.

// stopGrace is how long a maker is given to end once asked.
var stopGrace = 3 * time.Second

// vmm is one maker's process.
type vmm struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// vmms are the processes a backend started, by socket.
type vmms struct {
	mu sync.Mutex
	by map[string]*vmm
}

// launch runs the maker on a socket and waits for the socket to appear.
// A process that exits first, or a start whose context ends first, leaves
// nothing running.
func (p *vmms) launch(ctx context.Context, binary string, args []string, socket string) (*vmm, error) {
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("a socket from an earlier cell is in the way: %w", err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = filepath.Dir(socket)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", binary, err)
	}
	v := &vmm{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(v.done) }()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	limit := time.NewTimer(5 * time.Second)
	defer limit.Stop()
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case <-v.done:
			return nil, fmt.Errorf("%s ended before it made its socket: %v", binary, cmd.ProcessState)
		case <-ctx.Done():
			v.kill()
			return nil, ctx.Err()
		case <-limit.C:
			v.kill()
			return nil, fmt.Errorf("%s made no socket to be driven through", binary)
		case <-tick.C:
		}
	}
	p.mu.Lock()
	if p.by == nil {
		p.by = map[string]*vmm{}
	}
	p.by[socket] = v
	p.mu.Unlock()
	return v, nil
}

// kill ends the process and waits for it to be reaped.
func (v *vmm) kill() {
	_ = v.cmd.Process.Kill()
	<-v.done
}

// forget drops a process this backend no longer drives, killing it.
func (p *vmms) forget(socket string) {
	p.mu.Lock()
	v := p.by[socket]
	delete(p.by, socket)
	p.mu.Unlock()
	if v != nil {
		v.kill()
	}
	_ = os.Remove(socket)
}

// stop asks the maker to end, then makes sure it has. A socket this
// backend did not start is only asked.
func (p *vmms) stop(ctx context.Context, socket string, ask func(context.Context) error) error {
	p.mu.Lock()
	v := p.by[socket]
	delete(p.by, socket)
	p.mu.Unlock()
	actx, cancel := context.WithTimeout(ctx, stopGrace)
	asked := ask(actx)
	cancel()
	if v == nil {
		return asked
	}
	grace := time.NewTimer(stopGrace)
	defer grace.Stop()
	select {
	case <-v.done:
	case <-grace.C:
		v.kill()
	case <-ctx.Done():
		v.kill()
	}
	_ = os.Remove(socket)
	return nil
}
