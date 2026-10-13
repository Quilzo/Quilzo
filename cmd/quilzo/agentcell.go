// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/browser"
	"github.com/quilzo/quilzo/internal/cell"
)

// A run's desktop cell: brought up from the store's warm snapshot when
// the agent first touches the desktop, worked through the governed
// driver, its pictures kept with the run like the browser's are.
//
// Nothing here can bring a cell up on a machine that has not been set up
// for one: the backend and snapshot the settings name are checked before
// the first action, and a run that holds the desktop on such a machine is
// told so, in the first step, rather than at declaration — because a
// declaration is written once and machines differ.

func holdsCell(m agent.Manifest) bool {
	for _, c := range m.Capabilities {
		if agent.IsDesktop(c) {
			return true
		}
	}
	return false
}

// cellTestConnect, when set, is how a test brings a cell up: a fake
// conversation in place of a microVM.
var cellTestConnect func(ctx context.Context) (cell.Conn, error)

// runCell is a run's cell and what it keeps.
type runCell struct {
	driver *cell.Driver
	stops  []func()
}

func (rc *runCell) end() {
	for _, stop := range rc.stops {
		stop()
	}
}

// cellDir is where this machine's cells live: one socket per run.
func cellDir(root string) string { return filepath.Join(root, "cell") }

func newRunCell(root string, m agent.Manifest, sess *agent.Session, caller *Caller,
	actor assist.Model, runID string, chat bool) (*runCell, error) {
	rc := &runCell{}
	var frames *runFrames
	if runID != "" {
		kr, err := loadKeyring(root)
		if err != nil {
			return nil, err
		}
		kept, err := loadRunFrames(root, runID)
		if err != nil {
			return nil, err
		}
		frames = &runFrames{root: root, id: runID, kr: kr, index: kept}
	}
	d := &cell.Driver{Session: sess}
	if frames != nil {
		d.Frames = func(f cell.Frame) {
			// The same record the browser's pictures keep, so a run's page
			// shows both without knowing which kind of screen they came
			// from.
			frames.keep(browser.Frame{Op: f.Op, At: f.At, JPEG: f.JPEG, Asking: f.Asking})
		}
		if chat {
			if p, ok := actor.(interface{ TakesPictures() bool }); !ok || p.TakesPictures() {
				d.Picture = frames.now
			}
		}
	}
	d.Connect = func(ctx context.Context) (cell.Conn, error) {
		if cellTestConnect != nil {
			return cellTestConnect(ctx)
		}
		b, machine, err := cellBackendFor(root)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(cellDir(root), 0o700); err != nil {
			return nil, err
		}
		// One cell at a time: every restore of the snapshot binds the same
		// vsock path.
		release, err := holdCell(cellDir(root))
		if err != nil {
			return nil, err
		}
		socket := filepath.Join(cellDir(root), "vm-"+randomHex(8)+".sock")
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := b.Start(cctx, machine, socket); err != nil {
			release()
			return nil, err
		}
		rc.stops = append(rc.stops, func() {
			sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer scancel()
			_ = b.Stop(sctx, socket)
			release()
		})
		hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
		defer hcancel()
		return cell.Connect(hctx, machine.Vsock)
	}
	rc.driver = d
	return rc, nil
}

// cellBackendFor is the backend a store's settings name, when one does
// and it checks out on this machine. A machine that cannot run a cell
// says so here, once, with the reason.
func cellBackendFor(root string) (cell.Backend, cell.Machine, error) {
	c, err := loadConfig(root)
	if err != nil {
		return nil, cell.Machine{}, err
	}
	backend := c.Raw("cell.backend")
	if backend == "" {
		return nil, cell.Machine{}, errors.New("no cell backend is configured (cell.backend), so this machine runs no desktop cells")
	}
	b, err := cell.New(backend, c.Raw("cell.binary"))
	if err != nil {
		return nil, cell.Machine{}, err
	}
	m := cell.Machine{
		Snapshot: c.Raw("cell.snapshot"),
		Memory:   c.Raw("cell.memory"),
		Vsock:    c.Raw("cell.vsock"),
	}
	if !filepath.IsAbs(m.Vsock) {
		return nil, cell.Machine{}, errors.New("cell.vsock names no absolute path, so the helper in a restored cell cannot be reached")
	}
	a, _ := b.Check()
	if !a.OK {
		return nil, cell.Machine{}, fmt.Errorf("this machine cannot run a cell: %s", a.Why)
	}
	return b, m, nil
}
