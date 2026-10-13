// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cell

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
)

// Firecracker drives AWS's microVM: HTTP over the socket its process
// owns, snapshots at PUT /snapshot/create and PUT /snapshot/load. The
// binary runs as this program's user with Firecracker's default seccomp
// filters, once per cell, with the socket beside it. It does not run
// under the jailer, which Firecracker's production guidance asks for.
type Firecracker struct {
	Binary string
	procs  vmms
}

func (f *Firecracker) Name() string { return "firecracker" }

func (f *Firecracker) Check() (Availability, error) {
	if err := findBinary(f.Binary); err != nil {
		return Availability{Why: err.Error()}, nil
	}
	if err := findKVM(); err != nil {
		return Availability{Why: err.Error()}, nil
	}
	if _, err := exec.LookPath(f.Binary); err != nil {
		return Availability{OK: true, Why: f.Binary + " is here but not on PATH; it is run by absolute path"}, nil
	}
	return Availability{OK: true}, nil
}

// Start runs one Firecracker on the socket and restores the warm snapshot
// into it, resumed. A snapshot whose files disagree with what is named
// here is refused by Firecracker, not papered over here.
func (f *Firecracker) Start(ctx context.Context, m Machine, socket string) error {
	a, _ := f.Check()
	if err := a.ok(); err != nil {
		return err
	}
	return f.start(ctx, m, socket)
}

func (f *Firecracker) start(ctx context.Context, m Machine, socket string) error {
	if m.Snapshot == "" || m.Memory == "" {
		return errors.New("firecracker restores a snapshot from two files: set cell.snapshot and cell.memory")
	}
	if _, err := f.procs.launch(ctx, f.Binary, []string{"--api-sock", socket}, socket); err != nil {
		return err
	}
	if err := apiCall(ctx, httpOverUnix(socket), "PUT", "/snapshot/load", map[string]any{
		"snapshot_path": m.Snapshot,
		"mem_backend":   map[string]any{"backend_type": "File", "backend_path": m.Memory},
		"resume_vm":     true,
	}); err != nil {
		f.procs.forget(socket)
		return fmt.Errorf("restoring the warm snapshot: %w", err)
	}
	return nil
}

func (a Availability) ok() error {
	if !a.OK {
		return fmt.Errorf("this machine cannot run a cell: %s", a.Why)
	}
	return nil
}

// Snapshot pauses a running cell and writes its warm snapshot, for the
// operator who is making one: the state to restore every session from.
func Snapshot(ctx context.Context, socket, snapshot, memory string) error {
	return snapshotVM(ctx, httpOverUnix(socket), snapshot, memory)
}

func snapshotVM(ctx context.Context, c *http.Client, snap, memory string) error {
	if err := apiCall(ctx, c, "PATCH", "/vm", map[string]any{"state": "Paused"}); err != nil {
		return fmt.Errorf("pausing to snapshot: %w", err)
	}
	if err := apiCall(ctx, c, "PUT", "/snapshot/create", map[string]any{
		"snapshot_type": "Full",
		"snapshot_path": snap,
		"mem_file_path": memory,
	}); err != nil {
		return fmt.Errorf("taking the snapshot: %w", err)
	}
	return apiCall(ctx, c, "PATCH", "/vm", map[string]any{"state": "Resumed"})
}

// Stop ends a cell: Ctrl+Alt+Del to the guest, whose init answers by
// ending, and the process killed when it has not.
func (f *Firecracker) Stop(ctx context.Context, socket string) error {
	return f.procs.stop(ctx, socket, func(ctx context.Context) error {
		return apiCall(ctx, httpOverUnix(socket), "PUT", "/actions", map[string]any{"action_type": "SendCtrlAltDel"})
	})
}
