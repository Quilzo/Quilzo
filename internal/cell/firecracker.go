// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cell

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Firecracker drives AWS's microVM: HTTP over the socket its process
// owns, a fixed set of PUTs before one InstanceStart, snapshots at
// PUT /snapshot/create and PUT /snapshot/load. Driven as the jailer's
// user or not at all: the binary the operator names is run once per cell
// with the socket beside it, and this program speaks only to the socket.
type Firecracker struct {
	Binary string
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
// into it, resumed. The conversation is the maker's own order, and the
// maker's own refusals: a snapshot whose shape or files disagree with
// what is named here is refused by Firecracker, not papered over here.
func (f *Firecracker) Start(ctx context.Context, m Machine, socket string) error {
	a, _ := f.Check()
	if err := a.ok(); err != nil {
		return err
	}
	dir := filepath.Dir(socket)
	// A context of the caller's choosing governs the maker's lifetime —
	// see the Cloud Hypervisor driver's note.
	cmd := exec.CommandContext(ctx, f.Binary,
		"--api-sock", socket,
		"--seccomp-level", "2",
	)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", f.Binary, err)
	}
	go func() { _ = cmd.Wait() }()
	// The socket appears when the process is ready to be spoken to; a
	// process that never makes one is dead, and its own exit says so.
	wait := time.NewTicker(50 * time.Millisecond)
	defer wait.Stop()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if i == 99 {
			_ = cmd.Process.Kill()
			return fmt.Errorf("%s made no socket to be driven through", f.Binary)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
		}
	}
	c := httpOverUnix(socket)
	if err := apiCall(ctx, c, "PUT", "/snapshot/load", map[string]any{
		"snapshot_path": m.Snapshot,
		"mem_backend":   map[string]any{"backend_type": "File", "backend_path": m.Memory},
		"resume_vm":     true,
	}); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("restoring the warm snapshot: %w", err)
	}
	// The vsock: bound by the load where the snapshot says, and this
	// program connects to the path named in the machine.
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

// Stop ends a cell: the maker's own shutdown signal, which the guest's
// init answers by ending, taking the process with it.
func Stop(ctx context.Context, socket string) error {
	return apiCall(ctx, httpOverUnix(socket), "PUT", "/actions", map[string]any{"action_type": "SendCtrlAltDel"})
}
