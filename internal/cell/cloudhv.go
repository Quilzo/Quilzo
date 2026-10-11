// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cell

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// CloudHypervisor drives the other maker's microVM: also HTTP over a Unix
// socket, one PUT /vm.create with the whole shape and PUT /vm.boot, and
// snapshots at PUT /vm.snapshot and PUT /vm.restore.
type CloudHypervisor struct {
	Binary string
}

func (c *CloudHypervisor) Name() string { return "cloud-hypervisor" }

func (c *CloudHypervisor) Check() (Availability, error) {
	if err := findBinary(c.Binary); err != nil {
		return Availability{Why: err.Error()}, nil
	}
	if err := findKVM(); err != nil {
		return Availability{Why: err.Error()}, nil
	}
	return Availability{OK: true}, nil
}

func (c *CloudHypervisor) Start(ctx context.Context, m Machine, socket string) error {
	a, _ := c.Check()
	if err := a.ok(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, c.Binary,
		"--api-socket", "path="+socket,
		"--seccomp", "true",
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", c.Binary, err)
	}
	wait := time.NewTicker(50 * time.Millisecond)
	defer wait.Stop()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if i == 99 {
			_ = cmd.Process.Kill()
			return fmt.Errorf("%s made no socket to be driven through", c.Binary)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
		}
	}
	hc := httpOverUnix(socket)
	// The restore is one call carrying the whole shape, as this maker
	// wants it, and boots it in the same breath.
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.restore", map[string]any{
		"source_url": m.Snapshot,
		"cpus":       map[string]any{"boot_vcpus": m.CPUs, "max_vcpus": m.CPUs},
		"memory":     map[string]any{"size": m.MemoryMB, "shared": false},
	}); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("restoring the warm snapshot: %w", err)
	}
	return apiCall(ctx, hc, "PUT", "/api/v1/vm.resume", nil)
}

// SnapshotCH pauses and writes the warm snapshot, Cloud Hypervisor's
// shape: one file, at a URL this maker wants as a file:// path.
func SnapshotCH(ctx context.Context, socket, snapshot string) error {
	hc := httpOverUnix(socket)
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.pause", nil); err != nil {
		return fmt.Errorf("pausing to snapshot: %w", err)
	}
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.snapshot", map[string]any{
		"destination_url": "file://" + snapshot,
	}); err != nil {
		return fmt.Errorf("taking the snapshot: %w", err)
	}
	return apiCall(ctx, hc, "PUT", "/api/v1/vm.resume", nil)
}

// StopCH ends the cell: the maker's shutdown, which ends its process.
func StopCH(ctx context.Context, socket string) error {
	return apiCall(ctx, httpOverUnix(socket), "PUT", "/api/v1/vm.shutdown", nil)
}
