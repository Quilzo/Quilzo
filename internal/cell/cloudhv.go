// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// CloudHypervisor drives the other maker's microVM: also HTTP over a Unix
// socket, snapshots at PUT /vm.snapshot and PUT /vm.restore.
type CloudHypervisor struct {
	Binary string
	procs  vmms
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
	return c.start(ctx, m, socket)
}

func (c *CloudHypervisor) start(ctx context.Context, m Machine, socket string) error {
	if m.Snapshot == "" {
		return errors.New("no warm snapshot is named (cell.snapshot)")
	}
	if _, err := c.procs.launch(ctx, c.Binary, []string{"--api-socket", "path=" + socket, "--seccomp", "true"}, socket); err != nil {
		return err
	}
	hc := httpOverUnix(socket)
	// The restore takes the snapshot and nothing of the shape: the shape is
	// the snapshot's. It leaves the VM paused until the resume.
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.restore", map[string]any{
		"source_url": fileURL(m.Snapshot),
	}); err != nil {
		c.procs.forget(socket)
		return fmt.Errorf("restoring the warm snapshot: %w", err)
	}
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.resume", nil); err != nil {
		c.procs.forget(socket)
		return fmt.Errorf("resuming the restored cell: %w", err)
	}
	return nil
}

// fileURL is a snapshot path as the URL this maker reads it from.
func fileURL(path string) string {
	if strings.HasPrefix(path, "file://") {
		return path
	}
	return "file://" + path
}

// SnapshotCH pauses and writes the warm snapshot, Cloud Hypervisor's
// shape: one directory, at a URL this maker wants as a file:// path.
func SnapshotCH(ctx context.Context, socket, snapshot string) error {
	hc := httpOverUnix(socket)
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.pause", nil); err != nil {
		return fmt.Errorf("pausing to snapshot: %w", err)
	}
	if err := apiCall(ctx, hc, "PUT", "/api/v1/vm.snapshot", map[string]any{
		"destination_url": fileURL(snapshot),
	}); err != nil {
		return fmt.Errorf("taking the snapshot: %w", err)
	}
	return apiCall(ctx, hc, "PUT", "/api/v1/vm.resume", nil)
}

// Stop ends the cell: the maker's own shutdown of itself, which ends the
// VM with it, and the process killed when it has not.
func (c *CloudHypervisor) Stop(ctx context.Context, socket string) error {
	return c.procs.stop(ctx, socket, func(ctx context.Context) error {
		return apiCall(ctx, httpOverUnix(socket), "PUT", "/api/v1/vmm.shutdown", nil)
	})
}
