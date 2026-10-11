// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/cell"
)

// The cell command: what this machine has for desktop cells, and whether
// the warm snapshot a store would restore is where its setting says.
//
// A cell is a microVM an operator installs and warms; this program drives
// it, and says honestly when there is nothing to drive. It never offers a
// cell to an agent whose machine has not been set up for one: a capability
// that quietly degrades to nothing is a manifest that reads as wider than
// the machine it runs on.

func cmdCell(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return cellStatus(root)
	}
	return fmt.Errorf("unknown cell command %q; try status", args[0])
}

func cellStatus(root string) error {
	c, err := loadConfig(root)
	if err != nil {
		return err
	}
	backend := c.Raw("cell.backend")
	if backend == "" {
		fmt.Printf("  no cell backend configured (cell.backend). Desktop cells are off; an agent\\'s\n")
		fmt.Printf("  browser and workspace are all this store offers\n")
		return nil
	}
	b, err := cell.New(backend, c.Raw("cell.binary"))
	if err != nil {
		return err
	}
	a, _ := b.Check()
	if a.OK {
		fmt.Printf("  %s%s cells run on this machine%s\\n", green, b.Name(), reset)
	} else {
		fmt.Printf("  %sno %s cells on this machine: %s%s\\n", yellow, b.Name(), a.Why, reset)
	}
	snap, mem := c.Raw("cell.snapshot"), c.Raw("cell.memory")
	if snap != "" {
		m := cell.Machine{Snapshot: snap, Memory: mem}
		fmt.Printf("  warm snapshot %s", m.Snapshot)
		if m.Memory != "" {
			fmt.Printf(" (memory %s)", m.Memory)
		}
		fmt.Println()
	} else {
		fmt.Printf("  no warm snapshot named (cell.snapshot): a session has nothing to restore\\n")
	}
	caller := resolveCaller(root, "")
	record(root, caller.auditRecord("cell.status", "/", audit.Success,
		map[string]string{"backend": backend, "ok": fmt.Sprintf("%v", a.OK)}))
	return nil
}

// cellBackendFor is the backend a store's settings name, when one does and
// it checks out on this machine. Nil when no cell is configured — the
// caller refuses the capability, it does not fall back to anything.
func cellBackendFor(root string) (cell.Backend, cell.Machine, error) {
	c, err := loadConfig(root)
	if err != nil {
		return nil, cell.Machine{}, err
	}
	backend := c.Raw("cell.backend")
	if backend == "" {
		return nil, cell.Machine{}, fmt.Errorf("no cell backend is configured (cell.backend)")
	}
	b, err := cell.New(backend, c.Raw("cell.binary"))
	if err != nil {
		return nil, cell.Machine{}, err
	}
	a, _ := b.Check()
	if !a.OK {
		return nil, cell.Machine{}, fmt.Errorf("this machine cannot run a cell: %s", a.Why)
	}
	return b, cell.Machine{
		Snapshot: c.Raw("cell.snapshot"),
		Memory:   c.Raw("cell.memory"),
		CPUs:     c.Int("cell.cpus"),
		MemoryMB: c.Int("cell.memory_mb"),
	}, nil
}

// cellUp brings one cell up for a session and connects its helper: the
// whole of what a run that holds the desktop does to get one.
func cellUp(ctx context.Context, root, socket string) (cell.Backend, *cell.Helper, error) {
	b, m, err := cellBackendFor(root)
	if err != nil {
		return nil, nil, err
	}
	if err := b.Start(ctx, m, socket); err != nil {
		return nil, nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	h, err := cell.Connect(hctx, socket)
	if err != nil {
		_ = cell.Stop(context.Background(), socket)
		return nil, nil, err
	}
	return b, h, nil
}
