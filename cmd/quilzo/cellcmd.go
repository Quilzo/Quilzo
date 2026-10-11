// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"

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
		fmt.Println("  no cell backend configured (cell.backend). Desktop cells are off;")
		fmt.Println("  an agent's browser and workspace are all this store offers")
		return nil
	}
	b, err := cell.New(backend, c.Raw("cell.binary"))
	if err != nil {
		return err
	}
	a, _ := b.Check()
	if a.OK {
		fmt.Printf("  %s%s cells run on this machine%s\n", green, b.Name(), reset)
	} else {
		fmt.Printf("  %sno %s cells on this machine: %s%s\n", yellow, b.Name(), a.Why, reset)
	}
	snap, mem := c.Raw("cell.snapshot"), c.Raw("cell.memory")
	if snap != "" {
		m := cell.Machine{Snapshot: snap, Memory: mem, CPUs: c.Int("cell.cpus"), MemoryMB: c.Int("cell.memory_mb")}
		fmt.Printf("  warm snapshot %s", m.Snapshot)
		if m.Memory != "" {
			fmt.Printf(" (memory %s)", m.Memory)
		}
		fmt.Printf(", taken at %d CPUs and %d MiB: a restore names the shape it was taken at\n", m.CPUs, m.MemoryMB)
	} else {
		fmt.Println("  no warm snapshot named (cell.snapshot): a session has nothing to restore")
	}
	caller := resolveCaller(root, "")
	record(root, caller.auditRecord("cell.status", "/", audit.Success,
		map[string]string{"backend": backend, "ok": fmt.Sprintf("%v", a.OK)}))
	return nil
}
