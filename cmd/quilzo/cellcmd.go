// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
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
	case "warm":
		return cellWarm(root, args[1:])
	}
	return fmt.Errorf("unknown cell command %q; try status or warm", args[0])
}

// cellWarm makes the warm snapshot every session's cell is restored from.
//
// The operator brings a cell up from the image with the microVM's own
// binary and an API socket, and sets its desktop up as a session should
// find it. This pauses it, writes its snapshot in the shape its maker
// restores, where cell.snapshot and cell.memory say (or --snapshot and
// --memory), and resumes it. The setting said the operator made the
// snapshot with the microVM's own tools, the code said this program did,
// and nothing did: cell.Snapshot and cell.SnapshotCH ran only in tests.
//
// An administrator's, as the settings that name the snapshot are: it is
// what every agent's desktop starts as, with whatever is signed in on it.
// Checked here rather than in the table, because a bare `quilzo cell` is
// status, a reader's, and a table row may only narrow its parent's.
func cellWarm(root string, args []string) error {
	fs := flag.NewFlagSet("cell warm", flag.ContinueOnError)
	socket := fs.String("socket", "", "the API socket of the running cell to warm")
	snapshot := fs.String("snapshot", "", "where the snapshot is written (default: cell.snapshot)")
	memory := fs.String("memory", "", "where Firecracker writes its memory file (default: cell.memory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*socket) == "" || fs.NArg() > 0 {
		return errors.New("usage: quilzo cell warm --socket API.SOCK [--snapshot PATH] [--memory PATH]")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	c, err := loadConfig(root)
	if err != nil {
		return err
	}
	backend := c.Raw("cell.backend")
	if backend == "" {
		return errors.New("no cell backend configured (cell.backend): a snapshot is made in the shape " +
			"its maker restores, so name the maker first")
	}
	// A path given here is the operator's, from where they stand; the
	// microVM reads it from wherever it runs, so it is made absolute.
	given := func(flagValue, setting string) (string, error) {
		if v := strings.TrimSpace(flagValue); v != "" {
			return filepath.Abs(v)
		}
		return c.Raw(setting), nil
	}
	snap, err := given(*snapshot, "cell.snapshot")
	if err != nil {
		return err
	}
	mem, err := given(*memory, "cell.memory")
	if err != nil {
		return err
	}
	if snap == "" {
		return errors.New("nowhere to write the snapshot: --snapshot PATH, or cell.snapshot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	switch backend {
	case "firecracker":
		if mem == "" {
			return errors.New("firecracker writes a snapshot as two files: name the memory file with " +
				"--memory PATH, or cell.memory")
		}
		err = cell.Snapshot(ctx, *socket, snap, mem)
	case "cloud-hypervisor":
		mem = ""
		err = cell.SnapshotCH(ctx, *socket, snap)
	default:
		// A maker this program cannot drive is refused in New's words; one
		// it can start and has no snapshot call for is refused here, rather
		// than reported as warmed when nothing was asked of it.
		if _, err := cell.New(backend, ""); err != nil {
			return err
		}
		return fmt.Errorf("this program cannot warm a %s cell", backend)
	}
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("cell.warm", "/", audit.Success, map[string]string{"backend": backend}))
	if w.JSON(map[string]string{"backend": backend, "snapshot": snap, "memory": mem}) {
		return nil
	}
	w.Human("  %swarmed: %s's snapshot is at %s", green, backend, snap)
	if mem != "" {
		w.Human(", memory at %s", mem)
	}
	w.Human("%s\n", reset)
	if snap != c.Raw("cell.snapshot") || (mem != "" && mem != c.Raw("cell.memory")) {
		w.Human("  %ssessions restore what the settings name: quilzo config set cell.snapshot %s", dim, snap)
		if mem != "" {
			w.Human(", and cell.memory %s", mem)
		}
		w.Human("%s\n", reset)
	}
	return nil
}

func cellStatus(root string) error {
	c, err := loadConfig(root)
	if err != nil {
		return err
	}
	backend := c.Raw("cell.backend")
	snap, mem, vsock := c.Raw("cell.snapshot"), c.Raw("cell.memory"), c.Raw("cell.vsock")
	// The same answer as one document under --json. This printed its prose
	// whatever was asked for, so a script asking whether this machine has
	// desktop cells was given sentences to parse.
	doc := map[string]any{"backend": backend, "available": false,
		"snapshot": snap, "memory": mem, "vsock": vsock}
	if backend == "" {
		doc["why"] = "no cell backend configured (cell.backend)"
		if w.JSON(doc) {
			return nil
		}
		fmt.Println("  no cell backend configured (cell.backend). Desktop cells are off;")
		fmt.Println("  an agent's browser and workspace are all this store offers")
		return nil
	}
	b, err := cell.New(backend, c.Raw("cell.binary"))
	if err != nil {
		return err
	}
	a, _ := b.Check()
	caller := resolveCaller(root, "")
	record(root, caller.auditRecord("cell.status", "/", audit.Success,
		map[string]string{"backend": backend, "ok": fmt.Sprintf("%v", a.OK)}))
	doc["available"] = a.OK
	if !a.OK {
		doc["why"] = a.Why
	}
	if w.JSON(doc) {
		return nil
	}
	if a.OK {
		fmt.Printf("  %s%s cells run on this machine%s\n", green, b.Name(), reset)
	} else {
		fmt.Printf("  %sno %s cells on this machine: %s%s\n", yellow, b.Name(), a.Why, reset)
	}
	if snap != "" {
		fmt.Printf("  warm snapshot %s", snap)
		if mem != "" {
			fmt.Printf(" (memory %s)", mem)
		}
		fmt.Println()
	} else {
		fmt.Println("  no warm snapshot named (cell.snapshot): a session has nothing to restore;")
		fmt.Println("  quilzo cell warm --socket API.SOCK makes one of a cell set up by hand")
	}
	if vsock != "" {
		fmt.Printf("  the helper is reached through %s, the vsock the snapshot binds\n", vsock)
	} else {
		fmt.Println("  no vsock named (cell.vsock): the helper in a restored cell cannot be reached")
	}
	fmt.Printf("  %sexperimental: the helper inside the image is the operator's to build, and the%s\n", dim, reset)
	fmt.Printf("  %smicroVM runs as this program's user, without Firecracker's jailer%s\n", dim, reset)
	return nil
}
