// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/shield"
)

// A tool a person approved and its server then redefined. The call is
// refused where it is made (internal/mcpclient); here it is remembered,
// told to the shield once for each new definition rather than on every
// refused call, and kept in the posture until somebody looks at what the
// tool now is and pins it again.

type toolChange struct {
	Pinned string    `json:"pinned"`
	Now    string    `json:"now"`
	At     time.Time `json:"at"`
}

var toolChangesMu sync.Mutex

func toolChangesPath(root string) string { return filepath.Join(root, "self", "tools-changed.json") }

// loadToolChanges is the redefinitions seen, by integration/tool.
func loadToolChanges(root string) map[string]toolChange {
	out := map[string]toolChange{}
	if b, err := os.ReadFile(toolChangesPath(root)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func saveToolChanges(root string, m map[string]toolChange) error {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(toolChangesPath(root)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(toolChangesPath(root), b, 0o600)
}

// noteToolChanged is the MCP client's hook for a pinned tool redefined.
func noteToolChanged(root string, in agent.Integration, tool, pinned, now string) {
	record(root, audit.Record{Action: "integration.tool-changed", Resource: "/integrations/" + in.Name,
		Outcome: audit.Denied, Principal: "quilzo", Kind: audit.KindService, Verified: true,
		Detail: map[string]string{"integration": in.Name, "tool": tool, "pinned": pinned, "now": now}})
	key := in.Name + "/" + tool
	toolChangesMu.Lock()
	changes := loadToolChanges(root)
	seen, ok := changes[key]
	if ok && seen.Pinned == pinned && seen.Now == now {
		toolChangesMu.Unlock()
		return
	}
	changes[key] = toolChange{Pinned: pinned, Now: now, At: time.Now().UTC()}
	// Not remembered is told again next time, which is the better way
	// round for a server that turned on its users.
	_ = saveToolChanges(root, changes)
	toolChangesMu.Unlock()
	newShieldHost(root).engine.Observe(shield.Signal{Name: "tool-changed", Subject: "integration:" + key})
}

// forgetToolChanges is a person having looked: the tools they pinned are
// no longer redefinitions nobody has seen.
func forgetToolChanges(root, integration string, tools []string) error {
	toolChangesMu.Lock()
	defer toolChangesMu.Unlock()
	changes := loadToolChanges(root)
	n := len(changes)
	for _, t := range tools {
		delete(changes, integration+"/"+t)
	}
	if len(changes) == n {
		return nil
	}
	return saveToolChanges(root, changes)
}
