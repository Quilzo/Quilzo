// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/store"
)

// Every operation this program registers declares a role that can be checked.
//
// The central gate refuses an operation with no role, so an ungated one fails
// closed at call time rather than leaking. This catches it in CI instead,
// which is the difference between a build somebody fixes and a refusal
// somebody debugs.
//
// It exists because the shape it guards against is what happened: NeedsRole
// was set on three of twenty-three operations and read in one place that only
// printed it, so twenty operations were reachable by anybody who could start
// the process — including the four that return the posture and inventory
// reports the admin restricts to an administrator.
func TestEveryMCPOperationDeclaresACheckableRole(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, &Caller{Name: "test"}, "templates")

	ops := srv.Operations()
	if len(ops) < 20 {
		t.Fatalf("only %d operations registered; this is checking the wrong "+
			"server", len(ops))
	}
	for _, op := range ops {
		action, err := actionForRole(op.NeedsRole)
		if err != nil {
			t.Errorf("%s declares role %q, which cannot be checked: %v — so "+
				"the operation is refused at call time and nobody finds out "+
				"until they try it", op.Name, op.NeedsRole, err)
			continue
		}
		// A write must not be gated as a read. The four-tool split already
		// refuses calling a write through quilzo_read, but that is a
		// labelling boundary; this is the privilege one.
		if op.Writes && action == auth.ActView {
			t.Errorf("%s changes content and is gated on %s", op.Name, action)
		}
		if !op.Writes && (action == auth.ActEditDraft || action == auth.ActPublish) {
			t.Errorf("%s reads and is gated on %s, which is stricter than it "+
				"needs and will refuse a reader the read", op.Name, action)
		}
	}
}

// The gate is wired, not merely available.
//
// buildMCP sets Authorise. A server built without it refuses everything,
// which is safe but would take the whole agent interface down — so the thing
// worth asserting is that the real constructor wires it.
func TestBuildMCPWiresTheGate(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if srv := buildMCP(root, s, &Caller{Name: "test"}, "templates"); srv.Authorise == nil {
		t.Fatal("buildMCP left Authorise nil, so every operation refuses")
	}
}
