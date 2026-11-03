// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// The policy a server was started with follows the file, as its tokens do: a
// grant and a revocation made on the command line both apply at the next
// request, and a server that cannot read the file keeps what it knew.
//
// The content API in `quilzo serve` and `quilzo site --api` decided against
// the policy loaded at startup, so a reader granted while it ran was refused
// there and a revoked one kept reading pages there until a restart.
func TestThePolicyAServerHoldsFollowsTheFile(t *testing.T) {
	root := t.TempDir()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	reload := policyReloader(root, pol)
	reload()
	if pol.Evaluate("late", auth.ActView, "/").Allowed {
		t.Fatal("somebody granted nothing may read")
	}

	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "late", Role: auth.RoleReader, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	reload()
	if !pol.Evaluate("late", auth.ActView, "/").Allowed {
		t.Fatal("a reader granted while the server ran is not seen")
	}

	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("late", auth.RoleReader, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reload()
	if pol.Evaluate("late", auth.ActView, "/").Allowed {
		t.Fatal("a reader revoked while the server ran may still read")
	}
}
