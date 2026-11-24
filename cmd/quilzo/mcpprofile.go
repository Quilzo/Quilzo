// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
)

// The security profile, for an agent: read-only. Which features run is a
// person's decision, made with a reason on the Security profile screen or
// the command line; an agent may read what was decided and the manifest
// that records it, and switches nothing.

func registerProfileOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "profile_status", NeedsRole: "reader", Area: auth.AreaSecurity,
		Summary: "which features this installation runs: the profile in force, each feature it " +
			"switches off, and the signed feature manifest that records it",
		Detail: "The profile (security or standard), each feature it can switch with whether it is on, " +
			"why it is off, and the recorded change that set it when one did (who, when and why), and " +
			"the digest and key of the signed feature manifest, which is CM-7 evidence in Quilzo's " +
			"OSCAL component. Read-only: switching a feature is a person's, with a reason.",
		Keywords: []string{"profile", "feature", "least functionality", "cm-7", "switched off",
			"manifest", "security profile"},
	}, func(map[string]any) (any, error) {
		v, err := viewProfile(root)
		if err != nil {
			return nil, err
		}
		return v, nil
	})
}
