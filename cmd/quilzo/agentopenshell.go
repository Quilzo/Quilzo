// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/agentbox"
)

// openShellBackend is NVIDIA OpenShell as a program's box, reaching this
// machine where the settings say. See internal/agentbox/openshell.go.
func openShellBackend(root, image string) (agentbox.Backend, error) {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, err
	}
	return agentbox.OpenShell{Listen: cfg.Raw("agents.openshell_listen"),
		Reach: cfg.Raw("agents.openshell_reach"), Image: image}, nil
}
