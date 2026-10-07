// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux && !amd64 && !arm64

package sandbox

import "errors"

// The system call filter's tables are written for amd64 and arm64. On any
// other architecture it is not applied, and a hardened sandbox says so.

func applySeccomp() error {
	return errors.New("this build has no system call filter for this architecture")
}

// SeccompSupported says this build can filter system calls here.
func SeccompSupported() bool { return false }
