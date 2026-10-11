// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build !linux

package shell

import "io/fs"

func ident(fs.FileInfo) uint64 { return 0 }
