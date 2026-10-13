// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package shell

import "io/fs"

func ident(fs.FileInfo) uint64 { return 0 }
