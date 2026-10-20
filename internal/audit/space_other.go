// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package audit

// FreeBytes cannot tell on this system; a full disk is then found by the
// write that fails, which the caller remembers.
func FreeBytes(string) (uint64, bool) { return 0, false }
