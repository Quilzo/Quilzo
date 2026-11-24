// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package out

import "os"

// isTTY is whether f is not the null device, on a platform no release is
// built for: the null device is the character device a command's output is
// most often sent to, and it is not a terminal.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	null, nerr := os.Stat(os.DevNull)
	return err != nil || nerr != nil || !os.SameFile(info, null)
}
