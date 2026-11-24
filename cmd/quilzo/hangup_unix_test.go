// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// hangup sends this process the SIGHUP that `quilzo site` and `quilzo serve`
// read the design and the settings again on. It lives in its own file
// because syscall.Kill does not exist on Windows, and a test that only skips
// the call there at run time still has to compile there.
func hangup() error { return syscall.Kill(os.Getpid(), syscall.SIGHUP) }
