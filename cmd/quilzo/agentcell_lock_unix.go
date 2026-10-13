// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// holdCell claims this machine's one cell, or says another run has it.
func holdCell(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "cell.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another run is using this machine's desktop cell; one runs at a time")
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
