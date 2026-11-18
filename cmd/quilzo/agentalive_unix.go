// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// holdRunAlive takes the lock that says this process is working on a run,
// and keeps it until the file it returns is closed. flock is let go of by
// the kernel when the descriptor closes, which is when the process ends,
// however it ends: that is the whole of what the lock is for.
//
// Tried for a second rather than waited on: whoever reads a run takes the
// lock for a moment to see whether anybody holds it, and only that should
// ever be in the way.
func holdRunAlive(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || i >= 50 {
			f.Close()
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runAliveLetGo reports whether the lock a run's process held has been let
// go of, which means that process has ended. False when it cannot tell:
// no lock file, or one that could not be asked.
func runAliveLetGo(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return false
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return true
}
