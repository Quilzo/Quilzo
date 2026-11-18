// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import (
	"errors"
	"os"
)

// holdRunAlive has no lock to take here, so a run's record is judged by
// when it was last written (agent.StaleAfter), as it always was.
func holdRunAlive(string) (*os.File, error) {
	return nil, errors.New("a run's lock is taken only on Unix")
}

func runAliveLetGo(string) bool { return false }
