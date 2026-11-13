// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "errors"

// hangup has nothing to send on Windows, which has no SIGHUP: the test that
// would send it reloads the site directly there instead.
func hangup() error { return errors.New("there is no SIGHUP on Windows") }
