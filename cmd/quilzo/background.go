// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync"
	"time"
)

// Work that must not keep its caller waiting, and must not be lost either.
//
// Telling the security contact is a message through a mail relay, which
// can take seconds or not answer at all. Sent from inside the request that
// raised the signal, a slow relay held that request — and a signal is
// raised most often by somebody hammering the server, who would then hold
// as many of its workers as they cared to. So it is sent in the background,
// and the command line, which would otherwise exit in the middle of a
// message, waits for what it started before it ends.

var backgroundWork sync.WaitGroup

// inBackground runs fn without its caller waiting for it.
func inBackground(fn func()) {
	backgroundWork.Add(1)
	go func() {
		defer backgroundWork.Done()
		fn()
	}()
}

// finishBackground waits for what was started in the background, for at
// most limit, and reports whether all of it finished.
func finishBackground(limit time.Duration) bool {
	done := make(chan struct{})
	go func() {
		backgroundWork.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(limit):
		return false
	}
}
