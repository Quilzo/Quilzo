// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build race

package ical

// The race detector makes what it watches several times slower, so a time
// budget measured without it is not one with it.
//
// TestManyOldRulesAreQuickToWorkOut works out its calendar in under a second
// and is allowed five. Under the race detector, which nightly.yml runs every
// package with, the same work took from 4 to 14 seconds on a busy machine,
// and the test failed on a calendar that was as quick as it ever was. Ten
// times the budget is still a bound on the work: walking those rules without
// maxWalk is over a hundred times as much of it.
func init() { raceSlowdown = 10 }
