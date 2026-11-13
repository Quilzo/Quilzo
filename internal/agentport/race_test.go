// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build race

package agentport

// The race detector makes what it watches several times slower, so a time
// budget measured without it is not one with it.
//
// TestAnAgentWithManyOperationsIsReadInTimeInProportion reads its agent file
// in under a second and is allowed eight. Under the race detector, which
// ci.yml runs this package with on every pull request, the same reading
// took over six seconds at best and over eight on a busier machine, and
// the test failed on a file that was read as quickly as it ever was.
// Ten times the budget is still a bound on the work: before tools were
// found by name, 80,000 operations took twenty-three seconds without the
// race detector, and this file has 100,000, which with it would be minutes.
func init() { raceSlowdown = 10 }
