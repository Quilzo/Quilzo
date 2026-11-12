// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// What a command shows of somebody's words on one line is cut where a
// character starts, and still comes to its width with the mark: a goal, a
// note, a reason, in whatever language they were written.
func TestWordsOnOneLineAreCutBetweenCharacters(t *testing.T) {
	if got, want := truncate(strings.Repeat("a", 58)+"中文 and more", 60), strings.Repeat("a", 57)+"…"; got != want {
		t.Errorf("%d bytes, ending %q", len(got), got[max(0, len(got)-6):])
	}
}
