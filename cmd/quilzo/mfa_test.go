// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/posture"
)

// The grace is written down the first time it is asked for and read the
// same ever after, and posture names who has no second factor.
func TestTheGraceIsWrittenOnceAndThePeopleWithoutASecondFactorAreNamed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	now := time.Now()
	from := mfaFrom(root, now)
	if d := from.Sub(now); d < mfaGrace-time.Minute || d > mfaGrace+time.Minute {
		t.Fatalf("the grace ends in %s", d)
	}
	if again := mfaFrom(root, now.Add(10*24*time.Hour)); !again.Equal(from) {
		t.Errorf("the grace moved from %s to %s", from, again)
	}
	if got, ok := mfaFromIfSet(root); !ok || !got.Equal(from) {
		t.Errorf("the date read back is %s %v", got, ok)
	}
	if err := cmdAuth(root, []string{"grant", "pat", "author"}); err != nil {
		t.Fatal(err)
	}
	none := withoutSecondFactor(root)
	if !slices.Contains(none, "pat") {
		t.Fatalf("pat has no passkey and is not named: %v", none)
	}
	for _, n := range none {
		if strings.HasPrefix(n, "agent/") {
			t.Errorf("an agent was counted as a person: %s", n)
		}
	}
	st := Observe(root, t.TempDir(), posture.ServerFacts{})
	if !st.SSO.MFAFrom.Equal(from) || !slices.Contains(st.SSO.NoSecondFactor, "pat") {
		t.Errorf("posture sees %s and %v", st.SSO.MFAFrom, st.SSO.NoSecondFactor)
	}
}
