// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"strings"
	"testing"
	"time"
)

// The provisioning token is reported a month before it ends and once it
// has; a token with long to run, or none, is not.
func TestAProvisioningTokenAboutToEndIsReported(t *testing.T) {
	r := ruleByID(t, "scim.token-expiring")
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		ends time.Time
		want string
	}{
		{now.AddDate(0, 0, 10), "ends"},
		{now.AddDate(0, 0, -1), "ended"},
		{now.AddDate(0, 3, 0), ""},
		{time.Time{}, ""},
	} {
		got := r.Check(State{Now: now, SSO: SSOFacts{SCIMTokenEnds: c.ends}})
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || !strings.Contains(got[0].Detail, c.want+" ")) {
			t.Errorf("%s: %+v", c.ends, got)
		}
	}
}

// Somebody without a second factor is reported before the grace ends, more
// urgently in its last days, and after it as somebody who cannot get in.
func TestPeopleWithoutASecondFactorAreReported(t *testing.T) {
	r := ruleByID(t, "mfa.no-second-factor")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	state := func(from time.Time, who ...string) State {
		return State{Now: now, SSO: SSOFacts{MFAFrom: from, NoSecondFactor: who}}
	}
	if got := r.Check(state(now.AddDate(0, 0, 10))); len(got) != 0 {
		t.Errorf("nobody without one was reported: %+v", got)
	}
	got := r.Check(state(now.AddDate(0, 0, 10), "pat"))
	if len(got) != 1 || got[0].Severity != Medium || !strings.Contains(got[0].Detail, "become compulsory") {
		t.Errorf("ten days before: %+v", got)
	}
	if got := r.Check(state(now.AddDate(0, 0, 2), "pat")); len(got) != 1 || got[0].Severity != High {
		t.Errorf("two days before: %+v", got)
	}
	if got := r.Check(state(now.AddDate(0, 0, -1), "pat", "lee")); len(got) != 1 || !strings.Contains(got[0].Detail, "cannot sign in") ||
		!strings.Contains(got[0].Detail, "pat, lee") {
		t.Errorf("after: %+v", got)
	}
}
