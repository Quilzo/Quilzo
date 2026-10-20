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
