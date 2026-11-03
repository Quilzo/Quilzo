// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"strings"
	"testing"
	"time"
)

// A connected stream that has gone a day without answering a verification
// is reported; one answered within the day, one connected less than a day
// ago, and no stream at all are not. A stream made by hand, which cannot be
// asked, is reported for what it is.
func TestASecurityEventStreamThatStopsAnsweringIsReported(t *testing.T) {
	r := ruleByID(t, "signals.stream-silent")
	if r.Severity != Medium {
		t.Errorf("severity %s", r.Severity)
	}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	week := now.AddDate(0, 0, -7)
	for _, c := range []struct {
		name  string
		facts *SignalsFacts
		want  string
	}{
		{"none connected", nil, ""},
		{"answered this morning", &SignalsFacts{Connected: week, Verified: now.Add(-3 * time.Hour)}, ""},
		{"connected an hour ago", &SignalsFacts{Connected: now.Add(-time.Hour)}, ""},
		{"answered 25 hours ago", &SignalsFacts{Connected: week, Verified: now.Add(-25 * time.Hour)}, "last answered"},
		{"never answered", &SignalsFacts{Connected: week}, "never answered"},
		{"made by hand", &SignalsFacts{Connected: week, Manual: true}, "cannot be asked"},
	} {
		got := r.Check(State{Now: now, SSO: SSOFacts{Signals: c.facts}})
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: reported %+v", c.name, got)
			}
			continue
		}
		if len(got) != 1 || !strings.Contains(got[0].Detail, c.want) || got[0].Fix == "" {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}
