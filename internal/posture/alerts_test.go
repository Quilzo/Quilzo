// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"slices"
	"strings"
	"testing"
)

// Every alert is a mail to a mailto: address through mail.json, and with
// either missing it went nowhere and nothing said so. A contact that is
// only a web page or a telephone number is somewhere for a researcher to
// report, not somewhere an alert can go.
func TestAlertsWithNowhereToGoAreReported(t *testing.T) {
	r := ruleByID(t, "alerts.unrouted")
	if got := r.Check(State{}); len(got) != 0 {
		t.Errorf("facts nobody gathered: %+v", got)
	}
	if got := r.Check(State{Alerts: AlertFacts{Checked: true, Address: true, Relay: true}}); len(got) != 0 {
		t.Errorf("an address and a relay: %+v", got)
	}
	got := r.Check(State{Alerts: AlertFacts{Checked: true, Relay: true}})
	if len(got) != 1 || got[0].Resource != "security.contact" || !strings.Contains(got[0].Detail, "mailto:") {
		t.Errorf("no mailto: address: %+v", got)
	}
	got = r.Check(State{Alerts: AlertFacts{Checked: true, Address: true}})
	if len(got) != 1 || got[0].Resource != "mail.json" {
		t.Errorf("no relay: %+v", got)
	}
	got = r.Check(State{Alerts: AlertFacts{Checked: true, Address: true, Problem: "mail.json needs a host"}})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "needs a host") {
		t.Errorf("a relay that cannot be used: %+v", got)
	}
	// Not looked at is not passing.
	if rep := Scan(State{}, nil); !slices.Contains(rep.Skipped, "alerts.unrouted") {
		t.Error("a scan that did not look at alerts says they are routed")
	}
}
