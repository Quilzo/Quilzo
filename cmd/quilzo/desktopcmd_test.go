// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// A consent that could not be asked for is a failure, and says so.
//
// `quilzo desktop consent` printed the portal's error, recorded a failure,
// and then returned what closing a desktop it never had returns, which is
// nil: exit status 0. A script or an agent asking for somebody's desktop
// was told the question had been put when it had not.
func TestADesktopConsentThatFailedSaysSo(t *testing.T) {
	root := connectStore(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	for name, bus := range map[string]string{
		"no session bus":          "",
		"a bus that is not there": "unix:path=" + t.TempDir() + "/no-bus",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", bus)
			if err := cmdDesktop(root, []string{"consent"}); err == nil {
				t.Fatal("a consent the desktop was never asked for succeeded")
			}
		})
	}
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, e := range evs {
		if e.Action == "desktop.consent" && e.Outcome == audit.Failure {
			failed++
		}
	}
	if failed != 2 {
		t.Errorf("%d failed consent(s) are on the record; two were tried", failed)
	}
}
