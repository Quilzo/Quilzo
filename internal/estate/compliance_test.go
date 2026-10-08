// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var day = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func on() *bool    { b := true; return &b }
func off() *bool   { b := false; return &b }
func n(i int) *int { return &i }

func dev(issuer, os, version string, seen time.Time) Device {
	return Device{ID: telemetry.ID{Issuer: issuer, Value: "d1"}, OS: os, OSVersion: version, Seen: seen}
}

func verdict(c Compliance, id string) Result {
	for _, r := range c.Results {
		if r.Control.ID == id {
			return r
		}
	}
	return Result{}
}

// A laptop that does everything asked of it is compliant.
func TestAMachineThatMeetsEveryControlIsCompliant(t *testing.T) {
	d := dev("endpointcentral", "macOS", "26.7.1", day.Add(-time.Hour))
	d.Encrypted, d.ScreenLock, d.Antivirus, d.PasswordManager = on(), on(), on(), on()
	d.MissingPatches, d.Prohibited = n(0), n(0)
	c := Comply(&Machine{Class: Computer, Records: []Device{d}}, day)
	if c.Status != "compliant" || len(c.Violations()) != 0 {
		t.Fatalf("status %s, violations %+v", c.Status, c.Violations())
	}
	if verdict(c, "passcode").Verdict != NA || verdict(c, "rooted").Verdict != NA {
		t.Error("a phone's controls were asked of a laptop")
	}
}

// An old, unencrypted Windows 10 laptop that has gone quiet fails on each
// count, worst first, and says which tool said so.
func TestEachFailureIsAViolationWithItsSource(t *testing.T) {
	d := dev("endpointcentral", "Windows 10 Pro", "10.0.19045.4529", day.Add(-20*24*time.Hour))
	d.Encrypted, d.ScreenLock, d.Antivirus = off(), on(), on()
	d.MissingPatches = n(7)
	c := Comply(&Machine{Class: Computer, Records: []Device{d}}, day)
	v := c.Violations()
	if c.Status != "violations" || c.Worst != telemetry.SeverityCritical {
		t.Fatalf("status %s worst %v", c.Status, c.Worst)
	}
	ids := []string{}
	for _, r := range v {
		ids = append(ids, r.Control.ID)
	}
	got := strings.Join(ids, ",")
	for _, want := range []string{"os-supported", "disk-encryption", "patches", "checked-in", "os-current"} {
		if !strings.Contains(got, want) {
			t.Errorf("violations %s lack %s", got, want)
		}
	}
	if v[0].Control.ID != "os-supported" {
		t.Errorf("the worst violation is not first: %s", got)
	}
	if enc := verdict(c, "disk-encryption"); len(enc.By) != 1 || enc.By[0] != "endpointcentral" {
		t.Errorf("encryption's failure names %v", enc.By)
	}
	if !strings.Contains(verdict(c, "os-supported").Detail, "14 October 2025") {
		t.Errorf("the end of support is not dated: %s", verdict(c, "os-supported").Detail)
	}
}

// One tool saying no is a violation even when another says yes; the
// disagreement is in the detail, not hidden by it.
func TestAToolSayingNoIsNotOutvoted(t *testing.T) {
	a := dev("vanta", "macOS", "26.7.1", day)
	a.Encrypted = on()
	b := dev("mdmplus", "macOS", "26.7.1", day)
	b.Encrypted = off()
	c := Comply(&Machine{Class: Computer, Records: []Device{a, b}}, day)
	r := verdict(c, "disk-encryption")
	if r.Verdict != Fail || !strings.Contains(r.Detail, "vanta disagrees") {
		t.Errorf("encryption: %s %q", r.Verdict, r.Detail)
	}
}

// Nothing measured is unknown, never compliant.
func TestWhatNoToolMeasuresIsUnknownNotPassed(t *testing.T) {
	d := dev("entra", "iOS", "26.7.1", day)
	c := Comply(&Machine{Class: Mobile, Records: []Device{d}}, day)
	if c.Status != "unknown" {
		t.Errorf("an unmeasured phone is %s", c.Status)
	}
	if verdict(c, "passcode").Verdict != Unknown || verdict(c, "antivirus").Verdict != NA {
		t.Error("a phone's passcode is not unknown, or a laptop control was asked of it")
	}
	if verdict(c, "os-supported").Verdict != Pass {
		t.Error("the version alone did not say iOS 26 is supported")
	}
}

// A rooted phone is a critical violation.
func TestARootedPhoneIsCritical(t *testing.T) {
	d := dev("mdmplus", "Android", "14", day)
	d.Rooted, d.Passcode, d.Encrypted = on(), on(), on()
	c := Comply(&Machine{Class: Mobile, Records: []Device{d}}, day)
	if verdict(c, "rooted").Verdict != Fail || c.Worst != telemetry.SeverityCritical {
		t.Errorf("rooted: %s, worst %v", verdict(c, "rooted").Verdict, c.Worst)
	}
}
