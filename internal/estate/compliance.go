// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/lifecycle"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Device compliance: what a machine is required to be, against what the
// tools say it is.
//
// The controls are the ones a SOC 2 or ISO 27001 assessor asks of an
// endpoint and that Vanta's device monitor and CIS benchmarks check: an
// encrypted disk, a screen that locks, a passcode on a phone, anti-malware,
// a password manager, an operating system that is still patched and kept
// up to date, a machine that has reported recently, and one that has not
// been rooted or carry prohibited software.
//
// # Unknown is not a pass
//
// A property no tool reports is unknown, and is neither held against the
// machine nor counted in its favour. A device page that showed "compliant"
// because nothing was measured would be the most dangerous thing on it; one
// that showed "violation" for every tool that does not measure screen lock
// would be ignored within a week. Unknown is shown as unknown.

// Verdict is one control's result on one machine.
type Verdict string

const (
	Pass    Verdict = "pass"
	Fail    Verdict = "fail"
	Unknown Verdict = "unknown"
	// NA: the control does not apply to this kind of machine.
	NA Verdict = "na"
)

// DeviceControl is one device requirement.
type DeviceControl struct {
	ID       string
	Name     string
	Severity telemetry.Severity
	// Applies is which kinds of machine it is asked of.
	Applies []Class
	// Why is what it protects against, in a sentence.
	Why string
}

// DeviceControls are the requirements, in the order they are shown.
var DeviceControls = []DeviceControl{
	{ID: "os-supported", Name: "Operating system still supported", Severity: telemetry.SeverityCritical,
		Applies: []Class{Computer, Mobile},
		Why:     "a version past its end of support gets no security fixes, so every flaw found after that date stays open"},
	{ID: "disk-encryption", Name: "Disk encrypted", Severity: telemetry.SeverityHigh,
		Applies: []Class{Computer, Mobile},
		Why:     "a lost or stolen machine with an unencrypted disk is a data breach"},
	{ID: "rooted", Name: "Not rooted or jailbroken", Severity: telemetry.SeverityCritical,
		Applies: []Class{Mobile},
		Why:     "a rooted phone has none of its platform's protections left"},
	{ID: "antivirus", Name: "Anti-malware running", Severity: telemetry.SeverityHigh,
		Applies: []Class{Computer},
		Why:     "the last line against malware that arrives by mail or download"},
	{ID: "passcode", Name: "Passcode set", Severity: telemetry.SeverityHigh,
		Applies: []Class{Mobile},
		Why:     "a phone without a passcode hands its mail and sessions to whoever picks it up"},
	{ID: "screen-lock", Name: "Screen locks when idle", Severity: telemetry.SeverityMedium,
		Applies: []Class{Computer},
		Why:     "an unlocked, unattended machine is signed in as its owner"},
	{ID: "patches", Name: "Security updates installed", Severity: telemetry.SeverityMedium,
		Applies: []Class{Computer, Mobile},
		Why:     "known, published flaws are the ones attackers use first"},
	{ID: "os-current", Name: "Newest version of its release", Severity: telemetry.SeverityLow,
		Applies: []Class{Computer, Mobile},
		Why:     "the newest point release carries the latest fixes for that line"},
	{ID: "checked-in", Name: "Reported in the last 14 days", Severity: telemetry.SeverityMedium,
		Applies: []Class{Computer, Mobile},
		Why:     "a machine that has gone quiet cannot be shown to be any of the rest"},
	{ID: "password-manager", Name: "Password manager installed", Severity: telemetry.SeverityLow,
		Applies: []Class{Computer},
		Why:     "reused and written-down passwords are how one breach becomes several"},
	{ID: "prohibited", Name: "No prohibited software", Severity: telemetry.SeverityMedium,
		Applies: []Class{Computer},
		Why:     "software the organisation has banned is banned for a reason"},
}

// CheckedIn is how recently a machine must have reported.
const CheckedIn = 14 * 24 * time.Hour

// Result is one control on one machine.
type Result struct {
	Control DeviceControl
	Verdict Verdict
	// Detail says what was found, and By which tools said so.
	Detail string
	By     []string
}

// Compliance is a machine measured against every control.
type Compliance struct {
	Machine *Machine
	// OS and Version are what the tools report, the most recent first.
	OS, Version string
	Lifecycle   lifecycle.Assessment
	Results     []Result
	// Status is compliant (every applicable control measured and passed),
	// violations (at least one failed) or unknown (none failed and at
	// least one could not be measured).
	Status string
	// Worst is the most severe failed control, zero when none failed.
	Worst telemetry.Severity
}

// Violations are the failed results, worst first.
func (c Compliance) Violations() []Result {
	var out []Result
	for _, r := range c.Results {
		if r.Verdict == Fail {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Control.Severity > out[j].Control.Severity })
	return out
}

// Comply measures one machine.
func Comply(m *Machine, now time.Time) Compliance {
	c := Compliance{Machine: m}
	// The newest report decides what it runs.
	var latest Device
	for _, r := range m.Records {
		if r.OSVersion != "" && (latest.OSVersion == "" || r.Seen.After(latest.Seen)) {
			latest = r
		}
	}
	c.OS, c.Version = firstNonEmpty(latest.OS, latest.Platform), latest.OSVersion
	if c.OS == "" {
		for _, r := range m.Records {
			if r.OS != "" {
				c.OS = r.OS
				break
			}
		}
	}
	c.Lifecycle = lifecycle.Assess(c.OS, c.Version, now)
	class := m.Class
	if class == "" {
		class = classify(c.OS)
	}
	measured, failed := 0, 0
	for _, ctl := range DeviceControls {
		res := Result{Control: ctl, Verdict: NA}
		if applies(ctl, class) {
			res = measure(ctl, m, c, now)
		}
		switch res.Verdict {
		case Fail:
			failed++
			if ctl.Severity > c.Worst {
				c.Worst = ctl.Severity
			}
		case Pass:
			measured++
		}
		c.Results = append(c.Results, res)
	}
	switch {
	case failed > 0:
		c.Status = "violations"
	case measured == 0 || hasUnknown(c.Results):
		c.Status = "unknown"
	default:
		c.Status = "compliant"
	}
	return c
}

func applies(ctl DeviceControl, class Class) bool {
	if class == "" {
		// Not known to be a phone or a computer: only what applies to both.
		return len(ctl.Applies) == 2
	}
	for _, a := range ctl.Applies {
		if a == class {
			return true
		}
	}
	return false
}

func hasUnknown(rs []Result) bool {
	for _, r := range rs {
		if r.Verdict == Unknown {
			return true
		}
	}
	return false
}

func measure(ctl DeviceControl, m *Machine, c Compliance, now time.Time) Result {
	res := Result{Control: ctl, Verdict: Unknown}
	flag := func(get func(Device) *bool, bad bool, failWord, passWord string) Result {
		said := m.Posture(get)
		var no, yes []string
		for src, v := range said {
			if v == bad {
				no = append(no, src)
			} else {
				yes = append(yes, src)
			}
		}
		sort.Strings(no)
		sort.Strings(yes)
		switch {
		case len(no) > 0:
			res.Verdict, res.By, res.Detail = Fail, no, failWord
			if len(yes) > 0 {
				res.Detail += " (" + strings.Join(yes, ", ") + " disagrees)"
			}
		case len(yes) > 0:
			res.Verdict, res.By, res.Detail = Pass, yes, passWord
		default:
			res.Detail = "no tool reports this"
		}
		return res
	}
	switch ctl.ID {
	case "os-supported":
		a := c.Lifecycle
		switch a.Currency {
		case lifecycle.Unsupported:
			res.Verdict = Fail
			res.Detail = fmt.Sprintf("%s has had no security fixes since %s", a.Cycle.Label, a.EOL.Format("2 January 2006"))
		case lifecycle.EndingSoon:
			res.Verdict = Pass
			res.Detail = fmt.Sprintf("%s: support ends in %d days", a.Cycle.Label, int(a.EOL.Sub(now).Hours()/24)+1)
		case lifecycle.Unknown:
			res.Detail = "the version is not one this program knows"
		default:
			res.Verdict = Pass
			res.Detail = a.Cycle.Label + " is supported"
		}
	case "os-current":
		switch c.Lifecycle.Currency {
		case lifecycle.UpdateAvailable:
			res.Verdict, res.Detail = Fail, fmt.Sprintf("%s is out; this runs %s", c.Lifecycle.Latest, c.Version)
		case lifecycle.Current, lifecycle.EndingSoon:
			res.Verdict, res.Detail = Pass, "runs the newest version of "+c.Lifecycle.Cycle.Label
		case lifecycle.Unsupported:
			res.Verdict, res.Detail = Fail, "its release is no longer updated at all"
		default:
			res.Detail = "the version is not one this program knows"
		}
	case "disk-encryption":
		return flag(func(d Device) *bool { return d.Encrypted }, false, "not encrypted", "encrypted")
	case "screen-lock":
		return flag(func(d Device) *bool { return d.ScreenLock }, false, "does not lock", "locks")
	case "antivirus":
		return flag(func(d Device) *bool { return d.Antivirus }, false, "none running", "running")
	case "passcode":
		return flag(func(d Device) *bool { return d.Passcode }, false, "no passcode", "set")
	case "password-manager":
		return flag(func(d Device) *bool { return d.PasswordManager }, false, "none installed", "installed")
	case "rooted":
		return flag(func(d Device) *bool { return d.Rooted }, true, "rooted or jailbroken", "intact")
	case "patches":
		worst, by := -1, []string{}
		for _, r := range m.Records {
			if r.MissingPatches != nil {
				by = append(by, r.ID.Issuer)
				if *r.MissingPatches > worst {
					worst = *r.MissingPatches
				}
			}
		}
		switch {
		case worst > 0:
			res.Verdict, res.By = Fail, by
			res.Detail = fmt.Sprintf("%d missing", worst)
		case worst == 0:
			res.Verdict, res.By, res.Detail = Pass, by, "none missing"
		default:
			res.Detail = "no tool reports this"
		}
	case "prohibited":
		worst, by := -1, []string{}
		for _, r := range m.Records {
			if r.Prohibited != nil {
				by = append(by, r.ID.Issuer)
				if *r.Prohibited > worst {
					worst = *r.Prohibited
				}
			}
		}
		switch {
		case worst > 0:
			res.Verdict, res.By, res.Detail = Fail, by, fmt.Sprintf("%d prohibited", worst)
		case worst == 0:
			res.Verdict, res.By, res.Detail = Pass, by, "none"
		default:
			res.Detail = "no tool reports this"
		}
	case "checked-in":
		seen := m.Seen()
		switch {
		case seen.IsZero():
			res.Detail = "no tool says when it last reported"
		case now.Sub(seen) > CheckedIn:
			res.Verdict = Fail
			res.Detail = fmt.Sprintf("last reported %d days ago", int(now.Sub(seen).Hours()/24))
		default:
			res.Verdict, res.Detail = Pass, "reported recently"
		}
	}
	return res
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
