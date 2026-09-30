// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"strconv"
	"strings"
	"time"
)

// Reading what tools write, in the words they write it.
//
// Every table here is closed. A value not in one is unknown, and unknown is
// kept as unknown: a posture field that says "Suspended" is not a pass and
// is not a failure, and turning it into either would be this program
// inventing a fact about somebody's laptop.

// yes and no are the ways tools say a thing holds or does not.
var (
	yes = map[string]bool{"true": true, "yes": true, "1": true, "pass": true,
		"passed": true, "ok": true, "enabled": true, "on": true,
		"encrypted": true, "compliant": true, "installed": true}
	no = map[string]bool{"false": true, "no": true, "0": true, "fail": true,
		"failed": true, "disabled": true, "off": true,
		"not encrypted": true, "notencrypted": true, "unencrypted": true,
		"noncompliant": true, "non-compliant": true, "not installed": true}
)

// truth reads a yes or a no, and nothing else.
func truth(v string) *bool {
	low := strings.ToLower(strings.TrimSpace(v))
	switch {
	case yes[low]:
		t := true
		return &t
	case no[low]:
		f := false
		return &f
	}
	return nil
}

// active and gone are how tools say somebody is or is not current.
var (
	active = map[string]bool{"active": true, "current": true,
		"on_leave": true, "enabled": true, "true": true}
	gone = map[string]bool{"archived": true, "former": true, "inactive": true,
		"terminated": true, "deactivated": true, "disabled": true,
		"suspended": true, "deleted": true, "offboarded": true, "false": true}
)

// current reads whether somebody is current. UPCOMING is neither: they have
// not started, and saying either would put them in the wrong queue.
func current(v string) *bool {
	low := strings.ToLower(strings.TrimSpace(v))
	switch {
	case active[low]:
		t := true
		return &t
	case gone[low]:
		f := false
		return &f
	}
	return nil
}

// taskStatus is a compliance task's state, in Vanta's words, which the
// other tools are read into.
var taskStatus = map[string]string{
	"complete": "COMPLETE", "completed": "COMPLETE", "passed": "COMPLETE",
	"done": "COMPLETE", "overdue": "OVERDUE", "past_due": "OVERDUE",
	"due_soon": "DUE_SOON", "in_progress": "DUE_SOON", "not_started": "DUE_SOON",
	"none": "NONE", "paused": "PAUSED",
}

func task(v string) string {
	return taskStatus[strings.ToLower(strings.TrimSpace(v))]
}

// finished reads whether a training enrolment was completed. KnowBe4 says
// Passed or Completed; Failed, Not Started, In Progress and Past Due are not.
func finished(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "passed", "completed", "complete", "done":
		return true
	}
	return false
}

// when reads a time in the forms tools write one: RFC 3339, a date, or
// epoch milliseconds (ManageEngine). A negative or zero epoch is ManageEngine
// saying "never", which is no time at all.
func when(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		switch {
		case n > 1e11:
			return time.UnixMilli(n).UTC()
		case n > 1e9:
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Time{}
}

// number reads a figure, or nil.
func number(v string) *float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return nil
	}
	return &f
}

// count reads a whole number that cannot be negative, or nil.
func count(v string) *int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

// placeholders are the serial numbers a manufacturer ships when it did not
// set one, collected from what BIOSes, hypervisors and MDMs report. Each
// is on thousands of machines, and a join on any of them makes those
// machines one.
var placeholders = map[string]bool{
	"": true, "0": true, "00000000": true, "000000000000": true,
	"0000000000000000": true, "123456789": true, "0123456789": true,
	"1234567890": true, "NONE": true, "NA": true, "N/A": true, "NULL": true,
	"UNKNOWN": true, "DEFAULT": true, "DEFAULTSTRING": true,
	"TOBEFILLEDBYO.E.M.": true, "TOBEFILLEDBYOEM": true, "OEM": true,
	"SYSTEMSERIALNUMBER": true, "CHASSISSERIALNUMBER": true,
	"NOTSPECIFIED": true, "NOTAPPLICABLE": true, "INVALID": true,
	"SERIAL": true, "SERIALNUMBER": true, "XXXXXXXX": true, "TBD": true,
	"EMPTY": true, "NOSERIAL": true, "--": true, "-": true,
}

// Serial normalises a serial number, or returns empty for one that is not
// usable as an identity: a known placeholder, fewer than five characters, or
// the same character over and over.
func Serial(v string) string {
	up := strings.ToUpper(strings.TrimSpace(v))
	up = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(up)
	if placeholders[up] || len(up) < 5 {
		return ""
	}
	if strings.Count(up, up[:1]) == len(up) {
		return ""
	}
	return up
}

// Class is what kind of machine something is, which decides which tools
// are expected to know about it: an MDM for phones, an endpoint manager for
// computers.
type Class string

const (
	Computer Class = "computer"
	Mobile   Class = "mobile"
)

// classify reads a class from an OS or platform name, or empty.
func classify(os string) Class {
	low := strings.ToLower(os)
	switch {
	case strings.Contains(low, "ios"), strings.Contains(low, "ipados"),
		strings.Contains(low, "android"), strings.Contains(low, "iphone"),
		strings.Contains(low, "ipad"), strings.Contains(low, "chromeos") &&
			strings.Contains(low, "mobile"):
		return Mobile
	case strings.Contains(low, "windows"), strings.Contains(low, "mac"),
		strings.Contains(low, "linux"), strings.Contains(low, "ubuntu"),
		strings.Contains(low, "chrome"):
		return Computer
	}
	return ""
}

// Email normalises an address for a join: trimmed and lowercased. Nothing
// cleverer — no stripping of dots or plus tags, which is right for one
// provider and merges two people at another.
func Email(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if !strings.Contains(v, "@") || strings.ContainsAny(v, " \t") {
		return ""
	}
	return v
}

// shared are the local parts of mailboxes that belong to a team rather than
// a person. Joining on one merges everybody who reads it.
var shared = map[string]bool{
	"admin": true, "administrator": true, "info": true, "support": true,
	"help": true, "helpdesk": true, "security": true, "abuse": true,
	"postmaster": true, "noreply": true, "no-reply": true,
	"donotreply": true, "hr": true, "it": true, "ops": true, "sales": true,
	"billing": true, "accounts": true, "finance": true, "legal": true,
	"marketing": true, "press": true, "contact": true, "team": true,
	"office": true, "hello": true, "careers": true, "jobs": true,
	"dpo": true, "privacy": true, "compliance": true, "root": true,
}

// Shared reports whether an address is a team's rather than a person's.
func Shared(email string) bool {
	local, _, _ := strings.Cut(email, "@")
	return shared[local]
}
