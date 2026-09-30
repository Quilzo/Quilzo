// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package estate is what the company's tools say about its people and their
// machines, joined: one person however many systems know them, one device
// however many systems manage it.
//
// # Why this is its own layer
//
// A connector brings back what one tool said, in that tool's words: Vanta's
// employment status is FORMER, KnowBe4's is archived, MDM Plus says a device
// is removed. The checks that matter are the ones that set two tools side by
// side — the leaver whose laptop still checks in, the laptop Vanta monitors
// that no MDM manages, the training one system calls finished and another
// overdue — and they can only be written once the words agree.
//
// So a connector's output is read in a small vocabulary (the field names the
// shipped manifests map to, documented on each type below), and a new tool
// joins every check and every chart by mapping to it. Nothing here knows
// KnowBe4 from Vanta except through what their records say.
//
// # What is refused rather than guessed
//
// A serial number shared by two machines in one tool is not a serial number:
// "To be filled by O.E.M." is on thousands of white-box PCs, and a join on it
// makes them one machine with one owner and one posture. A shared mailbox is
// not a person. A tool that was not read, or not read to the end, is absent
// from every check that needs it, and the check says so — a finding that
// could not be looked for is reported as not looked for, never as clean.
package estate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Kind is what a record describes: the Produces of the endpoint it came from.
type Kind string

// The kinds, as internal/connector names them.
const (
	KindPerson        Kind = "identity"
	KindDevice        Kind = "device"
	KindEvent         Kind = "event"
	KindTraining      Kind = "training"
	KindPhishing      Kind = "phishing"
	KindPolicy        Kind = "policy"
	KindSoftware      Kind = "software"
	KindVulnerability Kind = "vulnerability"
	KindControl       Kind = "control"
)

// Line is one record as `quilzo connect run` writes it: the mapped fields,
// with _source, _endpoint and _produces saying where it came from.
type Line map[string]string

// Snapshot is what one tool said, read at one time.
type Snapshot struct {
	Source string    `json:"source"`
	At     time.Time `json:"at"`
	// Endpoints says, for each endpoint read, what it produces, which
	// endpoint it was read per record of, and whether it was read to the end.
	Endpoints map[string]EndpointInfo `json:"endpoints"`
	Lines     []Line                  `json:"-"`
}

// EndpointInfo is one endpoint's part of a snapshot.
type EndpointInfo struct {
	Produces Kind   `json:"produces"`
	Of       string `json:"of,omitempty"`
	Complete bool   `json:"complete"`
	Records  int    `json:"records"`
}

// MaxLine bounds one record. A mapped record is a few dozen short fields.
const MaxLine = 256 << 10

// ReadLines reads records written one JSON object per line.
func ReadLines(r io.Reader) ([]Line, error) {
	var out []Line
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	for n := 1; sc.Scan(); n++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var l Line
		if err := json.Unmarshal([]byte(text), &l); err != nil {
			return nil, fmt.Errorf("line %d is not a record: %w", n, err)
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// complete reports whether a snapshot read every endpoint producing a kind,
// and read at least one. A kind nobody read is not a kind with nothing in it.
func (s Snapshot) complete(k Kind) bool {
	any := false
	for _, e := range s.Endpoints {
		if e.Produces != k {
			continue
		}
		any = true
		if !e.Complete {
			return false
		}
	}
	return any
}

// Person is one tool's record of somebody.
//
// Fields read from a record: id, email, employee_number, name, first_name,
// last_name, title, department, division, office, manager, manager_email;
// status, employment, archived and ended for whether they are current;
// phish_prone and risk_score; and the task statuses training, policies,
// device_monitoring and background_check, with training_due and
// policies_due.
type Person struct {
	ID             telemetry.ID `json:"id"`
	Email          string       `json:"email,omitempty"`
	EmployeeNumber string       `json:"employee_number,omitempty"`
	Name           string       `json:"name,omitempty"`
	Title          string       `json:"title,omitempty"`
	Department     string       `json:"department,omitempty"`
	Office         string       `json:"office,omitempty"`
	ManagerEmail   string       `json:"manager_email,omitempty"`
	// Active is whether the tool considers them current: nil when it does
	// not say, which is different from saying no.
	Active     *bool     `json:"active,omitempty"`
	Ended      time.Time `json:"ended,omitempty"`
	PhishProne *float64  `json:"phish_prone,omitempty"`
	RiskScore  *float64  `json:"risk_score,omitempty"`
	// Tasks are the compliance tasks the tool tracks, by name, each one of
	// the statuses in taskStatus.
	Tasks map[string]string    `json:"tasks,omitempty"`
	Due   map[string]time.Time `json:"due,omitempty"`
}

// Device is one tool's record of a machine.
//
// Fields: id, serial, name, os, os_version, platform, model, owner_email,
// owner_name, user, seen, removed, lost_mode; and the posture fields
// encryption or encrypted, screenlock, antivirus, password_manager, rooted,
// passcode_set, missing_patches and prohibited_software, which may also
// arrive on a record read per device and are merged onto it.
type Device struct {
	ID         telemetry.ID `json:"id"`
	Serial     string       `json:"serial,omitempty"`
	Name       string       `json:"name,omitempty"`
	OS         string       `json:"os,omitempty"`
	OSVersion  string       `json:"os_version,omitempty"`
	Platform   string       `json:"platform,omitempty"`
	Class      Class        `json:"class,omitempty"`
	OwnerEmail string       `json:"owner_email,omitempty"`
	OwnerName  string       `json:"owner_name,omitempty"`
	// User is who is signed in to it, in the tool's form: often a logon
	// name rather than an address, so it is shown and never joined on.
	User    string    `json:"user,omitempty"`
	Seen    time.Time `json:"seen,omitempty"`
	Removed bool      `json:"removed,omitempty"`

	Encrypted       *bool `json:"encrypted,omitempty"`
	ScreenLock      *bool `json:"screenlock,omitempty"`
	Antivirus       *bool `json:"antivirus,omitempty"`
	PasswordManager *bool `json:"password_manager,omitempty"`
	Rooted          *bool `json:"rooted,omitempty"`
	Passcode        *bool `json:"passcode,omitempty"`
	MissingPatches  *int  `json:"missing_patches,omitempty"`
	Prohibited      *int  `json:"prohibited_software,omitempty"`
}

// Training is one enrolment. Fields: id, user, email, module, kind, status,
// completed, policy_acknowledged.
type Training struct {
	ID        telemetry.ID `json:"id"`
	User      telemetry.ID `json:"user"`
	Email     string       `json:"email,omitempty"`
	Module    string       `json:"module,omitempty"`
	Policy    bool         `json:"policy,omitempty"`
	Status    string       `json:"status,omitempty"`
	Done      bool         `json:"done"`
	Completed time.Time    `json:"completed,omitempty"`
	// Acknowledged is a policy enrolment's acceptance: nil when not a
	// policy or not reported.
	Acknowledged *bool `json:"acknowledged,omitempty"`
}

// Phish is one person's result in one simulated phishing test. Fields: id,
// parent (the test), user, email, delivered, opened, clicked, replied,
// attachment_opened, macro_enabled, data_entered, qr_scanned, reported.
type Phish struct {
	ID          telemetry.ID `json:"id"`
	Test        string       `json:"test,omitempty"`
	TestName    string       `json:"test_name,omitempty"`
	User        telemetry.ID `json:"user"`
	Email       string       `json:"email,omitempty"`
	Delivered   time.Time    `json:"delivered,omitempty"`
	Clicked     time.Time    `json:"clicked,omitempty"`
	DataEntered time.Time    `json:"data_entered,omitempty"`
	Reported    time.Time    `json:"reported,omitempty"`
	// Other is the first of the other failures: a reply, an opened
	// attachment, enabled macros, a scanned QR code.
	Other time.Time `json:"other,omitempty"`
}

// Outcome is the result in words, worst first.
func (p Phish) Outcome() string {
	switch {
	case !p.DataEntered.IsZero():
		return "Entered data"
	case !p.Clicked.IsZero():
		return "Clicked"
	case !p.Other.IsZero():
		return "Opened an attachment, replied or scanned"
	case !p.Reported.IsZero():
		return "Reported it"
	case !p.Delivered.IsZero():
		return "Did nothing"
	}
	return "Not delivered"
}

// Failed reports whether this result is a failure, and when.
func (p Phish) Failed() (time.Time, bool) {
	var first time.Time
	for _, t := range []time.Time{p.Clicked, p.DataEntered, p.Other} {
		if !t.IsZero() && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	return first, !first.IsZero()
}

// Software is one application on one device. Fields: parent, name,
// version, maker, prohibited.
type Software struct {
	Device     telemetry.ID `json:"device"`
	Name       string       `json:"name"`
	Version    string       `json:"version,omitempty"`
	Maker      string       `json:"maker,omitempty"`
	Prohibited bool         `json:"prohibited,omitempty"`
}

// Vulnerability is one open weakness on one device. Fields: computer or
// parent, id, name, severity, status.
type Vulnerability struct {
	Device   telemetry.ID `json:"device"`
	ID       string       `json:"id"`
	Name     string       `json:"name,omitempty"`
	Severity string       `json:"severity,omitempty"`
	Open     bool         `json:"open"`
}

// Control is one automated check a compliance tool runs across the company,
// or one policy's state. Fields: id, name, category, status, remediation,
// failing_items, latest_version.
type Control struct {
	ID       telemetry.ID `json:"id"`
	Name     string       `json:"name"`
	Category string       `json:"category,omitempty"`
	Policy   bool         `json:"policy,omitempty"`
	Passing  *bool        `json:"passing,omitempty"`
	Failing  int          `json:"failing,omitempty"`
}

// sortedKeys is a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
