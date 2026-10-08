// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/workforce"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func ago(days int) string {
	return now.AddDate(0, 0, -days).Format(time.RFC3339)
}

// snap is one tool's snapshot: endpoint name → kind, and lines keyed by
// endpoint. Every endpoint is complete unless listed in partial.
type snap struct {
	source  string
	kinds   map[string]Kind
	lines   map[string][]Line
	partial []string
}

func (s snap) build() Snapshot {
	out := Snapshot{Source: s.source, At: now,
		Endpoints: map[string]EndpointInfo{}}
	for ep, k := range s.kinds {
		complete := true
		for _, p := range s.partial {
			if p == ep {
				complete = false
			}
		}
		out.Endpoints[ep] = EndpointInfo{Produces: k, Complete: complete,
			Records: len(s.lines[ep])}
		for _, l := range s.lines[ep] {
			c := Line{"_source": s.source, "_endpoint": ep,
				"_produces": string(k)}
			for k2, v := range l {
				c[k2] = v
			}
			out.Lines = append(out.Lines, c)
		}
	}
	return out
}

func vantaSnap(people, computers []Line) snap {
	return snap{source: "vanta", kinds: map[string]Kind{
		"people": KindPerson, "computers": KindDevice},
		lines: map[string][]Line{"people": people, "computers": computers}}
}

func kb4Snap(users, enrollments, results []Line) snap {
	return snap{source: "knowbe4", kinds: map[string]Kind{
		"users": KindPerson, "enrollments": KindTraining,
		"phishing_results": KindPhishing},
		lines: map[string][]Line{"users": users, "enrollments": enrollments,
			"phishing_results": results}}
}

func ecSnap(computers []Line, drives []Line) snap {
	return snap{source: "endpointcentral", kinds: map[string]Kind{
		"computers": KindDevice, "encryption": KindControl},
		lines: map[string][]Line{"computers": computers, "encryption": drives}}
}

func evaluate(snaps ...snap) (*Estate, Outcome) {
	var built []Snapshot
	for _, s := range snaps {
		built = append(built, s.build())
	}
	e := Build(built, nil, now)
	return e, Evaluate(e, now)
}

func found(o Outcome, check string) []finding.Finding {
	var out []finding.Finding
	for _, f := range o.Findings {
		if f.Source == "estate/"+check {
			out = append(out, f)
		}
	}
	return out
}

// --- joining people ---------------------------------------------------------

func TestPeopleAreJoinedByExactEmailAcrossTools(t *testing.T) {
	e, _ := evaluate(
		vantaSnap([]Line{{"id": "v1", "email": "Jane.Doe@Acme.com",
			"employment": "CURRENT"}}, nil),
		kb4Snap([]Line{{"id": "k1", "email": "jane.doe@acme.com ",
			"status": "active"}}, nil, nil))
	if len(e.People) != 1 {
		t.Fatalf("%d people; one address in two tools is one person",
			len(e.People))
	}
	if got := strings.Join(e.People[0].JoinedBy, ","); got != "email" {
		t.Errorf("joined by %q", got)
	}
}

func TestATeamMailboxAndADuplicateAreNotJoined(t *testing.T) {
	e, _ := evaluate(
		vantaSnap([]Line{
			{"id": "v1", "email": "security@acme.com"},
			{"id": "v2", "email": "sam@acme.com"},
			{"id": "v3", "email": "sam@acme.com"}}, nil),
		kb4Snap([]Line{
			{"id": "k1", "email": "security@acme.com"},
			{"id": "k2", "email": "sam@acme.com"}}, nil, nil))
	if len(e.People) != 5 {
		t.Errorf("%d people from five records that must stay apart",
			len(e.People))
	}
	notes := strings.Join(e.Notes, "\n")
	if !strings.Contains(notes, "team mailbox") ||
		!strings.Contains(notes, "records in vanta") {
		t.Errorf("the refusals are not explained: %s", notes)
	}
}

func TestAConfirmedLinkJoinsWhatEmailCannot(t *testing.T) {
	var built []Snapshot
	for _, s := range []snap{
		vantaSnap([]Line{{"id": "v1", "email": "jdoe@acme.com"}}, nil),
		kb4Snap([]Line{{"id": "k1", "email": "jane.doe@acme.com"}}, nil, nil),
	} {
		built = append(built, s.build())
	}
	e := Build(built, []workforce.Link{{
		A:  telemetry.ID{Issuer: "vanta", Value: "v1"},
		B:  telemetry.ID{Issuer: "knowbe4", Value: "k1"},
		At: now, By: "ada", Because: "renamed"}}, now)
	if len(e.People) != 1 || e.People[0].JoinedBy[0] != "confirmed" {
		t.Errorf("a confirmed link was not applied: %d people", len(e.People))
	}
}

// --- joining machines -------------------------------------------------------

func TestMachinesAreJoinedBySerialHoweverItIsWritten(t *testing.T) {
	e, _ := evaluate(
		vantaSnap(nil, []Line{{"id": "a", "serial": "c02x-abc 12",
			"os": "macOS"}}),
		ecSnap([]Line{{"id": "301", "serial": "C02XABC12",
			"os": "macOS 14"}}, nil))
	if len(e.Machines) != 1 || len(e.Machines[0].Sources) != 2 {
		t.Fatalf("%d machines", len(e.Machines))
	}
}

func TestAPlaceholderOrSharedSerialJoinsNothing(t *testing.T) {
	e, _ := evaluate(
		vantaSnap(nil, []Line{
			{"id": "a", "serial": "To be filled by O.E.M."},
			{"id": "b", "serial": "VMWARE42"}}),
		ecSnap([]Line{
			{"id": "1", "serial": "To Be Filled By O.E.M."},
			{"id": "2", "serial": "vmware42"},
			{"id": "3", "serial": "VMware-42"},
			{"id": "4", "serial": "0000000000"}}, nil))
	for _, m := range e.Machines {
		if len(m.Records) > 1 {
			t.Errorf("%s joined %d records", m.Key, len(m.Records))
		}
	}
	if len(e.Machines) != 6 {
		t.Errorf("%d machines from six records", len(e.Machines))
	}
	if !strings.Contains(strings.Join(e.Notes, " "), "VMWARE42") {
		t.Errorf("a serial shared inside one tool is not reported: %v",
			e.Notes)
	}
}

func TestSerialsThatAreNotSerials(t *testing.T) {
	for _, s := range []string{"", "0", "N/A", "Default string",
		"System Serial Number", "1111111", "abc", "To be filled by O.E.M."} {
		if Serial(s) != "" {
			t.Errorf("%q was taken as a serial", s)
		}
	}
	if Serial(" fvfgpgv2-q6l5 ") != "FVFGPGV2Q6L5" {
		t.Error("a real serial was not normalised")
	}
}

// --- leaver with a device ---------------------------------------------------

func TestALeaverWhoseLaptopStillChecksInIsFound(t *testing.T) {
	_, o := evaluate(vantaSnap(
		[]Line{{"id": "v1", "email": "jane@acme.com", "name": "Jane Doe",
			"employment": "FORMER", "ended": ago(20)}},
		[]Line{{"id": "c1", "serial": "FVFGPGV2Q6L5", "name": "Jane's Mac",
			"owner_email": "jane@acme.com", "seen": ago(2), "os": "macOS"}}),
		ecSnap([]Line{{"id": "301", "serial": "FVFGPGV2Q6L5",
			"os": "macOS", "seen": ago(1)}}, nil))
	got := found(o, "leaver-device")
	if len(got) != 1 || got[0].Severity != telemetry.SeverityCritical {
		t.Fatalf("%v", got)
	}
	if !strings.Contains(got[0].Title, "Jane Doe") ||
		!strings.Contains(got[0].Title, "24 hours ago") {
		t.Errorf("title: %s", got[0].Title)
	}
	if !got[0].Tainted() {
		t.Error("evidence quoting names typed into a tool is not tainted")
	}
}

func TestALeaverWithoutALiveDeviceIsNotAFinding(t *testing.T) {
	for name, device := range map[string]Line{
		"quiet for two months": {"id": "c1", "serial": "SER12345",
			"owner_email": "jane@acme.com", "seen": ago(60)},
		"removed": {"id": "c1", "serial": "SER12345", "removed": "true",
			"owner_email": "jane@acme.com", "seen": ago(1)},
		"never seen": {"id": "c1", "serial": "SER12345",
			"owner_email": "jane@acme.com"},
	} {
		_, o := evaluate(vantaSnap([]Line{{"id": "v1",
			"email": "jane@acme.com", "employment": "FORMER"}},
			[]Line{device}), kb4Snap(nil, nil, nil))
		if n := len(found(o, "leaver-device")); n != 0 {
			t.Errorf("%s: %d findings", name, n)
		}
	}
	_, o := evaluate(vantaSnap([]Line{{"id": "v1", "email": "jane@acme.com",
		"employment": "CURRENT"}}, []Line{{"id": "c1", "serial": "SER12345",
		"owner_email": "jane@acme.com", "seen": ago(1)}}))
	if len(found(o, "leaver-device")) != 0 {
		t.Error("somebody current with a laptop was reported as a leaver")
	}
}

func TestAnArchivedDateMeansGoneWhateverTheStatusSays(t *testing.T) {
	_, o := evaluate(
		vantaSnap([]Line{{"id": "v1", "email": "jane@acme.com",
			"employment": "CURRENT"}}, nil),
		kb4Snap([]Line{{"id": "k1", "email": "jane@acme.com",
			"status": "active", "archived": ago(3)}}, nil, nil))
	if len(found(o, "leaver-still-active")) != 1 {
		t.Error("an archived KnowBe4 account beside a current Vanta record " +
			"was not raised")
	}
}

func TestALeaverStillActiveElsewhereIsFound(t *testing.T) {
	_, o := evaluate(
		vantaSnap([]Line{{"id": "v1", "email": "jane@acme.com",
			"employment": "FORMER"}}, nil),
		kb4Snap([]Line{{"id": "k1", "email": "jane@acme.com",
			"status": "active"}}, nil, nil))
	got := found(o, "leaver-still-active")
	if len(got) != 1 || got[0].Entity.Issuer != "knowbe4" {
		t.Fatalf("%v", got)
	}
	// Both saying gone is consistent, not a finding.
	_, o = evaluate(
		vantaSnap([]Line{{"id": "v1", "email": "jane@acme.com",
			"employment": "FORMER"}}, nil),
		kb4Snap([]Line{{"id": "k1", "email": "jane@acme.com",
			"status": "archived"}}, nil, nil))
	if len(found(o, "leaver-still-active")) != 0 {
		t.Error("two tools agreeing she left was reported")
	}
}

// --- training ---------------------------------------------------------------

func person(training string) []Line {
	return []Line{{"id": "v1", "email": "sam@acme.com", "name": "Sam",
		"employment": "CURRENT", "training": training}}
}

func TestTrainingThatOneToolCallsDoneAndAnotherDoesNot(t *testing.T) {
	kbUser := []Line{{"id": "k1", "email": "sam@acme.com", "status": "active"}}
	cases := []struct {
		name     string
		vanta    string
		kb       []Line
		want     int
		severity telemetry.Severity
	}{
		{"complete in Vanta, unfinished in KnowBe4", "COMPLETE",
			[]Line{{"id": "e1", "user": "k1", "module": "Phishing 101",
				"kind": "Training Module", "status": "Not Started"}},
			1, telemetry.SeverityMedium},
		{"overdue in Vanta, every course passed", "OVERDUE",
			[]Line{{"id": "e1", "user": "k1", "module": "Phishing 101",
				"kind": "Training Module", "status": "Passed"}},
			1, telemetry.SeverityLow},
		{"both done", "COMPLETE", []Line{{"id": "e1", "user": "k1",
			"kind": "Training Module", "status": "Passed"}}, 0, 0},
		{"only a policy unfinished", "COMPLETE", []Line{{"id": "e1",
			"user": "k1", "kind": "Uploaded Policy", "status": "Not Started"}},
			0, 0},
		{"overdue in both", "OVERDUE", []Line{{"id": "e1", "user": "k1",
			"kind": "Training Module", "status": "Past Due"}}, 0, 0},
	}
	for _, c := range cases {
		_, o := evaluate(vantaSnap(person(c.vanta), nil),
			kb4Snap(kbUser, c.kb, nil))
		got := found(o, "training-disagrees")
		if len(got) != c.want {
			t.Errorf("%s: %d findings", c.name, len(got))
			continue
		}
		if c.want == 1 && got[0].Severity != c.severity {
			t.Errorf("%s: %v", c.name, got[0].Severity)
		}
	}
}

func TestSomebodyMissingFromTheTrainingPlatformIsFound(t *testing.T) {
	people := []Line{
		{"id": "v1", "email": "sam@acme.com", "employment": "CURRENT",
			"training": "OVERDUE"},
		{"id": "v2", "email": "ann@acme.com", "employment": "CURRENT",
			"training": "COMPLETE"},
		{"id": "v3", "email": "old@acme.com", "employment": "FORMER",
			"training": "OVERDUE"},
	}
	kb := kb4Snap([]Line{{"id": "k2", "email": "ann@acme.com",
		"status": "active"}}, []Line{{"id": "e1", "user": "k2",
		"status": "Passed"}}, nil)
	_, o := evaluate(vantaSnap(people, nil), kb)
	got := found(o, "not-in-training")
	if len(got) != 1 || got[0].Entity.Value != "v1" {
		t.Fatalf("%v", got)
	}
	// If KnowBe4's users were not read to the end, absence proves nothing.
	kb.partial = []string{"users"}
	_, o = evaluate(vantaSnap(people, nil), kb)
	if len(found(o, "not-in-training")) != 0 {
		t.Error("absence from a list that was not read completely was " +
			"reported")
	}
}

// --- phishing ---------------------------------------------------------------

func TestAFailedPhishWithNoTrainingSinceIsFound(t *testing.T) {
	users := []Line{{"id": "k1", "email": "sam@acme.com", "name": "Sam",
		"status": "active"}}
	cases := []struct {
		name     string
		result   Line
		training []Line
		want     telemetry.Severity
	}{
		{"entered data", Line{"id": "r1", "user": "k1", "parent": "9",
			"clicked": ago(10), "data_entered": ago(10)}, nil,
			telemetry.SeverityHigh},
		{"clicked", Line{"id": "r1", "user": "k1", "clicked": ago(10)}, nil,
			telemetry.SeverityMedium},
		{"opened an attachment", Line{"id": "r1", "user": "k1",
			"attachment_opened": ago(5)}, nil, telemetry.SeverityMedium},
		{"trained afterwards", Line{"id": "r1", "user": "k1",
			"clicked": ago(10)}, []Line{{"id": "e1", "user": "k1",
			"status": "Passed", "completed": ago(3)}}, 0},
		{"trained only before", Line{"id": "r1", "user": "k1",
			"clicked": ago(10)}, []Line{{"id": "e1", "user": "k1",
			"status": "Passed", "completed": ago(30)}},
			telemetry.SeverityMedium},
		{"long ago", Line{"id": "r1", "user": "k1", "clicked": ago(200)},
			nil, 0},
		{"reported it", Line{"id": "r1", "user": "k1", "delivered": ago(10),
			"reported": ago(10)}, nil, 0},
	}
	for _, c := range cases {
		_, o := evaluate(kb4Snap(users, c.training, []Line{c.result}))
		got := found(o, "phished-untrained")
		switch {
		case c.want == 0 && len(got) != 0:
			t.Errorf("%s: raised %s", c.name, got[0].Title)
		case c.want != 0 && (len(got) != 1 || got[0].Severity != c.want):
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// --- devices ----------------------------------------------------------------

func windows(n int, seen string) []Line {
	var out []Line
	for i := 0; i < n; i++ {
		out = append(out, Line{"id": fmt.Sprint(300 + i),
			"serial": fmt.Sprintf("DELLTAG%03d", i),
			"os":     "Windows 11 Professional", "seen": seen})
	}
	return out
}

func TestADeviceTheEndpointManagerDoesNotKnowIsFound(t *testing.T) {
	vanta := append(windows(4, ago(1)), Line{"id": "stray",
		"serial": "UNMANAGED01", "os": "Windows 11", "seen": ago(2)})
	var vl []Line
	for _, l := range vanta {
		vl = append(vl, l)
	}
	_, o := evaluate(vantaSnap(nil, vl), ecSnap(windows(4, ago(1)), nil))
	got := found(o, "unmanaged-device")
	if len(got) != 1 || !strings.Contains(got[0].Title, "UNMANAGED01") ||
		got[0].Entity.Issuer != "endpointcentral" {
		t.Fatalf("%v", got)
	}
}

func TestADeviceNoToolIsExpectedToManageIsNotFound(t *testing.T) {
	mdm := snap{source: "mdmplus", kinds: map[string]Kind{"devices": KindDevice},
		lines: map[string][]Line{"devices": {
			{"id": "p1", "serial": "PHONE0001", "platform": "android", "seen": ago(1)},
			{"id": "p2", "serial": "PHONE0002", "platform": "ios", "seen": ago(1)},
			{"id": "p3", "serial": "PHONE0003", "platform": "android", "seen": ago(1)},
			{"id": "p4", "serial": "PHONE0004", "platform": "android", "seen": ago(1)},
			{"id": "m1", "serial": "ONEMAC001", "os": "macOS", "seen": ago(1)},
		}}}
	vanta := vantaSnap(nil, append(windows(4, ago(1)),
		Line{"id": "mac2", "serial": "OTHERMAC1", "os": "macOS", "seen": ago(1)},
		Line{"id": "mac3", "serial": "OTHERMAC2", "os": "macOS", "seen": ago(1)},
		Line{"id": "mac4", "serial": "OTHERMAC3", "os": "macOS", "seen": ago(1)}))
	_, o := evaluate(vanta, mdm)
	for _, f := range found(o, "unmanaged-device") {
		if strings.Contains(f.Title, "PHONE") {
			t.Errorf("a phone was reported missing from Vanta, which does " +
				"not manage phones")
		}
		if f.Entity.Issuer == "mdmplus" {
			t.Errorf("an MDM holding one Mac was taken to manage every "+
				"Mac: %s", f.Title)
		}
	}
	// And a machine nobody has seen for two months is not in use.
	_, o = evaluate(vantaSnap(nil, append(windows(4, ago(1)),
		Line{"id": "old", "serial": "OLDLAPTOP1", "os": "Windows", "seen": ago(60)})),
		ecSnap(windows(4, ago(1)), nil))
	if len(found(o, "unmanaged-device")) != 0 {
		t.Error("a machine unseen for two months was reported unmanaged")
	}
}

func TestEncryptionTwoToolsDisagreeOnIsFound(t *testing.T) {
	vanta := vantaSnap(nil, []Line{{"id": "c1", "serial": "SER12345",
		"os": "Windows", "encryption": "PASS", "seen": ago(1)}})
	cases := map[string]struct {
		drives []Line
		want   int
	}{
		"a fixed drive unencrypted": {[]Line{
			{"parent": "301", "drive": "C:", "status": "Encrypted",
				"drive_type": "Primary"},
			{"parent": "301", "drive": "D:", "status": "Not Encrypted",
				"drive_type": "Primary"}}, 1},
		"only a removable drive unencrypted": {[]Line{
			{"parent": "301", "drive": "C:", "status": "Encrypted",
				"drive_type": "Primary"},
			{"parent": "301", "drive": "E:", "status": "Not Encrypted",
				"drive_type": "Removable"}}, 0},
		"every drive encrypted": {[]Line{{"parent": "301", "drive": "C:",
			"status": "Encrypted"}}, 0},
		"a status nobody can read": {[]Line{{"parent": "301", "drive": "C:",
			"status": "Suspended"}}, 0},
	}
	for name, c := range cases {
		_, o := evaluate(vanta, ecSnap([]Line{{"id": "301",
			"serial": "ser-12345", "os": "Windows", "seen": ago(1)}}, c.drives))
		got := found(o, "encryption-disagrees")
		if len(got) != c.want {
			t.Errorf("%s: %d findings", name, len(got))
		}
		if c.want == 1 && got[0].Severity != telemetry.SeverityHigh {
			t.Errorf("%s: %v", name, got[0].Severity)
		}
	}
}

func TestADeviceTwoToolsGiveToTwoPeopleIsFound(t *testing.T) {
	_, o := evaluate(
		vantaSnap([]Line{
			{"id": "v1", "email": "ann@acme.com"},
			{"id": "v2", "email": "bob@acme.com"}},
			[]Line{{"id": "c1", "serial": "SER12345", "owner_email": "ann@acme.com"}}),
		snap{source: "mdmplus", kinds: map[string]Kind{"devices": KindDevice},
			lines: map[string][]Line{"devices": {{"id": "d1",
				"serial": "SER12345", "owner_email": "bob@acme.com"}}}})
	if len(found(o, "owner-disagrees")) != 1 {
		t.Error("two owners for one serial were not raised")
	}
	// Two addresses of one joined person are one owner.
	var built []Snapshot
	for _, s := range []snap{
		vantaSnap([]Line{{"id": "v1", "email": "ann@acme.com"}},
			[]Line{{"id": "c1", "serial": "SER12345", "owner_email": "ann@acme.com"}}),
		snap{source: "mdmplus", kinds: map[string]Kind{"devices": KindDevice,
			"users": KindPerson}, lines: map[string][]Line{
			"users":   {{"id": "u1", "email": "ann.smith@acme.com"}},
			"devices": {{"id": "d1", "serial": "SER12345", "owner_email": "ann.smith@acme.com"}}}},
	} {
		built = append(built, s.build())
	}
	e := Build(built, []workforce.Link{{A: telemetry.ID{Issuer: "vanta",
		Value: "v1"}, B: telemetry.ID{Issuer: "mdmplus", Value: "u1"},
		At: now, By: "ada", Because: "same person"}}, now)
	if len(found(Evaluate(e, now), "owner-disagrees")) != 0 {
		t.Error("one person's two addresses were reported as two owners")
	}
}

// --- what could not be looked at --------------------------------------------

func TestAChecksThatCannotRunSaysWhyInsteadOfReportingNothing(t *testing.T) {
	_, o := evaluate(kb4Snap([]Line{{"id": "k1", "email": "a@acme.com"}},
		nil, nil))
	for _, id := range []string{"leaver-device", "unmanaged-device",
		"training-disagrees", "encryption-disagrees"} {
		if o.Skipped[id] == "" {
			t.Errorf("%s ran, or was skipped silently, with only KnowBe4", id)
		}
	}
	// A device list that was cut short does not count as read.
	v := vantaSnap([]Line{{"id": "v1", "email": "a@acme.com",
		"employment": "FORMER"}}, []Line{{"id": "c1", "serial": "SER12345",
		"owner_email": "a@acme.com", "seen": ago(1)}})
	v.partial = []string{"computers"}
	_, o = evaluate(v)
	if o.Skipped["leaver-device"] == "" {
		t.Error("the leaver check ran on a device list read only in part")
	}
}

func TestWhatCannotBePlacedIsCounted(t *testing.T) {
	e, _ := evaluate(kb4Snap([]Line{{"id": "k1", "email": "a@acme.com"}},
		[]Line{{"id": "e1", "user": "k404", "email": "ghost@acme.com",
			"status": "Passed"}}, nil))
	if e.Unplaced.Training != 1 {
		t.Errorf("an enrolment belonging to nobody was dropped silently: %+v",
			e.Unplaced)
	}
}

func TestTheSameFindingIsNotRaisedTwiceInOneRound(t *testing.T) {
	_, o := evaluate(vantaSnap(
		[]Line{{"id": "v1", "email": "jane@acme.com", "employment": "FORMER"}},
		[]Line{{"id": "c1", "serial": "SER12345", "owner_email": "jane@acme.com",
			"seen": ago(1)}}), ecSnap(nil, nil))
	ids := map[string]bool{}
	for _, f := range o.Findings {
		if ids[f.ID] {
			t.Errorf("%s twice", f.ID)
		}
		ids[f.ID] = true
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", f.ID, err)
		}
	}
}
