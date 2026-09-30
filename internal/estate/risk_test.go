// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"strings"
	"testing"
)

func scoreOf(t *testing.T, scores []Score, email string) Score {
	t.Helper()
	for _, s := range scores {
		if s.Email == email {
			return s
		}
	}
	t.Fatalf("%s was not scored", email)
	return Score{}
}

func fullEstate() []snap {
	return []snap{
		vantaSnap([]Line{
			{"id": "v1", "email": "sam@acme.com", "name": "Sam",
				"employment": "CURRENT", "training": "OVERDUE",
				"policies": "OVERDUE"},
			{"id": "v2", "email": "ann@acme.com", "name": "Ann",
				"employment": "CURRENT", "training": "COMPLETE",
				"policies": "COMPLETE"},
			{"id": "v3", "email": "old@acme.com", "name": "Old",
				"employment": "FORMER"},
			{"id": "v4", "email": "gone@acme.com", "name": "Gone",
				"employment": "FORMER"},
		}, []Line{
			{"id": "c1", "serial": "SAMLAPTOP1", "os": "Windows 11",
				"owner_email": "sam@acme.com", "seen": ago(1),
				"encryption": "FAIL", "screenlock": "PASS"},
			{"id": "c2", "serial": "ANNLAPTOP1", "os": "Windows 11",
				"owner_email": "ann@acme.com", "seen": ago(1),
				"encryption": "PASS", "screenlock": "PASS"},
			{"id": "c3", "serial": "OLDLAPTOP1", "os": "Windows 11",
				"owner_email": "old@acme.com", "seen": ago(2)},
		}),
		kb4Snap([]Line{
			{"id": "k1", "email": "sam@acme.com", "status": "active",
				"phish_prone": "30", "risk_score": "61.2"},
			{"id": "k2", "email": "ann@acme.com", "status": "active"},
		}, []Line{
			{"id": "e1", "user": "k2", "status": "Passed",
				"completed": ago(40)},
		}, []Line{
			{"id": "r1", "user": "k1", "clicked": ago(5),
				"data_entered": ago(5)},
			{"id": "r2", "user": "k2", "delivered": ago(5),
				"reported": ago(5)},
		}),
	}
}

func TestAScoreIsTheSumOfReasonsSomebodyCanCheck(t *testing.T) {
	e, _ := evaluate(fullEstate()...)
	scores := e.Scores(now)
	sam := scoreOf(t, scores, "sam@acme.com")
	want := Weights.DataEntered + 6 + Weights.TrainingOverdue +
		Weights.PoliciesOverdue + Weights.Unencrypted
	if sam.Points != want {
		t.Errorf("Sam scores %d, want %d: %+v", sam.Points, want, sam.Factors)
	}
	if sam.Band != BandCritical && sam.Band != BandHigh {
		t.Errorf("Sam is %s", sam.Band)
	}
	sum := 0
	for _, f := range sam.Factors {
		sum += f.Points
		if f.Source == "" || f.What == "" {
			t.Errorf("a factor with no source or reason: %+v", f)
		}
	}
	if clamp(sum) != sam.Points {
		t.Errorf("the reasons add to %d and the score is %d", sum, sam.Points)
	}
	if sam.Factors[0].Area != AreaPhishing {
		t.Errorf("the largest reason is not first: %+v", sam.Factors[0])
	}
	// KnowBe4's own number is shown, never blended in.
	if sam.Vendor["knowbe4"] != 61.2 {
		t.Errorf("vendor score: %v", sam.Vendor)
	}
}

func TestSomebodyWithNothingWrongScoresNothing(t *testing.T) {
	e, _ := evaluate(fullEstate()...)
	ann := scoreOf(t, e.Scores(now), "ann@acme.com")
	// Reporting a phish lowers a score, and a score does not go below zero.
	if ann.Points != 0 || ann.Band != BandLow {
		t.Errorf("Ann scores %d: %+v", ann.Points, ann.Factors)
	}
	// No tool in this estate reports patches, and that is the only thing
	// unknown about her.
	if len(ann.Unknown) != 1 || ann.Unknown[AreaPatching] == "" {
		t.Errorf("unknowns: %v", ann.Unknown)
	}
}

func TestALeaverIsScoredOnlyWhileTheirDeviceIsLive(t *testing.T) {
	e, _ := evaluate(fullEstate()...)
	scores := e.Scores(now)
	old := scoreOf(t, scores, "old@acme.com")
	if !old.Leaver || old.Points < Weights.LeaverWithDevice ||
		old.Band == BandLow || old.Band == BandModerate {
		t.Errorf("a leaver with a live laptop: %+v", old)
	}
	for _, s := range scores {
		if s.Email == "gone@acme.com" {
			t.Error("a leaver with nothing live was scored")
		}
	}
}

func TestWhatNoToolReportedIsUnknownNotSafe(t *testing.T) {
	e, _ := evaluate(vantaSnap([]Line{{"id": "v1", "email": "a@acme.com",
		"employment": "CURRENT"}}, nil))
	s := scoreOf(t, e.Scores(now), "a@acme.com")
	for _, a := range []Area{AreaPhishing, AreaPatching} {
		if s.Unknown[a] == "" {
			t.Errorf("%s is not reported as unknown: %v", a, s.Unknown)
		}
	}
	if s.Points != Weights.NoDevice {
		// Vanta was read for devices and holds none of theirs.
		t.Errorf("a person with no visible device scores %d: %+v",
			s.Points, s.Factors)
	}
}

func TestTheWorstMachineIsTheOneThatCounts(t *testing.T) {
	e, _ := evaluate(vantaSnap([]Line{{"id": "v1", "email": "a@acme.com",
		"employment": "CURRENT"}}, []Line{
		{"id": "c1", "serial": "GOODLAPTOP", "owner_email": "a@acme.com",
			"seen": ago(1), "encryption": "PASS"},
		{"id": "c2", "serial": "BADLAPTOP1", "owner_email": "a@acme.com",
			"seen": ago(1), "encryption": "FAIL", "antivirus": "FAIL"},
		{"id": "c3", "serial": "OLDLAPTOP9", "owner_email": "a@acme.com",
			"seen": ago(90), "encryption": "FAIL", "screenlock": "FAIL",
			"antivirus": "FAIL"},
	}))
	s := scoreOf(t, e.Scores(now), "a@acme.com")
	if s.Points != Weights.Unencrypted+Weights.NoAntivirus {
		t.Errorf("scored %d from %+v", s.Points, s.Factors)
	}
	for _, f := range s.Factors {
		if strings.Contains(f.What, "OLDLAPTOP9") {
			t.Error("a machine unseen for three months was scored")
		}
	}
}

func TestADayIsKeptAsAggregatesOnly(t *testing.T) {
	e, _ := evaluate(fullEstate()...)
	sum := Summarise(e.Scores(now), now)
	if sum.Scored != 3 || sum.Date != "2026-09-30" || sum.Leavers != 1 {
		t.Errorf("%+v", sum)
	}
	if sum.Areas[AreaPhishing] != 1 || sum.Areas[AreaDevice] != 1 {
		t.Errorf("areas: %v", sum.Areas)
	}
	n := 0
	for _, c := range sum.Bands {
		n += c
	}
	if n != sum.Scored {
		t.Errorf("bands hold %d of %d", n, sum.Scored)
	}
}

func TestAnOrdinaryPhishProneRateIsNotAReason(t *testing.T) {
	for _, c := range []struct {
		rate string
		want int
	}{{"7.4", 0}, {"19.9", 0}, {"20", 4}, {"37.7", 8}, {"95", 10}} {
		e, _ := evaluate(kb4Snap([]Line{{"id": "k1", "email": "a@acme.com",
			"status": "active", "phish_prone": c.rate}}, nil,
			[]Line{{"id": "r1", "user": "k1", "delivered": ago(3)}}))
		s := scoreOf(t, e.Scores(now), "a@acme.com")
		got := 0
		for _, f := range s.Factors {
			if f.Area == AreaPhishing {
				got += f.Points
			}
		}
		if got != c.want {
			t.Errorf("%s%% phish-prone scores %d, want %d", c.rate, got, c.want)
		}
	}
}
