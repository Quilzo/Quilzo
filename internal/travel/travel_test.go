// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package travel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/geo"
)

var (
	t0     = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	london = geo.Place{City: "London", Country: "GB", Lat: 51.5074, Lon: -0.1278}
	paris  = geo.Place{City: "Paris", Country: "FR", Lat: 48.8566, Lon: 2.3522}
	sydney = geo.Place{City: "Sydney", Country: "AU", Lat: -33.8688, Lon: 151.2093}
	nyc    = geo.Place{City: "New York", Country: "US", Lat: 40.7128, Lon: -74.006}
	vpn    = geo.Place{Network: "Corporate VPN", Kind: "vpn", City: "Frankfurt", Country: "DE", Lat: 50.11, Lon: 8.68}
)

func kinds(s []Signal) string {
	var k []string
	for _, x := range s {
		k = append(k, x.Kind)
	}
	return strings.Join(k, ",")
}

// London, then Sydney twenty minutes later: nobody flies that.
func TestLondonThenSydneyInTwentyMinutesIsImpossible(t *testing.T) {
	s := Assess([]SignIn{{At: t0, Place: london}}, SignIn{At: t0.Add(20 * time.Minute), Place: sydney})
	if kinds(s) != "impossible-travel" {
		t.Fatalf("signals %s", kinds(s))
	}
	if s[0].Km < 16900 || s[0].KmH < 50000 || s[0].Minutes != 20 {
		t.Errorf("measured %+v", s[0])
	}
	if !strings.Contains(s[0].Detail, "Sydney, AU") || !strings.Contains(s[0].Detail, "faster than a plane") {
		t.Errorf("detail: %s", s[0].Detail)
	}
}

// True positives and true negatives at the thresholds.
func TestTheThresholdsHoldBothWays(t *testing.T) {
	for _, c := range []struct {
		name     string
		from, to geo.Place
		after    time.Duration
		want     bool
	}{
		{"London to New York in 8 hours is a flight", london, nyc, 8 * time.Hour, false},
		{"London to New York in 3 hours is not", london, nyc, 3 * time.Hour, true},
		{"London to Paris in 20 minutes is under the distance floor", london, paris, 20 * time.Minute, false},
		{"through the VPN is not a place", london, vpn, 5 * time.Minute, false},
		{"from the VPN is not a place either", vpn, sydney, 5 * time.Minute, false},
		{"no coordinates, no claim", london, geo.Place{Country: "AU"}, 5 * time.Minute, false},
	} {
		s := Assess([]SignIn{{At: t0, Place: c.from}}, SignIn{At: t0.Add(c.after), Place: c.to})
		if got := strings.Contains(kinds(s), "impossible-travel"); got != c.want {
			t.Errorf("%s: %v (%s)", c.name, got, kinds(s))
		}
	}
}

// A country or device is new only against a history long enough to say so.
func TestNewCountryAndDeviceNeedAHistory(t *testing.T) {
	var history []SignIn
	for i := 0; i < Learning; i++ {
		history = append([]SignIn{{At: t0.Add(time.Duration(i) * 24 * time.Hour), Place: london, Device: "aa"}}, history...)
	}
	later := t0.Add(30 * 24 * time.Hour)
	if got := kinds(Assess(history[:Learning-1], SignIn{At: later, Place: paris, Device: "bb"})); got != "" {
		t.Errorf("judged against too little history: %s", got)
	}
	got := kinds(Assess(history, SignIn{At: later, Place: paris, Device: "bb"}))
	if got != "new-country,new-device" {
		t.Errorf("signals %s", got)
	}
	if got := kinds(Assess(history, SignIn{At: later, Place: london, Device: "aa"})); got != "" {
		t.Errorf("a usual sign-in raised %s", got)
	}
}

// The store judges each sign-in against the person's own history, by name
// without case, and keeps a bounded list.
func TestTheStoreJudgesEachPersonAgainstTheirOwnHistory(t *testing.T) {
	st := &Store{Dir: filepath.Join(t.TempDir(), "signins"), Now: func() time.Time { return t0.Add(90 * time.Hour) }}
	if s, err := st.Record("Ada@Example.com", SignIn{At: t0, Place: london}); err != nil || len(s) != 0 {
		t.Fatalf("first sign-in: %v %v", s, err)
	}
	if s, _ := st.Record("bo@example.com", SignIn{At: t0.Add(time.Minute), Place: sydney}); len(s) != 0 {
		t.Errorf("one person's sign-in was judged against another's: %s", kinds(s))
	}
	if s, _ := st.Record("ada@example.com", SignIn{At: t0.Add(10 * time.Minute), Place: sydney}); kinds(s) != "impossible-travel" {
		t.Errorf("ada's second sign-in: %s", kinds(s))
	}
	for i := 0; i < KeepPerPerson+10; i++ {
		_, _ = st.Record("cy@example.com", SignIn{At: t0.Add(time.Duration(i) * time.Hour), Place: london})
	}
	recent, _ := st.Since(time.Time{})
	n := 0
	for _, r := range recent {
		if r.Person == "cy@example.com" {
			n++
		}
	}
	if n != KeepPerPerson {
		t.Errorf("kept %d sign-ins for one person, want %d", n, KeepPerPerson)
	}
}

// Where somebody signed in from is kept for Keep and no longer: past it a
// sign-in is not judged against, not listed, and its file goes.
func TestSignInsAreForgottenAfterTheyAreKept(t *testing.T) {
	now := t0
	st := &Store{Dir: filepath.Join(t.TempDir(), "signins"), Now: func() time.Time { return now }}
	st.Record("ada@example.com", SignIn{At: t0, Place: london})
	now = t0.Add(Keep + time.Hour)
	if s, _ := st.Record("ada@example.com", SignIn{At: now, Place: sydney}); len(s) != 0 {
		t.Errorf("judged against a sign-in past keeping: %s", kinds(s))
	}
	st.Record("old@example.com", SignIn{At: t0, Place: paris})
	now = t0.Add(2*Keep + time.Hour)
	recent, _ := st.Since(time.Time{})
	if len(recent) != 0 {
		t.Errorf("%d sign-ins past keeping were listed", len(recent))
	}
	entries, _ := os.ReadDir(st.Dir)
	if len(entries) != 0 {
		t.Errorf("%d files of forgotten sign-ins remain", len(entries))
	}
}

// The directory does not say who signs in, and a damaged file is replaced
// rather than stopping sign-ins.
func TestTheStoreNamesNobodyAndSurvivesADamagedFile(t *testing.T) {
	st := &Store{Dir: filepath.Join(t.TempDir(), "signins"), Now: func() time.Time { return t0 }}
	st.Record("ada@example.com", SignIn{At: t0, Place: london})
	entries, _ := os.ReadDir(st.Dir)
	if len(entries) != 1 || strings.Contains(entries[0].Name(), "ada") {
		t.Fatalf("files %v", entries)
	}
	if err := os.WriteFile(filepath.Join(st.Dir, entries[0].Name()), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Record("ada@example.com", SignIn{At: t0.Add(time.Minute), Place: london}); err == nil {
		t.Error("a damaged history was not reported")
	}
	if s, err := st.Record("ada@example.com", SignIn{At: t0.Add(5 * time.Minute), Place: sydney}); err != nil || kinds(s) != "impossible-travel" {
		t.Errorf("after replacing it: %s %v", kinds(s), err)
	}
}

func history(n int, at time.Time, in SignIn) []SignIn {
	var out []SignIn
	for i := 0; i < n; i++ {
		x := in
		x.At = at.Add(-time.Duration(i) * 24 * time.Hour)
		out = append(out, x)
	}
	return out
}

// Each of the newer signals, both ways.
func TestTheOtherSignalsFireWhenTheyShouldAndNotOtherwise(t *testing.T) {
	usual := SignIn{IP: "198.51.100.7", ASN: 2856, Network: "BT", Place: london, Device: "Chrome on Windows"}
	before := history(10, t0, usual)
	at := t0.Add(2 * time.Hour)
	with := func(f func(*SignIn)) string {
		in := usual
		in.At = at
		f(&in)
		return kinds(Assess(before, in))
	}
	for _, c := range []struct {
		name string
		f    func(*SignIn)
		want string
	}{
		{"a usual sign-in", func(*SignIn) {}, ""},
		{"through Tor", func(in *SignIn) { in.Anon = "tor" }, "anonymous-network"},
		{"from a hosting provider", func(in *SignIn) { in.Anon = "hosting"; in.Network = "DigitalOcean" }, "hosting-network"},
		{"a hosting provider the company declared its VPN", func(in *SignIn) { in.Anon = "hosting"; in.Place.Kind = "vpn" }, ""},
		{"a new network", func(in *SignIn) { in.ASN = 14061; in.IP = "198.51.100.7" }, "new-network"},
		{"a new address on the usual network", func(in *SignIn) { in.IP = "198.51.100.99" }, "new-ip"},
		{"a new address at a declared office", func(in *SignIn) { in.IP = "198.51.100.99"; in.Place.Kind = "office" }, ""},
		{"a new kind of device", func(in *SignIn) { in.Device = "Firefox on Linux" }, "new-device"},
	} {
		if got := with(c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// Dormant: the first sign-in in more than sixty days.
	in := usual
	in.At = t0.Add(DormantGap + 48*time.Hour)
	if got := kinds(Assess(before, in)); got != "dormant" {
		t.Errorf("after sixty days away: %q", got)
	}
	// An unusual hour needs twenty sign-ins, all at about nine.
	nine := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	long := history(HourHistory, nine, usual)
	late := usual
	late.At = time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	if got := kinds(Assess(long, late)); got != "unusual-hour" {
		t.Errorf("three in the morning for a nine o'clock person: %q", got)
	}
	late.At = time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	if got := kinds(Assess(long, late)); got != "" {
		t.Errorf("ten o'clock: %q", got)
	}
}

// Several unfamiliar properties at once are worse than any one of them.
func TestThreeSignalsTogetherRaiseTheLevel(t *testing.T) {
	low := []Signal{{Kind: "new-ip"}}
	if Level(low) != "low" || Level(nil) != "none" {
		t.Errorf("levels %s %s", Level(low), Level(nil))
	}
	if got := Level([]Signal{{Kind: "new-ip"}, {Kind: "new-device"}, {Kind: "unusual-hour"}}); got != "medium" {
		t.Errorf("three low signals: %s", got)
	}
	if got := Level([]Signal{{Kind: "impossible-travel"}, {Kind: "new-ip"}, {Kind: "new-device"}}); got != "high" {
		t.Errorf("high stays high: %s", got)
	}
}

func TestDevicesAreKindsNotVersions(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36":                         "Chrome on Windows",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36":                         "Chrome on Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15":                      "Safari on macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": "Safari on iPhone",
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0 Safari/537.36 Edg/146.0":                   "Edge on Windows",
		"curl/8.5.0": "a script on another system",
		"":           "",
	} {
		if got := DeviceClass(ua); got != want {
			t.Errorf("%q: %q, want %q", ua, got, want)
		}
	}
}

// The score is higher for a sign-in less like the person, and zero with
// nothing to compare.
func TestTheScoreRisesWithHowUnlikeThePersonASignInIs(t *testing.T) {
	usual := SignIn{IP: "198.51.100.7", ASN: 2856, Place: london, Device: "Chrome on Windows"}
	before := history(20, t0, usual)
	g := Stats{Counts: map[string]map[string]int{}, People: 30}
	for i := 0; i < 600; i++ {
		other := SignIn{IP: fmt.Sprintf("203.0.113.%d", i%200), ASN: uint32(64500 + i%7), Place: paris, Device: "Safari on macOS"}
		g.add(other)
	}
	for _, in := range before {
		g.add(in)
	}
	familiar := Score(before, SignIn{IP: "198.51.100.7", ASN: 2856, Place: london, Device: "Chrome on Windows"}, g)
	partly := Score(before, SignIn{IP: "198.51.100.8", ASN: 2856, Place: london, Device: "Chrome on Windows"}, g)
	stranger := Score(before, SignIn{IP: "192.0.2.50", ASN: 14061, Place: sydney, Device: "a script on another system"}, g)
	if !(familiar < partly && partly < stranger) {
		t.Errorf("scores familiar %.1f, partly %.1f, stranger %.1f", familiar, partly, stranger)
	}
	if Score(nil, usual, g) != 0 {
		t.Error("a first sign-in was scored")
	}
}
