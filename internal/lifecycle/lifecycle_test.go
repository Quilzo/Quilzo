// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package lifecycle

import (
	"strings"
	"testing"
	"time"
)

var today = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// Real versions against the embedded dates, as of the day they were taken.
func TestAVersionIsPlacedOnItsLineAndJudged(t *testing.T) {
	for _, c := range []struct {
		os, version string
		cycle       string
		want        Currency
		latest      string
	}{
		{"macOS", "13.6.1", "13", Unsupported, ""},
		{"macOS", "14.8.9", "14", Unsupported, ""},
		{"Mac OS X", "15.6", "15", UpdateAvailable, "15.8.1"},
		{"macOS", "26.7.1", "26", Current, ""},
		{"iOS", "17.5", "17", Unsupported, ""},
		{"iPadOS", "18.7.10", "18", Current, ""},
		{"Android", "14", "14", Current, ""},
		{"Windows 10 Pro", "10.0.19045.4529", "10-22h2", Unsupported, ""},
		{"Windows 11 Pro", "10.0.22631.4317", "11-23h2-w", Unsupported, ""},
		{"Windows 11 Enterprise", "10.0.22631.3880", "11-23h2-e", EndingSoon, ""},
		{"Windows 11 Pro", "10.0.26100.2033", "11-24h2-w", EndingSoon, ""},
		{"Windows 11 Pro", "10.0.26200.100", "11-25h2-w", Current, ""},
	} {
		a := Assess(c.os, c.version, today)
		if a.Cycle.Cycle != c.cycle || a.Currency != c.want || a.Latest != c.latest {
			t.Errorf("%s %s: line %q %s latest %q; want %q %s %q", c.os, c.version,
				a.Cycle.Cycle, a.Currency, a.Latest, c.cycle, c.want, c.latest)
		}
	}
}

// Nothing is claimed about what is not in the data.
func TestAnUnknownSystemIsUnknownNotCurrent(t *testing.T) {
	for _, c := range [][2]string{{"Ubuntu", "22.04"}, {"macOS", ""}, {"", ""}, {"Windows 11", "eleven"}, {"ChromeOS", "128"}} {
		if a := Assess(c[0], c[1], today); a.Currency != Unknown {
			t.Errorf("%v was judged %s", c, a.Currency)
		}
	}
}

// The age of what a device runs is worked out from the line's release,
// with every later line counted, so "how far behind" needs no tool to say.
func TestAgeAndHowFarBehindAreWorkedOut(t *testing.T) {
	a := Assess("macOS", "13.6.1", today)
	if Words(a.Age) != "3 years 11 months" {
		t.Errorf("macOS 13 is %s old", Words(a.Age))
	}
	if a.Newer != 4 {
		t.Errorf("macOS 13 has %d newer lines, want 4 (14, 15, 26, 27)", a.Newer)
	}
	w := Assess("Windows 10 Pro", "10.0.19045.4529", today)
	if w.Newer == 0 {
		t.Error("Windows 10 is behind nothing")
	}
	if Words(36*time.Hour) != "1 day" || Words(400*24*time.Hour) != "1 year 1 month" {
		t.Error("ages are not said the way people say them")
	}
}

func TestVersionsCompareByNumberNotByText(t *testing.T) {
	if !older("15.6", "15.10") || older("15.10", "15.6") || older("15.6", "15.6") || !older("15", "15.0.1") {
		t.Error("15.10 is after 15.6")
	}
}

// A year's last days are not its twelfth month.
func TestAnAgeNeverSaysTwelveMonths(t *testing.T) {
	for days, want := range map[int]string{29: "29 days", 31: "1 month", 364: "11 months",
		365: "1 year", 1824: "4 years 11 months", 1826: "5 years", 1100: "3 years"} {
		if got := Words(time.Duration(days) * 24 * time.Hour); got != want {
			t.Errorf("%d days is %q, want %q", days, got, want)
		}
	}
	for days := 0; days < 20*365; days++ {
		if got := Words(time.Duration(days) * 24 * time.Hour); strings.Contains(got, "12 month") {
			t.Fatalf("%d days is %q", days, got)
		}
	}
}
