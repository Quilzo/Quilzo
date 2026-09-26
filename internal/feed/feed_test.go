// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package feed

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

func mirrored(t *testing.T, f Feed) *Mirror {
	t.Helper()
	s := &Set{}
	m, err := s.Add(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func daily() Feed {
	return Feed{Name: "epss", Kind: Scores, From: "https://example.invalid",
		Publishes: 24 * time.Hour, Fetch: 24 * time.Hour}
}

func unscheduled() Feed {
	return Feed{Name: "kev", Kind: Exploited,
		From: "https://example.invalid", Fetch: 12 * time.Hour}
}

func release(f string, at time.Time, entries int) Release {
	return Release{Feed: f, Version: at.Format("2006-01-02"), Fetched: at,
		Published: at, Digest: Digest([]string{"a", "b"}), Entries: entries}
}

// TestNeverFetchedIsTheWorstThing, because an empty database reports
// nothing wrong.
func TestNeverFetchedIsTheWorstThing(t *testing.T) {
	m := mirrored(t, daily())
	stale, why := m.Stale(t0)
	if !stale {
		t.Fatal("a mirror that has never been fetched is not stale?")
	}
	if !strings.Contains(why, "empty database") {
		t.Fatalf("why = %q", why)
	}
	tr := m.Look(t0)
	if len(tr) != 1 || tr[0].Weight != Never {
		t.Fatalf("trouble = %+v", tr)
	}
	if !strings.Contains(tr[0].Detail, "the order the queue is worked in") {
		t.Fatalf("the detail does not say what this decides: %q",
			tr[0].Detail)
	}
	a := m.Attest(t0)
	if !strings.Contains(a.Says(), "never been fetched") {
		t.Fatalf("says = %q", a.Says())
	}
}

// TestOurSilenceAndTheirSilenceAreDifferentFacts.
func TestOurSilenceAndTheirSilenceAreDifferentFacts(t *testing.T) {
	// A daily feed we have not fetched for three days: ours.
	ours := mirrored(t, daily())
	if err := ours.Take(release("epss", t0, 250_000)); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(3 * 24 * time.Hour)
	stale, why := ours.Stale(now)
	if !stale {
		t.Fatal("three days behind a daily feed is not stale?")
	}
	if !strings.Contains(why, "this program's, not the source's") {
		t.Fatalf("why = %q", why)
	}
	missed, known := ours.Missing(now)
	if !known || missed != 3 {
		t.Fatalf("missed %d, known %v", missed, known)
	}

	// An unscheduled feed we fetched an hour ago: nothing is wrong, and
	// the quiet is not evidence of anything.
	theirs := mirrored(t, unscheduled())
	if err := theirs.Take(release("kev", t0, 1_665)); err != nil {
		t.Fatal(err)
	}
	if stale, _ := theirs.Stale(t0.Add(time.Hour)); stale {
		t.Fatal("an hour into a twelve-hour cadence is stale?")
	}
	if _, known := theirs.Missing(t0.Add(30 * 24 * time.Hour)); known {
		t.Fatal("a feed with no schedule produced a count of missed " +
			"publications, which would be a number somebody invented")
	}
	// And when it is overdue, it says how much is missing cannot be said.
	a := theirs.Attest(t0.Add(48 * time.Hour))
	if !a.Stale {
		t.Fatal("two days into a twelve-hour cadence is not stale?")
	}
	if !strings.Contains(a.Says(), "how much is missing cannot be said") {
		t.Fatalf("says = %q", a.Says())
	}
}

// TestAnEmptyFetchLooksExactlyLikeACleanResult.
func TestAnEmptyFetchLooksExactlyLikeACleanResult(t *testing.T) {
	m := mirrored(t, daily())
	if err := m.Take(release("epss", t0, 0)); err != nil {
		t.Fatal(err)
	}
	c, _ := m.Current()
	if !c.Empty() {
		t.Fatal("zero entries is not empty?")
	}
	tr := m.Look(t0)
	if len(tr) == 0 || tr[0].Weight != Empty {
		t.Fatalf("trouble = %+v", tr)
	}
	if !strings.Contains(tr[0].Detail, "moved address") {
		t.Fatalf("detail = %q", tr[0].Detail)
	}
}

// TestFailingFetchesAreDistinctFromNotTrying.
func TestFailingFetchesAreDistinctFromNotTrying(t *testing.T) {
	m := mirrored(t, daily())
	if err := m.Take(release("epss", t0, 100)); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		m.Missed(t0.Add(time.Duration(i+1)*24*time.Hour),
			errors.New("connection refused"))
	}
	now := t0.Add(4 * 24 * time.Hour)
	_, why := m.Stale(now)
	if !strings.Contains(why, "3 fetch(es) have failed") {
		t.Fatalf("why = %q", why)
	}
	var failing *Trouble
	for _, tr := range m.Look(now) {
		if tr.Weight == Failing {
			t := tr
			failing = &t
		}
	}
	if failing == nil {
		t.Fatal("failing fetches were not reported")
	}
	if !strings.Contains(failing.Detail, "connection refused") {
		t.Fatalf("detail = %q", failing.Detail)
	}
}

// TestAnUnverifiedReleaseIsAcceptedAndMarked.
func TestAnUnverifiedReleaseIsAcceptedAndMarked(t *testing.T) {
	f := Feed{Name: "sigma", Kind: Rules, From: "https://example.invalid",
		Fetch: 7 * 24 * time.Hour, Signs: true}
	m := mirrored(t, f)
	r := release("sigma", t0, 3760)
	r.Why = "the signing key rotated and the new one is not pinned yet"
	if err := m.Take(r); err != nil {
		t.Fatal(err)
	}
	var found *Trouble
	for _, tr := range m.Look(t0) {
		if tr.Weight == Unsigned {
			t := tr
			found = &t
		}
	}
	if found == nil {
		t.Fatal("an unverified release from a signing source was not " +
			"reported")
	}
	if !strings.Contains(found.Detail, "worse failure") {
		t.Fatalf("the detail does not explain why it was accepted: %q",
			found.Detail)
	}
	if !strings.Contains(m.Attest(t0).Says(), "was not verified") {
		t.Fatalf("says = %q", m.Attest(t0).Says())
	}
	// A verified one says nothing.
	r2 := release("sigma", t0.Add(time.Hour), 3761)
	r2.Verified = true
	if err := m.Take(r2); err != nil {
		t.Fatal(err)
	}
	for _, tr := range m.Look(t0.Add(time.Hour)) {
		if tr.Weight == Unsigned {
			t.Fatal("a verified release was still reported")
		}
	}
}

// TestASourceThatHasStoppedPublishingIsTheirProblemAndStillOurs.
func TestASourceThatHasStoppedPublishingIsTheirProblemAndStillOurs(t *testing.T) {
	m := mirrored(t, daily())
	// Fetched just now, but what we fetched is a week old at the source.
	r := release("epss", t0, 250_000)
	r.Published = t0.Add(-7 * 24 * time.Hour)
	if err := m.Take(r); err != nil {
		t.Fatal(err)
	}
	if stale, _ := m.Stale(t0); stale {
		t.Fatal("a mirror fetched an hour ago is not overdue")
	}
	lag, ok := m.Lag()
	if !ok || lag != 7*24*time.Hour {
		t.Fatalf("lag = %s", lag)
	}
	var frozen *Trouble
	for _, tr := range m.Look(t0) {
		if tr.Weight == Frozen {
			t := tr
			frozen = &t
		}
	}
	if frozen == nil {
		t.Fatal("a source that has published nothing for a week was not " +
			"reported")
	}
	if !strings.Contains(frozen.Detail, "about them rather than about") {
		t.Fatalf("detail = %q", frozen.Detail)
	}
	if !strings.Contains(frozen.Detail, "still what the scanner is") {
		t.Fatalf("the detail lets us off the hook: %q", frozen.Detail)
	}
}

// TestAResultCarriesTheDatabaseItWasCheckedAgainst.
func TestAResultCarriesTheDatabaseItWasCheckedAgainst(t *testing.T) {
	s := &Set{}
	for _, f := range []Feed{daily(), unscheduled()} {
		m, err := s.Add(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Take(release(f.Name, t0, 100)); err != nil {
			t.Fatal(err)
		}
	}
	ok, _ := s.Trustworthy(t0.Add(time.Hour))
	if !ok {
		t.Fatal("a freshly fetched set is not trustworthy?")
	}

	now := t0.Add(4 * 24 * time.Hour)
	ok, why := s.Trustworthy(now)
	if ok {
		t.Fatal("a four-day-old set is trustworthy?")
	}
	if !strings.Contains(why, "statement about this database rather than") {
		t.Fatalf("why = %q", why)
	}
	if !strings.Contains(why, "epss") || !strings.Contains(why, "kev") {
		t.Fatalf("the reason does not name the feeds: %q", why)
	}

	att := s.Attest(now)
	if len(att) != 2 {
		t.Fatalf("%d attestation(s)", len(att))
	}
	for _, a := range att {
		if !a.Stale {
			t.Fatalf("%s is not stale at four days", a.Feed)
		}
		if a.Feed == "epss" && a.Missed != 4 {
			t.Fatalf("epss missed %d", a.Missed)
		}
		if a.Feed == "kev" && a.Missed != 0 {
			t.Fatal("an unscheduled feed reported missed publications")
		}
	}
	due := s.Due(now)
	if len(due) != 2 {
		t.Fatalf("%d due", len(due))
	}
}

// TestConfigurationsThatCannotWorkAreRefused.
func TestConfigurationsThatCannotWorkAreRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		f    Feed
		says string
	}{
		{"no name", Feed{Kind: Scores, From: "x", Fetch: time.Hour},
			"needs a name"},
		{"no kind", Feed{Name: "a", From: "x", Fetch: time.Hour},
			"kind of feed"},
		{"nowhere", Feed{Name: "a", Kind: Scores, Fetch: time.Hour},
			"where it comes from"},
		{"no cadence", Feed{Name: "a", Kind: Scores, From: "x"},
			"how often it is fetched"},
		{"fetched too rarely", Feed{Name: "a", Kind: Scores, From: "x",
			Fetch: 30 * 24 * time.Hour}, "the answer to whether it is " +
			"current is no"},
		{"behind by design", Feed{Name: "a", Kind: Scores, From: "x",
			Publishes: time.Hour, Fetch: 6 * time.Hour}, "behind by design"},
	} {
		if err := c.f.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, f := range Known() {
		if err := f.Validate(); err != nil {
			t.Errorf("the built-in %q does not validate: %v", f.Name, err)
		}
	}
	// Known deliberately leaves the catalogue without a schedule.
	for _, f := range Known() {
		if f.Name == "kev" && f.Scheduled() {
			t.Fatal("the known-exploited catalogue was given a cadence it " +
				"does not have")
		}
	}
}

// TestASourceThatSignsNothingIsNotReportedAsUnverified.
//
// Saying "unverified" of a source that publishes no signatures is noise,
// and noise on that line trains people to skip it where it matters.
func TestASourceThatSignsNothingIsNotReportedAsUnverified(t *testing.T) {
	m := mirrored(t, daily()) // Signs is false
	if err := m.Take(release("epss", t0, 100)); err != nil {
		t.Fatal(err)
	}
	says := m.Attest(t0).Says()
	if strings.Contains(says, "verif") {
		t.Fatalf("a source that signs nothing was reported unverified: %q",
			says)
	}
	for _, tr := range m.Look(t0) {
		if tr.Weight == Unsigned {
			t.Fatal("a source that signs nothing produced a signature " +
				"complaint")
		}
	}
}

func TestDigestIsOrderIndependent(t *testing.T) {
	a := Digest([]string{"CVE-1", "CVE-2", "CVE-3"})
	b := Digest([]string{"CVE-3", "CVE-1", "CVE-2"})
	if a != b {
		t.Fatal("two mirrors with the same contents in a different order " +
			"disagreed, which is the whole use of it")
	}
	if a == Digest([]string{"CVE-1", "CVE-2"}) {
		t.Fatal("a different set has the same digest")
	}
}

func TestAReleaseNeedsADigestAndATime(t *testing.T) {
	m := mirrored(t, daily())
	if err := m.Take(Release{Feed: "epss", Digest: "x"}); err == nil {
		t.Fatal("a release with no fetch time was taken")
	}
	if err := m.Take(Release{Feed: "epss", Fetched: t0}); err == nil {
		t.Fatal("a release with no digest was taken")
	}
	if err := m.Take(release("somethingelse", t0, 1)); err == nil {
		t.Fatal("a release from another feed was taken")
	}
}

func TestAQuietReleaseIsNotAFailedOne(t *testing.T) {
	m := mirrored(t, daily())
	r := release("epss", t0, 250_000)
	if err := m.Take(r); err != nil {
		t.Fatal(err)
	}
	c, _ := m.Current()
	if !c.Quiet() {
		t.Fatal("a release that changed nothing is not quiet?")
	}
	if c.Empty() {
		t.Fatal("a release with entries that changed nothing is not empty")
	}
	if len(m.Look(t0)) != 0 {
		t.Fatalf("a fresh quiet release produced trouble: %+v", m.Look(t0))
	}
}
