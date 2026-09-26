// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/feed"
	"github.com/quilzo/quilzo/internal/flow"
	"github.com/quilzo/quilzo/internal/proving"
	"github.com/quilzo/quilzo/internal/source"
)

// screen opens /security/running with the given capabilities wired.
func screen(t *testing.T, r *Running) string {
	t.Helper()
	srv, token := setup(t)
	srv.Running = r
	w := get(t, srv, "/security/running", token)
	if w.Code != 200 {
		t.Fatalf("answered %d:\n%s", w.Code, firstLines(w.Body.String(), 6))
	}
	return w.Body.String()
}

// TestAnAbsentCapabilityDoesNotReadAsNothingFound.
//
// The property this whole screen turns on. An empty list of stale feeds and
// a build that cannot see any feeds are the same picture and opposite
// facts, and the second one is the dangerous one because it looks like the
// first.
func TestAnAbsentCapabilityDoesNotReadAsNothingFound(t *testing.T) {
	// Nothing wired at all.
	body := screen(t, nil)
	if !strings.Contains(body, "would read as everything being fine") {
		t.Fatalf("an unwired build did not say so:\n%s", firstLines(body, 20))
	}
	if strings.Contains(body, "Nothing here is silent") {
		t.Fatal("an unwired build reported that nothing is silent")
	}

	// Three of four wired, one absent.
	part := &Running{
		Feeds: func() ([]feed.Attestation, error) {
			return []feed.Attestation{{Feed: "osv", Entries: 40000,
				Fetched: time.Now().UTC()}}, nil
		},
		Sources: func() ([]source.Health, error) {
			return []source.Health{{Source: "okta/system", Records: 100,
				Mapped: 100}}, nil
		},
		Flows: func() ([]flow.Trouble, error) { return nil, nil },
	}
	body = screen(t, part)
	if !strings.Contains(body, "cannot answer for") ||
		!strings.Contains(body, "detection estate") {
		t.Fatalf("a missing capability was not named:\n%s",
			firstLines(body, 30))
	}
	if !strings.Contains(body, "not a section that found nothing") {
		t.Fatal("the screen does not say what an absent section means")
	}
}

// TestAnErroringCapabilityIsNotSilence.
func TestAnErroringCapabilityIsNotSilence(t *testing.T) {
	body := screen(t, &Running{
		Feeds: func() ([]feed.Attestation, error) {
			return nil, errors.New("the mirror directory is unreadable")
		},
	})
	if !strings.Contains(body, "the mirror directory is unreadable") {
		t.Fatalf("an error was swallowed:\n%s", firstLines(body, 20))
	}
}

// TestSilentThingsAreNamedRatherThanCounted.
func TestSilentThingsAreNamedRatherThanCounted(t *testing.T) {
	body := screen(t, &Running{
		Feeds: func() ([]feed.Attestation, error) {
			return []feed.Attestation{
				{Feed: "epss", Stale: true, Missed: 3, Schedule: true,
					Fetched: time.Now().Add(-72 * time.Hour),
					Age:     72 * time.Hour, Entries: 284311},
				{Feed: "osv", Fetched: time.Now(), Entries: 40000},
			}, nil
		},
		Sources: func() ([]source.Health, error) {
			return []source.Health{{Source: "aws/cloudtrail",
				Records: 100, Mapped: 60, Drifted: true,
				Why: "failing 40% of records on userIdentity.arn"}}, nil
		},
		Estate: func() (proving.Noise, []*proving.Candidate, error) {
			return proving.Noise{}, nil, nil
		},
	})
	for _, want := range []string{
		"epss is behind",
		"aws/cloudtrail is not mapping",
		"userIdentity.arn",
		"nothing is live",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not name %q", want)
		}
	}
	// A healthy feed is still listed, so the table is the whole picture
	// rather than only the bad half.
	if !strings.Contains(body, "osv") {
		t.Error("a current feed was left out of the table")
	}
}

// TestNothingSilentSaysSoPlainly.
func TestNothingSilentSaysSoPlainly(t *testing.T) {
	body := screen(t, &Running{
		Feeds: func() ([]feed.Attestation, error) {
			return []feed.Attestation{{Feed: "osv",
				Fetched: time.Now().UTC(), Entries: 40000}}, nil
		},
		Sources: func() ([]source.Health, error) {
			return []source.Health{{Source: "okta/system", Records: 10,
				Mapped: 10}}, nil
		},
		Flows: func() ([]flow.Trouble, error) { return nil, nil },
		Estate: func() (proving.Noise, []*proving.Candidate, error) {
			return proving.Noise{Rules: 12, PerDay: 31.5,
				Worst: "Encoded PowerShell", WorstAt: 9}, nil, nil
		},
	})
	if !strings.Contains(body, "Nothing here is silent") {
		t.Fatalf("a healthy build did not say so:\n%s", firstLines(body, 30))
	}
	if !strings.Contains(body, "31.5") || !strings.Contains(body, "12") {
		t.Error("the estate's cost is not shown")
	}
}
