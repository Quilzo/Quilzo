// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The Today screen said "Last published 3 hours ago" above a waiting item
// "3 h ago": two wordings of one age on one screen, from two helpers that
// had drifted apart.
func TestTheTodayScreenSaysHowLongAgoInOneWay(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	now := time.Now()
	then := now.Add(-3*time.Hour - 10*time.Minute)

	draft, err := srv.Store.GetCommit(srv.Store.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	live, err := srv.Store.PutCommit(store.Commit{Tree: draft.Tree, Message: "publish", Author: "dana", At: then.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Store.SetRef(site.RefLive, live); err != nil {
		t.Fatal(err)
	}
	read := agent.Action{Op: "read_page", Input: map[string]any{"page": "x"}}
	waitingRun(st, "run-20261104-000000d1", "librarian", read, "it asks first", then)

	body := get(t, srv, "/today", token).Body.String()
	if !strings.Contains(body, "Last published 3 hours ago") {
		t.Errorf("the last publish is not said in words:\n%s", firstLines(body[strings.Index(body, "glance"):], 8))
	}
	if !strings.Contains(body, `<td class="when">3 hours ago</td>`) {
		t.Errorf("the waiting item is not said the same way:\n%s", firstLines(body[strings.Index(body, "Waiting for you"):], 12))
	}
	if strings.Contains(body, " h ago") || strings.Contains(body, " min ago") {
		t.Error("an age on Today is still abbreviated")
	}
}

// roughDuration(time.Minute) printed "1 minutes", which the Shield screen
// put in a sentence: "slow the source on the site for 1 minutes".
func TestAMinuteIsOneMinute(t *testing.T) {
	minute := shield.Duration(time.Minute)
	for _, said := range []string{
		roughDuration(time.Minute),
		plainDuration(time.Minute),
		shieldStepWords(shield.Step{Action: "slow-source", Where: shield.Site, For: minute}),
		shieldTrigger(shield.Playbook{On: shield.Trigger{Signal: "form-spam", Per: "source", Count: 5, Within: minute}}),
	} {
		if !strings.Contains(said, "1 minute") || strings.Contains(said, "1 minutes") {
			t.Errorf("%q", said)
		}
	}
}

// Every screen says an age, and a span of time, in the same words. Ages
// came from agoText ("5 min ago", "3 h ago", hours up to 48) and agoAt
// ("5 minutes ago", "3 hours ago", hours up to 24); spans from
// plainDuration ("1 hour") and roughDuration ("an hour", "1 minutes").
func TestEveryAgeOnTheScreensUsesTheSameWords(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		-time.Hour: "just now", 30 * time.Second: "just now",
		time.Minute: "1 minute ago", 5 * time.Minute: "5 minutes ago", 59 * time.Minute: "59 minutes ago",
		time.Hour: "1 hour ago", 3*time.Hour + 59*time.Minute: "3 hours ago", 23 * time.Hour: "23 hours ago",
		24 * time.Hour: "1 day ago", 47 * time.Hour: "1 day ago", 72 * time.Hour: "3 days ago",
	} {
		said := map[string]string{
			"agoText": agoText(d),
			"agoAt":   agoAt(now.Add(-d).Unix(), now),
		}
		if d >= 0 {
			said["ranAgo"] = ranAgo(time.Now().Add(-d).Format(time.RFC3339))
		}
		for who, got := range said {
			if got != want {
				t.Errorf("%s of %s: %q, want %q", who, d, got, want)
			}
		}
	}
	if agoAt(0, now) != "never" {
		t.Error("zero is not never")
	}

	for d, want := range map[time.Duration]string{
		time.Minute: "1 minute", 10 * time.Minute: "10 minutes", 90 * time.Minute: "90 minutes",
		time.Hour: "an hour", 6 * time.Hour: "6 hours", 24 * time.Hour: "24 hours",
		// Not a whole number of minutes: Go's own rendering, exact, rather
		// than a tidy number that is wrong.
		90 * time.Second: "1m30s", 30 * time.Second: "30s",
	} {
		for who, got := range map[string]string{"plainDuration": plainDuration(d), "roughDuration": roughDuration(d)} {
			if got != want {
				t.Errorf("%s of %s: %q, want %q", who, d, got, want)
			}
		}
	}
}

// A card on Ask that counts agent runs said "Runs of every agent you
// manage in the last 1 days" when the question was about the last day: the
// same wrong plural as "for 1 minutes", in a span the card writes itself.
// Today says "in the last day", and so does the card now.
func TestADayIsOneDay(t *testing.T) {
	for days, want := range map[int]string{
		1: "Runs of every agent you manage in the last day",
		7: "Runs of every agent you manage in the last 7 days",
	} {
		if got := cardWords(AskCard{Kind: "runs", Days: days}); got != want {
			t.Errorf("%d days: %q, want %q", days, got, want)
		}
	}
}
