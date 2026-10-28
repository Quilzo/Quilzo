// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Setting events up is one feature, installed as one decision: the type,
// its collection, the listings, the pages and the site's events listing.
// What is on is then read the way the site reads it, by people and agents,
// and taking the feature away leaves the site with no calendar.
func TestEventsAreSetUpAsOneFeature(t *testing.T) {
	root, _ := siteStore(t)
	if err := eventsCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Raw("site.events"); got != "upcoming_events" {
		t.Fatalf("site.events is %q", got)
	}
	set, err := loadListings(root)
	if err != nil {
		t.Fatal(err)
	}
	if l, ok := set.Get("upcoming_events"); !ok || !l.Timed() {
		t.Fatal("the listing of what is to come was not installed, or is not by the clock")
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pages["events"]; !ok {
		t.Fatal("no events page in the draft")
	}
	if p, _ := pages["event"].(map[string]any); p["detail"] != "upcoming_events" {
		t.Fatalf("no page for each event: %v", pages["event"])
	}

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	putTestRecords(t, s, "events", []collection.Record{
		{Fields: map[string]any{"title": "Rye night", "slug": "rye-night", "date": "2099-11-14", "time": "19:30"}},
		{Fields: map[string]any{"title": "Old fair", "slug": "old-fair", "date": "2001-05-01"}},
	})
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	rows, name, err := upcomingEvents(root)
	if err != nil || name != "upcoming_events" || len(rows) != 1 || rows[0]["title"] != "Rye night" {
		t.Fatalf("what is on: %v %s %v", rows, name, err)
	}
	call := siteCrew(t, root)
	got := call("quilzo_read", "upcoming_events", nil)
	up, _ := got["upcoming"].([]any)
	if got["events"] != true || len(up) != 1 || !strings.Contains(stringOf(got), "Rye night") {
		t.Fatalf("over MCP: %v", got)
	}

	if err := removeFeature(root, "events", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(root)
	if got := cfg.Raw("site.events"); got != "" {
		t.Fatalf("the feature is gone and site.events still names %q", got)
	}
}

// The site's clock is site.timezone, and a change to it is seen without a
// restart.
func TestTheSitesClockIsItsTimeZone(t *testing.T) {
	root, _ := siteStore(t)
	zone := siteZone(root)
	if zone() != time.UTC {
		t.Fatal("with no zone set, the clock is not UTC")
	}
	cfg, _ := loadConfig(root)
	if err := cfg.Set("site.timezone", "Not/AZone", "", "dana"); err == nil {
		t.Fatal("a zone that does not exist was set")
	}
	if err := cfg.Set("site.timezone", "Europe/London", "", "dana"); err != nil {
		t.Skip("no zone database")
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if got := siteZone(root)(); got.String() != "Europe/London" {
		t.Fatalf("the clock is %s", got)
	}
	listing.SetZone(siteZone(root))
	t.Cleanup(func() { listing.SetZone(nil) })
	if listing.Zone().String() != "Europe/London" {
		t.Fatal("listings do not read the site's clock")
	}
}
