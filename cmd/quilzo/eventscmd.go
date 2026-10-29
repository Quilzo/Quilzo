// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Events (internal/public/events.go): records whose listing site.events
// names. What makes them events is that one setting and the fields they are
// read by; everything else is a type, a collection, a listing and pages,
// which `quilzo events setup` installs as one feature package, and which an
// agent can propose the same way.

// siteZone is site.timezone, as the clock upcoming compares with: read again
// a minute after it was last read, so a change is seen without a restart.
func siteZone(root string) func() *time.Location {
	var (
		mu  sync.Mutex
		at  time.Time
		loc = time.UTC
	)
	return func() *time.Location {
		mu.Lock()
		defer mu.Unlock()
		if !at.IsZero() && time.Since(at) < time.Minute {
			return loc
		}
		at, loc = time.Now(), time.UTC
		if cfg, err := loadConfig(root); err == nil && cfg != nil {
			if z := strings.TrimSpace(cfg.Raw("site.timezone")); z != "" {
				if l, err := time.LoadLocation(z); err == nil {
					loc = l
				}
			}
		}
		return loc
	}
}

// eventFields are what an event is read by, in the order the editor asks.
// eventsPackage is the ready-made events feature: a type for an event, its
// collection, the listing of what is to come and the one of what has been,
// an events page and a page for each event.
func eventsPackage() *feature.Package {
	f := func(name string, kind schema.Kind, label, help string, required bool) schema.Field {
		return schema.Field{Name: name, Kind: kind, Label: label, Help: help, Required: required}
	}
	event := schema.Type{Name: "event", Description: "Something happening, on a date: where, when, and how to go.",
		Fields: []schema.Field{
			f("title", schema.Text, "Title", "", true),
			f("slug", schema.Slug, "Page link", "The end of the event's own page link: /event/this-part.", true),
			f("date", schema.Date, "Date", "The day it is on, or the first of several.", true),
			f("time", schema.Time, "Starts at", "Leave empty for all day.", false),
			f("end_date", schema.Date, "Last day", "For an event over several days.", false),
			f("until", schema.Time, "Finishes at", "", false),
			f("venue", schema.Text, "Venue", "The name of the place.", false),
			f("location", schema.Text, "Location", "Its street and town, so a map and a calendar can find it.", false),
			f("online", schema.URL, "Online at", "Where to join, for an event online.", false),
			f("summary", schema.LongText, "About it", "", false),
			f("image", schema.Text, "Picture", "A picture from the media library.", false),
			{Name: "alt", Kind: schema.Text, Label: "What the picture shows", AltFor: "image"},
			f("price", schema.Text, "Price", "As it should read: £5, or Free.", false),
			f("tickets", schema.URL, "Tickets", "Where to get tickets, when somewhere else sells them.", false),
			{Name: "status", Kind: schema.Choice, Label: "Status",
				Help:    "Leave empty while it is on as planned.",
				Choices: []string{"cancelled", "postponed", "moved online", "rescheduled"}},
		}}
	public := []string{"title", "slug", "date", "time", "end_date", "until", "venue", "location", "online",
		"summary", "image", "alt", "price", "tickets", "status"}
	return &feature.Package{Format: feature.Format, Name: "events", Version: "1.0", Title: "Events",
		Purpose: "What is on: a page of events still to come, a page for each, and a calendar visitors can " +
			"subscribe to.",
		Types:       []schema.Type{event},
		Collections: []feature.Collection{{Name: "events", Type: "event"}},
		Listings: []listing.Listing{
			{Name: "upcoming_events", Label: "What's on", Collection: "events", Fields: public,
				Where: []listing.Condition{{Field: "end_date", Else: "date", Match: listing.Upcoming}},
				Sort:  "date", Rows: 50},
			{Name: "past_events", Label: "What has been", Collection: "events", Fields: public,
				Where: []listing.Condition{{Field: "end_date", Else: "date", Match: listing.Past}},
				Sort:  "date", Descending: true, Rows: 50},
		},
		Pages: []feature.Page{
			{Name: "events", Body: map[string]any{"title": "What's on",
				"description": "Events still to come, and a calendar to subscribe to.",
				"sections": []any{map[string]any{"events": map[string]any{"title": "What's on", "rows": float64(20),
					"intro": ""}}}}},
			// No title of its own: it stands for whichever event is being
			// looked at, and the heading comes from the record.
			{Name: "event", Body: map[string]any{"detail": "upcoming_events", "detail_key": "slug"}},
		},
		Events: "upcoming_events",
	}
}

// cmdEvents is `quilzo events …`.
func cmdEvents(root string, args []string) error {
	return eventsCmd(root, args, resolveCaller(root, flagToken))
}

func eventsCmd(root string, args []string, caller *Caller) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return eventsList(root, caller)
	case "setup":
		return eventsSetup(root, caller)
	case "example":
		body, _ := json.MarshalIndent(eventsPackage(), "", "  ")
		w.Human("%s\n", body)
		return nil
	default:
		return fmt.Errorf("unknown events command %q; try list, setup or example", args[0])
	}
}

// eventsSetup installs the ready-made events feature, as `quilzo feature
// install` would: one decision, on the record.
func eventsSetup(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return fmt.Errorf("events are added as a feature, by whoever may install one: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("a feature is installed by a person. A model may propose one; it may not install one")
	}
	body, err := json.Marshal(eventsPackage())
	if err != nil {
		return err
	}
	p, body, err := readFeatureBytes(root, body, "")
	if err != nil {
		return err
	}
	o, err := requestFeature(root, p, body, caller, false, false, nil)
	if err := printOutcome(p, o, err, caller); err != nil {
		return err
	}
	// A layout written before events existed has nowhere to show them.
	if b, err := os.ReadFile(filepath.Join(newsletterDesignDir, "page.html")); err == nil &&
		!strings.Contains(string(b), "s.events") {
		w.Human("%syour layout was made before events: choose your starter again under Design, or run "+
			"quilzo template use sections --force, for the events section and each event's page%s\n", yellow, reset)
	}
	if o.Waiting == nil {
		w.Human("add events on the Data screen (collection events) or with quilzo records add events " +
			"title=… slug=… date=2026-11-14 time=19:30; publish the draft for the What's on page, and the " +
			"calendar is at /events.ics\n")
	}
	return nil
}

// upcomingEvents is the events the site's events listing keeps now, at the
// live site, as rows.
func upcomingEvents(root string) ([]listing.Row, string, error) {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, "", err
	}
	name := strings.TrimSpace(cfg.Raw("site.events"))
	if name == "" {
		return nil, "", nil
	}
	set, err := loadListings(root)
	if err != nil {
		return nil, name, err
	}
	l, ok := set.Get(name)
	if !ok {
		return nil, name, fmt.Errorf("site.events names %q and no listing has that name", name)
	}
	s, err := store.Open(root)
	if err != nil {
		return nil, name, err
	}
	c, err := s.GetCommit(s.GetRef(site.RefLive))
	if err != nil {
		return nil, name, nil
	}
	idx, err := collection.Build(s, c.Tree, l.Collection, nil)
	if err != nil {
		return nil, name, err
	}
	rows, _, err := listing.Every(l, idx, nil, listing.MaxRows)
	return rows, name, err
}

func eventsList(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	rows, name, err := upcomingEvents(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"listing": name, "events": rows}) {
		return nil
	}
	if name == "" {
		w.Human("this site has no events yet: quilzo events setup adds them\n")
		return nil
	}
	if len(rows) == 0 {
		w.Human("nothing is planned in %s\n", name)
		return nil
	}
	for _, r := range rows {
		str := func(k string) string { v, _ := r[k].(string); return v }
		when := str("date")
		if t := str("time"); t != "" {
			when += " " + t
		}
		place := str("venue")
		if place == "" && str("online") != "" {
			place = "online"
		}
		w.Human("%s  %s  %s%s\n", when, str("title"), place, map[bool]string{true: "  (" + str("status") + ")",
			false: ""}[str("status") != ""])
	}
	return nil
}

// setSiteEvents names the site's events listing, or none, on the record.
func setSiteEvents(root, name, why string, caller *Caller) error {
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	if name == "" {
		err = cfg.Unset("site.events")
	} else {
		err = cfg.Set("site.events", name, why, caller.Name)
	}
	if err != nil {
		return err
	}
	if err := saveConfig(root, cfg); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("site.events", "/", audit.Success,
		map[string]string{"listing": name, "why": why}))
}
