// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
)

func draftRecords(t *testing.T, root, coll string) []collection.Record {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := collection.Build(s, tree, coll, nil)
	if err != nil {
		t.Fatal(err)
	}
	return idx.Records
}

func bySlug(recs []collection.Record) map[string]collection.Record {
	out := map[string]collection.Record{}
	for _, r := range recs {
		s, _ := r.Fields["slug"].(string)
		out[s] = r
	}
	return out
}

// A spreadsheet of events comes in as events, goes out as a spreadsheet,
// and comes back in as the same events, changed where the sheet was.
func TestASpreadsheetComesInAndGoesOutAsTheSameRecords(t *testing.T) {
	root, _ := siteStore(t)
	if err := eventsCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sheetFile := "Title,Date,Starts at,Place,Notes\r\n" +
		"Rye night,14/11/2099,7.30pm,The bakery,bring a loaf\r\n" +
		"Rye night,12/12/2099,7.30pm,The bakery,\r\n" +
		"Open day,25/12/2099,,,\r\n"
	b, err := bringFile(ctx, root, "events", "events.csv", []byte(sheetFile), bringOptions{}, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if b.New != 3 || b.Updated != 0 {
		t.Fatalf("%+v", b)
	}
	got := bySlug(draftRecords(t, root, "events"))
	if r := got["rye-night"]; r.Fields["date"] != "2099-11-14" || r.Fields["time"] != "19:30" ||
		r.Fields["venue"] != "The bakery" {
		t.Fatalf("rye night: %v (all %v)", r.Fields, got)
	}
	if _, ok := got["rye-night-2"]; !ok {
		t.Fatalf("the second rye night has no page of its own: %v", got)
	}

	// Out as a spreadsheet, a venue changed, and back in: the same three.
	out, n, err := sheetOf(root, "events", "csv", false)
	if err != nil || n != 3 {
		t.Fatalf("%d records: %v", n, err)
	}
	if !strings.HasPrefix(string(out), "id,title,slug,date,time,end_date,until,venue,") {
		t.Fatalf("headings: %s", strings.SplitN(string(out), "\n", 2)[0])
	}
	changed := strings.Replace(string(out), "The bakery", "The mill", 1)
	file := filepath.Join(t.TempDir(), "events.csv")
	if err := os.WriteFile(file, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordsImport(root, []string{"events", file}); err != nil {
		t.Fatal(err)
	}
	after := draftRecords(t, root, "events")
	if len(after) != 3 || bySlug(after)["rye-night"].Fields["venue"] != "The mill" {
		t.Fatalf("brought back as %v", after)
	}

	// A check writes nothing; a sheet with a bad row writes nothing unless
	// asked to bring the rest.
	bad := "title,date\nHarvest supper,2099-10-01\nNo date,someday\n"
	if b, err := bringFile(ctx, root, "events", "x.csv", []byte(bad), bringOptions{dryRun: true},
		asAdmin("dana")); err == nil || b.New != 0 || !strings.Contains(err.Error(), `line 3: date: "someday" is not a date`) {
		t.Fatalf("%+v %v", b, err)
	}
	if b, err := bringFile(ctx, root, "events", "x.csv", []byte(bad), bringOptions{dryRun: true, skipBad: true},
		asAdmin("dana")); err != nil || b.New != 1 {
		t.Fatalf("checking with the rest brought: %+v %v", b, err)
	}
	if len(draftRecords(t, root, "events")) != 3 {
		t.Fatal("a check wrote")
	}

	// JSON goes out and comes back the same way.
	js, _, err := sheetOf(root, "events", "json", false)
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal(js, &list); err != nil || len(list) != 3 || list[0]["id"] == nil {
		t.Fatalf("%s %v", js, err)
	}
	if b, err := bringFile(ctx, root, "events", "x.json", js, bringOptions{}, asAdmin("dana")); err != nil ||
		b.Updated != 3 || b.New != 0 {
		t.Fatalf("%+v %v", b, err)
	}
}

// A calendar's events come in each time they happen; brought again they
// are the same events; one the calendar keeps private does not come in.
func TestACalendarBringsItsEventsOnce(t *testing.T) {
	root, _ := siteStore(t)
	if err := eventsCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	next := time.Now().UTC().AddDate(0, 0, 7).Format("20060102")
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\nUID:choir@x\r\nSUMMARY:Choir\r\nDTSTART:" + next + "T180000Z\r\n" +
		"DTEND:" + next + "T190000Z\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\nLOCATION:The hall\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:me@x\r\nSUMMARY:Dentist\r\nCLASS:PRIVATE\r\nDTSTART:" + next + "T090000Z\r\nEND:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	file := filepath.Join(t.TempDir(), "club.ics")
	if err := os.WriteFile(file, []byte(ics), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := eventsCmd(root, []string{"import", file}, asAdmin("dana")); err != nil {
			t.Fatal(err)
		}
	}
	recs := draftRecords(t, root, "events")
	if len(recs) != 3 {
		t.Fatalf("%d events: %v", len(recs), recs)
	}
	for _, r := range recs {
		if r.Fields["title"] != "Choir" || r.Fields["location"] != "The hall" ||
			!strings.HasPrefix(r.Fields["slug"].(string), "choir-") {
			t.Errorf("%v", r.Fields)
		}
	}
	if err := eventsCmd(root, []string{"import", filepath.Join(t.TempDir(), "none.ics")}, asAdmin("dana")); err == nil {
		t.Error("a calendar that is not there was brought in")
	}
}

// A calendar's address is its password: when it cannot be fetched, the
// error names its host and not the rest of it.
func TestAPrivateCalendarsAddressIsNotRepeated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, name, err := calendarFrom(ctx, "webcal://calendar.invalid/calendar/ical/me%40x/private-SECRET123/basic.ics")
	if err == nil || name != "calendar.invalid" {
		t.Fatalf("%q %v", name, err)
	}
	if strings.Contains(err.Error(), "SECRET123") || strings.Contains(err.Error(), "private-") {
		t.Errorf("the error repeats the address: %v", err)
	}
}

// Events are brought only where there are events to bring them into.
func TestACalendarNeedsEventsSetUp(t *testing.T) {
	root, _ := siteStore(t)
	err := eventsCmd(root, []string{"import", "x.ics"}, asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "quilzo events setup") {
		t.Fatalf("%v", err)
	}
}
