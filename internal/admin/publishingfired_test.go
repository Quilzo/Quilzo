// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/schedule"
)

// What scheduled publishing did is on the Publishing screen after it did
// it: a refused launch says why, so the person who scheduled it can find
// out, and the screen says who will publish what is still pending.
func TestTheScheduleSaysWhatHappened(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"})
	now := time.Now()
	sch := &schedule.Schedule{Entries: []schedule.Entry{
		{Commit: strings.Repeat("a", 64), At: now.Add(-2 * time.Hour).Unix(), By: "sam",
			Done: true, Result: "refused: sam may no longer publish", FiredAt: now.Add(-2 * time.Hour).Unix()},
		{Commit: strings.Repeat("b", 64), At: now.Add(-time.Hour).Unix(), By: "editor",
			Done: true, Result: "published 4 minutes late", FiredAt: now.Add(-56 * time.Minute).Unix()},
		// Long ago: not recent, so not listed.
		{Commit: strings.Repeat("c", 64), At: now.Add(-90 * 24 * time.Hour).Unix(), By: "editor",
			Done: true, Result: "published", FiredAt: now.Add(-90 * 24 * time.Hour).Unix()},
	}}
	on := true
	srv.Publishing.Schedule = func() (*schedule.Schedule, error) { return sch, nil }
	srv.Publishing.InServer = func() bool { return on }

	body := getPage(t, srv, "/publishing", tok["editor"])
	for _, want := range []string{"Recently fired", "refused: sam may no longer publish",
		"published 4 minutes late", "This server publishes it at that time"} {
		if !strings.Contains(body, want) {
			t.Errorf("the Publishing screen does not say %q", want)
		}
	}
	if strings.Contains(body, strings.Repeat("c", 12)) {
		t.Error("an entry from three months ago is listed as recent")
	}
	if strings.Index(body, strings.Repeat("b", 12)) > strings.Index(body, strings.Repeat("a", 12)) {
		t.Error("not newest first")
	}

	on = false
	if body := getPage(t, srv, "/publishing", tok["editor"]); !strings.Contains(body, "schedule.in_server") {
		t.Error("with the server not publishing, the screen does not say what will")
	}
}

// The Publishing screen's record of scheduling keeps the note as the
// command line's does: on one line and clipped whole, with who scheduled
// it. It kept all 301 bytes of a pasted paragraph, so the one act read two
// ways in the log depending on where it was done.
func TestScheduledFromTheBrowserTheNoteIsClippedAsOnTheCommandLine(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"})
	sch := &schedule.Schedule{}
	srv.Publishing.Schedule = func() (*schedule.Schedule, error) { return sch, nil }
	srv.Publishing.UpdateSchedule = func(fn func(*schedule.Schedule) error) error { return fn(sch) }
	var detail map[string]string
	srv.Audit = func(action, _ string, d map[string]string) {
		if action == "schedule.add" {
			detail = d
		}
	}
	note := "x10gui " + strings.Repeat("a", 192) + "é" + strings.Repeat("b", 100)
	w := postForm(t, srv, "/publishing/schedule", tok["editor"],
		url.Values{"when": {"240h"}, "note": {note}}.Encode())
	if w.Code != http.StatusSeeOther || len(sch.Entries) != 1 {
		t.Fatalf("not scheduled: %d %s", w.Code, w.Header().Get("Location"))
	}
	if sch.Entries[0].Note != note {
		t.Error("the entry does not keep the whole note")
	}
	want := schedule.Detail(sch.Entries[0].Commit, time.Unix(sch.Entries[0].At, 0), note, "editor")
	if detail["note"] != want["note"] || !utf8.ValidString(detail["note"]) || len(detail["note"]) > schedule.MaxNote+len("…") {
		t.Errorf("the record kept the note as %q (%d bytes), not %q", detail["note"], len(detail["note"]), want["note"])
	}
	if detail["by"] != "editor" || detail["scheduled"] != sch.Entries[0].Commit {
		t.Errorf("the record does not say what was scheduled and by whom: %v", detail)
	}
}

// A server whose scheduler may not publish says so on the Publishing
// screen, beside every entry it will not publish and when one is added. It
// said "This server publishes it at that time" and showed an entry past its
// time as pending, while the scheduler, started without a token that may
// publish, refused every entry and said why only on the server's own
// error output.
func TestTheScheduleSaysWhenThisServerCannotPublishIt(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"})
	now := time.Now()
	sch := &schedule.Schedule{Entries: []schedule.Entry{
		{Commit: srv.Store.GetRef("draft"), At: now.Add(-10 * time.Minute).Unix(), By: "editor"},
	}}
	why := "this store has access control configured, so publish needs a verified identity"
	srv.Publishing.Schedule = func() (*schedule.Schedule, error) { return sch, nil }
	srv.Publishing.UpdateSchedule = func(fn func(*schedule.Schedule) error) error { return fn(sch) }
	srv.Publishing.InServer = func() bool { return true }
	srv.Publishing.CannotPublish = func() string { return why }

	body := getPage(t, srv, "/publishing", tok["editor"])
	if strings.Contains(body, "This server publishes it at that time") {
		t.Error("the screen promises a publish this server cannot make")
	}
	if !strings.Contains(body, why) || !strings.Contains(body, "overdue") {
		t.Errorf("the screen does not say the entry past its time was not published, and why:\n%s", body)
	}
	if strings.Contains(body, `<span class="ok">pending</span>`) {
		t.Error("an entry past its time that nothing will publish reads as pending")
	}

	sch.Entries = nil
	w := postForm(t, srv, "/publishing/schedule", tok["editor"], url.Values{"when": {"1h"}}.Encode())
	if len(sch.Entries) != 1 {
		t.Fatalf("not scheduled: %d %s", w.Code, w.Header().Get("Location"))
	}
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, why) {
		t.Errorf("scheduling on a server that cannot publish it says %q", loc)
	}
}

// The Schedule form takes the reason a hand-written launch needs, as Review
// → Publish does, and says when an entry will be refused for pages with no
// provenance: it had only a note, so a scheduled publish of pages edited in
// the browser was refused at its time with advice nobody could act on.
func TestTheScheduleFormTakesTheReasonForPagesWithNoProvenance(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"})
	sch := &schedule.Schedule{}
	srv.Publishing.Schedule = func() (*schedule.Schedule, error) { return sch, nil }
	srv.Publishing.UpdateSchedule = func(fn func(*schedule.Schedule) error) error { return fn(sch) }
	srv.LoadProvenance = func() (*provenance.Index, error) { return provenance.NewIndex(), nil }
	var detail map[string]string
	srv.Audit = func(action, _ string, d map[string]string) {
		if action == "schedule.add" {
			detail = d
		}
	}

	w := postForm(t, srv, "/publishing/schedule", tok["editor"], url.Values{"when": {"1h"}}.Encode())
	if len(sch.Entries) != 1 {
		t.Fatalf("not scheduled: %d %s", w.Code, w.Header().Get("Location"))
	}
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "no provenance") {
		t.Errorf("scheduling pages with no provenance does not say it will be refused: %q", loc)
	}

	sch.Entries = nil
	w = postForm(t, srv, "/publishing/schedule", tok["editor"],
		url.Values{"when": {"1h"}, "reason": {"written by hand, marking pending"}}.Encode())
	if len(sch.Entries) != 1 || sch.Entries[0].UnmarkedReason != "written by hand, marking pending" {
		t.Fatalf("the reason was not kept with the entry: %+v", sch.Entries)
	}
	if detail["waives"] != "unmarked-ai" || detail["reason"] != "written by hand, marking pending" {
		t.Errorf("the record of scheduling does not name the waiver: %v", detail)
	}
	if body := getPage(t, srv, "/publishing", tok["editor"]); !strings.Contains(body, "written by hand, marking pending") {
		t.Error("the pending entry does not show the reason it will publish on")
	}
}
