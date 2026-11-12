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
