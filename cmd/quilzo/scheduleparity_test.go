// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
)

// Scheduling the draft leaves the same audit record whichever surface did
// it, and the note in it is whole.
//
// `quilzo schedule add` and the Publishing screen's form were two copies.
// The command line cut the note at its 200th byte, through an é, and the
// record kept half of it and then "…"; the browser kept all 301 bytes. The
// browser's record said who in its detail and the command line's did not.
// The same act, in a log that is evidence, read two ways.
func TestTheCLIAndTheAdminScheduleAPublishTheSameWay(t *testing.T) {
	root := newStoreWithDraft(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	draft := s.GetRef(site.RefDraft)
	note := "x10 " + strings.Repeat("a", 195) + "é" + strings.Repeat("b", 100)

	if err := cmdSchedule(root, []string{"add", "240h", "--note", note}); err != nil {
		t.Fatal(err)
	}
	cli := lastScheduleAdd(t, root)
	if err := cmdSchedule(root, []string{"cancel", draft[:12]}); err != nil {
		t.Fatal(err)
	}

	seedPolicy(t, root, [2]string{"dana", "admin"})
	srv, tok := scheduleScreen(t, root)
	form := url.Values{"when": {"240h"}, "note": {note}}
	req := httptest.NewRequest(http.MethodPost, "/publishing/schedule", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "e=") {
		t.Fatalf("the Publishing screen did not schedule the draft: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	browser := lastScheduleAdd(t, root)

	for name, d := range map[string]map[string]string{"the command line": cli, "the browser": browser} {
		if got := d["note"]; !utf8.ValidString(got) || len(got) > schedule.MaxNote+len("…") || !strings.HasSuffix(got, "…") {
			t.Errorf("%s recorded the note as %q (%d bytes): not clipped whole to %d bytes", name, got, len(got), schedule.MaxNote)
		}
		if d["scheduled"] != draft {
			t.Errorf("%s recorded %q as scheduled, not the draft", name, d["scheduled"])
		}
	}
	if cli["note"] != browser["note"] {
		t.Errorf("the two surfaces recorded one note two ways:\n  command line %q\n  browser      %q", cli["note"], browser["note"])
	}
	if a, b := slices.Sorted(maps.Keys(cli)), slices.Sorted(maps.Keys(browser)); !slices.Equal(a, b) {
		t.Errorf("the two records say different things: command line %v, browser %v", a, b)
	}
	if cli["by"] == "" || browser["by"] == "" {
		t.Errorf("a record does not say who scheduled it: command line %q, browser %q", cli["by"], browser["by"])
	}
}

// Both surfaces read a time the same way, from one reading of it.
func TestTheCLIAndTheAdminReadWhenTheSameWay(t *testing.T) {
	root := newStoreWithDraft(t)
	seedPolicy(t, root, [2]string{"dana", "admin"})
	srv, tok := scheduleScreen(t, root)
	for _, when := range []string{"0s", "soon", "2026-13-01T09:00:00Z"} {
		_, want := schedule.ParseWhen(when, time.Now())
		if want == nil {
			t.Fatalf("%q was read as a time", when)
		}
		form := url.Values{"when": {when}}
		req := httptest.NewRequest(http.MethodPost, "/publishing/schedule", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if got := loc.Query().Get("e"); got != want.Error() {
			t.Errorf("the browser refused %q with %q, the schedule with %q", when, got, want.Error())
		}
		if err := cmdSchedule(root, []string{"add", when}); err == nil || err.Error() != want.Error() {
			t.Errorf("the command line refused %q with %v, the schedule with %q", when, err, want.Error())
		}
	}
}

// scheduleScreen is the admin's Publishing screen as `quilzo serve` wires
// it, with an administrator's session.
func scheduleScreen(t *testing.T, root string) (*admin.Server, string) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Audit = func(action, resource string, detail map[string]string) {
		record(root, adminRecord(action, resource, detail))
	}
	srv.Publishing = &admin.Publishing{
		Schedule:       func() (*schedule.Schedule, error) { return loadSchedule(root) },
		UpdateSchedule: func(fn func(*schedule.Schedule) error) error { return updateSchedule(root, fn) },
	}
	tok := tokenFor(t, toks, waitingSession{name: "dana", actor: admin.Actor{Name: "dana", Role: auth.RoleAdmin, Scope: "/"}})
	return srv, tok
}

func lastScheduleAdd(t *testing.T, root string) map[string]string {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Action == "schedule.add" {
			return evs[i].Detail
		}
	}
	t.Fatal("no schedule.add was recorded")
	return nil
}
