// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
	"time"

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
