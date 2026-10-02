// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// asJob signs in as somebody holding one job and nothing else.
func asJob(t *testing.T, job string) (*Server, string) {
	t.Helper()
	srv, _ := fullyWired(t)
	j, ok := auth.JobNamed(job)
	if !ok {
		t.Fatalf("no job %q", job)
	}
	pol := &auth.Policy{}
	top := auth.RoleReader
	for _, b := range j.Bindings {
		b.Principal = "worker"
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
		if b.Role.AtLeast(top) {
			top = b.Role
		}
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("test", "worker", top, "/", time.Hour, top)
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens = pol, ts
	return srv, secret
}

// Each job opens its own screens and no others.
func TestAJobOpensItsScreensAndNoOthers(t *testing.T) {
	for _, c := range []struct {
		job       string
		open      []string
		closed    []string
		firstStop string
	}{
		{"analyst",
			[]string{"/findings", "/security/cases", "/security/events", "/security/hunt", "/security/detections", "/logs"},
			[]string{"/people", "/access", "/settings", "/page/index", "/security", "/security/frameworks", "/inbox", "/members"},
			"/findings"},
		{"compliance",
			[]string{"/security", "/security/frameworks", "/logs"},
			[]string{"/findings", "/security/cases", "/people", "/page/index", "/inbox"},
			"/security"},
		{"support",
			[]string{"/inbox", "/boards"},
			[]string{"/findings", "/security", "/logs", "/people", "/page/index", "/members"},
			"/inbox"},
	} {
		t.Run(c.job, func(t *testing.T) {
			srv, token := asJob(t, c.job)
			for _, path := range c.open {
				if w := get(t, srv, path, token); w.Code != http.StatusOK {
					t.Errorf("%s cannot open %s: %d", c.job, path, w.Code)
				}
			}
			for _, path := range c.closed {
				if w := get(t, srv, path, token); w.Code == http.StatusOK {
					t.Errorf("%s opened %s", c.job, path)
				}
			}
			w := get(t, srv, "/", token)
			if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), c.firstStop) {
				t.Errorf("the front door sent %s to %d %q", c.job, w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// Granting is a whole-site decision, whatever area somebody administers.
func TestAnAreaAdministratorCannotGrant(t *testing.T) {
	srv, token := asJob(t, "analyst")
	w := postForm(t, srv, "/people/grant", token, "principal=mallory&role=admin&resource=/")
	if w.Code == http.StatusSeeOther || w.Code == http.StatusOK {
		if srv.Policy.Evaluate("mallory", auth.ActView, "/").Allowed {
			t.Fatal("an analyst granted somebody the whole site")
		}
	}
	w = postForm(t, srv, "/people/grant", token, "principal=mallory&role=admin&resource=/@security")
	if srv.Policy.Evaluate("mallory", auth.ActView, auth.AreaSecurity).Allowed {
		t.Error("an analyst granted somebody their own area")
	}
}

// The People screen grants a job, with an end, and shows it.
func TestThePeopleScreenGrantsAJobUntilADay(t *testing.T) {
	srv, token := setup(t)
	day := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	postForm(t, srv, "/people/grant", token, "new_principal=lee&role=job%3Asupport&until="+day)
	if !srv.Policy.Evaluate("lee", auth.ActEditDraft, auth.AreaInbox).Allowed ||
		srv.Policy.Evaluate("lee", auth.ActEditDraft, "/index").Allowed {
		t.Fatal("the support job was not granted as its areas alone")
	}
	for _, b := range srv.Policy.Bindings {
		if b.Principal == "lee" && b.Expires == 0 {
			t.Errorf("a grant with an end day never ends: %+v", b)
		}
	}
	if body := get(t, srv, "/people", token).Body.String(); !strings.Contains(body, "until ") {
		t.Error("the People screen does not say when the grant ends")
	}
	// A day already gone is refused, not granted forever.
	postForm(t, srv, "/people/grant", token, "new_principal=old&role=reader&until=2020-01-01")
	if srv.Policy.Evaluate("old", auth.ActView, "/").Allowed {
		t.Error("a grant ending in the past was made")
	}
}
