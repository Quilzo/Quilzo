// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
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
		{"auditor",
			[]string{"/security", "/security/frameworks", "/security/rules", "/security/integrity", "/security/inventory", "/security/scan", "/security/agents", "/security/running", "/logs"},
			[]string{"/findings", "/security/hunt", "/people", "/access", "/page/index", "/inbox", "/boards", "/members"},
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

// An auditor reads the evidence and changes none of it.
func TestAnAuditorReadsEvidenceAndChangesNothing(t *testing.T) {
	srv, token := asJob(t, "auditor")
	body := get(t, srv, "/security/integrity", token).Body.String()
	if strings.Contains(body, `action="/security/verify"`) {
		t.Error("an auditor is offered verifying the store")
	}
	if w := postForm(t, srv, "/security/verify", token, ""); w.Code != http.StatusForbidden {
		t.Errorf("an auditor verified the store: %d", w.Code)
	}
}

// A reader over the whole site reads pages, not the audit log or the
// posture: the guarded areas need administrator over the site.
func TestAReaderOverTheSiteDoesNotReadTheLogOrThePosture(t *testing.T) {
	srv, token := asRole(t, auth.RoleReader)
	for _, path := range []string{"/logs", "/security", "/security/frameworks", "/security/integrity"} {
		if w := get(t, srv, path, token); w.Code == http.StatusOK {
			t.Errorf("a reader opened %s", path)
		}
	}
}

// An auditor's access has to end: the People screen will not grant it for ever.
func TestTheAuditorJobIsOnlyGrantedUntilADay(t *testing.T) {
	srv, token := setup(t)
	postForm(t, srv, "/people/grant", token, "new_principal=assessor&role=job%3Aauditor")
	if srv.Policy.Evaluate("assessor", auth.ActView, auth.AreaLog).Allowed {
		t.Fatal("an auditor was granted with no end")
	}
	day := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	postForm(t, srv, "/people/grant", token, "new_principal=assessor&role=job%3Aauditor&until="+day)
	if !srv.Policy.Evaluate("assessor", auth.ActView, auth.AreaLog).Allowed {
		t.Error("an auditor with an end day was not granted")
	}
}

// A permission is granted from the People screen like a role, shown as a
// permission, and removed the same way.
func TestAPermissionIsGrantedAndRemovedOnThePeopleScreen(t *testing.T) {
	srv, token := setup(t)
	w := postForm(t, srv, "/people/grant", token, "principal=ria&role=permission:approve&resource=/@agents/newsletter")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !srv.Policy.Evaluate("ria", auth.ActApprove, auth.AgentResource("newsletter")).Allowed ||
		srv.Policy.Evaluate("ria", auth.ActView, "/").Allowed {
		t.Fatal("the grant was not one permission on one agent")
	}
	body := get(t, srv, "/people", token).Body.String()
	if !strings.Contains(body, `approve <span class="hint">permission</span>`) || !strings.Contains(body, "<code>/@agents/newsletter</code>") ||
		!strings.Contains(body, "permission:install-features") {
		t.Errorf("the screen does not show or offer permissions")
	}
	postForm(t, srv, "/people/grant", token, "principal=ria&role=permission:fly&resource=/")
	if srv.Policy.Evaluate("ria", auth.ActInstall, "/").Allowed {
		t.Error("a made-up permission granted something")
	}
	postForm(t, srv, "/people/revoke", token, "principal=ria&role=approve&resource=/@agents/newsletter")
	if srv.Policy.Evaluate("ria", auth.ActApprove, auth.AgentResource("newsletter")).Allowed {
		t.Error("the permission was not removed")
	}
}

// A permission granted alone works through the person's own session, whose
// credential carries only their role; an administrator's credential capped
// to reader does not gain what their role gives.
func TestAPermissionWorksThroughThePersonsOwnSession(t *testing.T) {
	srv, _ := setup(t)
	srv.Policy.Grant(auth.Binding{Principal: "ria", Role: auth.RoleReader, Resource: "/"})
	srv.Policy.Grant(auth.Binding{Principal: "ria", Permission: auth.ActInstall, Resource: "/"})
	tok, _, err := srv.Tokens.Issue("ria", "ria", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/make", tok); w.Code == http.StatusForbidden {
		t.Errorf("install-features did not open Make: %d", w.Code)
	}
	if w := get(t, srv, "/people", tok); w.Code != http.StatusForbidden {
		t.Errorf("install-features opened People: %d", w.Code)
	}
	capped, _, err := srv.Tokens.Issue("capped", "editor", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/make", capped); w.Code != http.StatusForbidden {
		t.Errorf("an administrator's reader credential opened Make: %d", w.Code)
	}
}

// The Data screen shows somebody granted one collection that collection,
// and refuses their writes to another; it is in their menu.
func TestTheDataScreenShowsOnlyTheCollectionsGranted(t *testing.T) {
	srv, _ := setup(t)
	tree := ""
	for _, c := range []string{"samples", "payroll"} {
		next, _, err := collection.Put(srv.Store, tree, c, collection.Record{ID: strings.Repeat("b", 32),
			Fields: map[string]any{"name": c}}, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tree = next
	}
	var wrote []string
	srv.Data = &Data{Tree: func() (string, error) { return tree, nil },
		Commit: func(next, msg, by string) error { wrote = append(wrote, msg); return nil }}
	srv.Policy.Grant(auth.Binding{Principal: "tech", Role: auth.RoleAuthor, Resource: auth.DataResource("samples")})
	tok, _, err := srv.Tokens.Issue("tech", "tech", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, srv, "/records", tok).Body.String()
	if !strings.Contains(body, "samples") || strings.Contains(body, "payroll") || !strings.Contains(body, `href="/records"`) {
		t.Errorf("the Data screen shows the wrong collections")
	}
	if get(t, srv, "/records?c=payroll", tok).Body.String() == "" {
		t.Fatal("no answer")
	}
	if w := postForm(t, srv, "/records/save", tok, "collection=payroll&fields=%7B%22name%22%3A%22x%22%7D"); w.Code != http.StatusForbidden {
		t.Errorf("a write to another collection answered %d", w.Code)
	}
	if w := postForm(t, srv, "/records/save", tok, "collection=samples&fields=%7B%22name%22%3A%22x%22%7D"); w.Code == http.StatusForbidden {
		t.Errorf("a write to the granted collection was refused")
	}
}
