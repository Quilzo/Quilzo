// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/estate"
)

func wfSnapshot(source string, kinds map[string]estate.Kind,
	lines map[string][]estate.Line) estate.Snapshot {
	s := estate.Snapshot{Source: source, At: time.Now().UTC(),
		Endpoints: map[string]estate.EndpointInfo{}}
	for ep, k := range kinds {
		s.Endpoints[ep] = estate.EndpointInfo{Produces: k, Complete: true}
		for _, l := range lines[ep] {
			c := estate.Line{"_source": source, "_endpoint": ep,
				"_produces": string(k)}
			for key, v := range l {
				c[key] = v
			}
			s.Lines = append(s.Lines, c)
		}
	}
	return s
}

// wireWorkforce gives a server an estate with one person at risk, one whose
// name is a script, and one whose tool identifier is awkward to put in a
// path.
func wireWorkforce(srv *Server) {
	seen := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	snaps := []estate.Snapshot{
		wfSnapshot("vanta", map[string]estate.Kind{
			"people": estate.KindPerson, "computers": estate.KindDevice},
			map[string][]estate.Line{
				"people": {
					{"id": "v1", "email": "sam@acme.com", "name": "Sam Okafor",
						"employment": "CURRENT", "training": "OVERDUE"},
					{"id": "v2", "email": "x@acme.com",
						"name": `<script>alert(1)</script>`, "employment": "CURRENT"},
					{"id": "a/b?c=1", "email": "odd@acme.com", "name": "Odd Id",
						"employment": "CURRENT"},
				},
				"computers": {{"id": "c1", "serial": "SAMLAPTOP1",
					"os": "Windows 11", "owner_email": "sam@acme.com",
					"seen": seen, "encryption": "FAIL"}},
			}),
	}
	srv.Workforce = &Workforce{
		Load: func(now time.Time) (*estate.Estate, estate.Outcome, error) {
			e := estate.Build(snaps, nil, now)
			return e, estate.Evaluate(e, now), nil
		},
		History: func() ([]estate.Summary, error) {
			return []estate.Summary{
				{Date: "2026-09-28", Scored: 3, Mean: 20,
					Bands: map[estate.Band]int{estate.BandHigh: 2}},
				{Date: "2026-09-29", Scored: 3, Mean: 12,
					Bands: map[estate.Band]int{estate.BandCritical: 1}},
			}, nil
		},
	}
}

func TestTheWorkforcePagesRenderWhole(t *testing.T) {
	srv, token := setup(t)
	wireWorkforce(srv)
	var audited []map[string]string
	srv.Audit = func(action, resource string, detail map[string]string) {
		if action == "workforce.viewed" {
			audited = append(audited, detail)
		}
	}
	for _, path := range []string{"/workforce", "/workforce/devices",
		"/workforce?band=high", "/workforce/devices?show=partial",
		"/workforce/person/" + url.PathEscape("vanta:v1")} {
		w := get(t, srv, path, token)
		body := w.Body.String()
		if w.Code != 200 {
			t.Errorf("%s: %d", path, w.Code)
		}
		// A template error is written into the page and the rest of it
		// silently dropped, so a 200 alone proves nothing.
		if strings.Contains(body, "render error") ||
			!strings.Contains(body, "</html>") {
			t.Errorf("%s did not render to the end", path)
		}
		if strings.Contains(body, "<script>alert(1)") {
			t.Errorf("%s put a name from a tool into the page as markup", path)
		}
	}
	page := get(t, srv, "/workforce", token).Body.String()
	for _, want := range []string{"Sam Okafor", "People by band",
		"wf-heat", "Show as a table", `href="/workforce/person/vanta:v1"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}
	if len(audited) != 1 || audited[0]["subject"] != "vanta:v1" ||
		audited[0]["by"] == "" {
		t.Errorf("opening a person's page was not logged with who and whom: %v",
			audited)
	}
}

func TestAnAwkwardIdentifierStillReachesItsPerson(t *testing.T) {
	srv, token := setup(t)
	wireWorkforce(srv)
	page := get(t, srv, "/workforce", token).Body.String()
	link := "/workforce/person/" + url.PathEscape("vanta:a/b?c=1")
	if !strings.Contains(page, `href="`+link+`"`) {
		t.Fatalf("the link to an identifier with a slash and a question mark "+
			"is not one path segment: want %s", link)
	}
	w := get(t, srv, link, token)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Odd Id") {
		t.Errorf("%s: %d", link, w.Code)
	}
	if w := get(t, srv, "/workforce/person/vanta:nobody", token); w.Code != 404 {
		t.Errorf("an unknown person answered %d", w.Code)
	}
}

// A score is a file on an employee: an author, or a reader, sees nothing.
func TestOnlyAnAdministratorSeesAnybodysScore(t *testing.T) {
	srv, _ := setup(t)
	wireWorkforce(srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/workforce", "/workforce/devices",
		"/workforce/person/vanta:v1"} {
		w := get(t, srv, path, secret)
		if w.Code == 200 || strings.Contains(w.Body.String(), "Sam Okafor") {
			t.Errorf("an author opened %s: %d", path, w.Code)
		}
	}
}

func TestWithoutTheEstateThePageSaysSoRatherThanShowingNobody(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/workforce", token).Body.String()
	if !strings.Contains(body, "not a workforce with no risk") {
		t.Error("a build without the estate showed an empty page")
	}
}
