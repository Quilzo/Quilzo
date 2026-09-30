// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/incident"
)

// wireCases keeps incidents in memory, through the same Apply the store
// uses.
func wireCases(srv *Server) map[string]*incident.Incident {
	kept := map[string]*incident.Incident{}
	n := 0
	srv.Cases = &Cases{
		List: func() ([]*incident.Incident, error) {
			var out []*incident.Incident
			for _, i := range kept {
				out = append(out, i)
			}
			return out, nil
		},
		Get: func(id string) (*incident.Incident, error) {
			if i, ok := kept[id]; ok {
				return i, nil
			}
			return nil, fmt.Errorf("no incident %s", id)
		},
		Regimes: func() []string { return []string{"eu"} },
		Declare: func(title string, g incident.Grade, regimes,
			findings []string, by string) (string, error) {
			n++
			id := fmt.Sprintf("inc-20260930-%06x", n)
			i, err := incident.Declare(id, title, g, by, time.Now().UTC(),
				regimes...)
			if err != nil {
				return "", err
			}
			i.Findings = findings
			kept[id] = i
			return id, nil
		},
		Act: func(id, by string, a incident.Action) error {
			i, ok := kept[id]
			if !ok {
				return fmt.Errorf("no incident %s", id)
			}
			return i.Apply(a, by, time.Now().UTC())
		},
	}
	return kept
}

func caseAct(t *testing.T, srv *Server, token string, v url.Values) (int, string) {
	t.Helper()
	w := postForm(t, srv, "/security/cases/act", token, v.Encode())
	return w.Code, w.Header().Get("Location")
}

func TestAnIncidentWithNoDecisionShowsADecisionWaitingAndNotNothingDue(t *testing.T) {
	srv, token := setup(t)
	kept := wireCases(srv)
	list := get(t, srv, "/security/cases?finding=f-42", token).Body.String()
	whole(t, list)
	for _, want := range []string{"No incident has been declared",
		`value="eu" checked`, `value="f-42"`, "not legal advice"} {
		if !strings.Contains(list, want) {
			t.Errorf("the empty list lacks %q", want)
		}
	}
	code, loc := caseAct(t, srv, token, url.Values{"do": {"declare"},
		"title": {`Payroll export <script>alert(1)</script>`},
		"grade": {"sev2"}, "regime": {"eu", "nis2"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/security/case/inc-") {
		t.Fatalf("declare: %d %s", code, loc)
	}
	var id string
	for k := range kept {
		id = k
	}
	body := get(t, srv, "/security/case/"+id, token).Body.String()
	whole(t, body)
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("the title reached the page as markup")
	}
	for _, want := range []string{"2 decision(s) nobody has made",
		"no clock yet", "Nobody is commanding this", "GDPR Article 33",
		"NIS2 early warning", "Record it, as of now"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, ">running<") || strings.Contains(body, ">late<") {
		t.Error("a clock is shown running before anybody started it")
	}
	list = get(t, srv, "/security/cases", token).Body.String()
	if !strings.Contains(list, "with no clock yet") || strings.Contains(list, "none owed") {
		t.Error("the list shows an undecided incident as owing nothing")
	}

	// Decided: the clocks that run from it start, and the others do not.
	if _, loc := caseAct(t, srv, token, url.Values{"do": {"decide"}, "id": {id},
		"trigger": {"aware"}, "text": {"access logs show two downloads"}}); !strings.Contains(loc, "m=") {
		t.Fatalf("decide: %s", loc)
	}
	body = get(t, srv, "/security/case/"+id, token).Body.String()
	for _, want := range []string{">running<", "1 decision(s) nobody has made",
		"access logs show two downloads", "percent of the time allowed"} {
		if !strings.Contains(body, want) {
			t.Errorf("after deciding, the page lacks %q", want)
		}
	}
	// The start of a clock cannot be moved.
	if _, loc := caseAct(t, srv, token, url.Values{"do": {"decide"}, "id": {id},
		"trigger": {"aware"}, "text": {"actually later"}}); !strings.Contains(loc, "e=") {
		t.Error("a clock was started twice")
	}
	// Late is said as late.
	m := kept[id].Moments[incident.Aware]
	m.At = m.At.Add(-100 * time.Hour)
	kept[id].Moments[incident.Aware] = m
	body = get(t, srv, "/security/case/"+id, token).Body.String()
	if !strings.Contains(body, ">late<") || !strings.Contains(body, "Late by") {
		t.Error("a deadline a day past is not shown as late")
	}
	list = get(t, srv, "/security/cases", token).Body.String()
	if !strings.Contains(list, "late by") {
		t.Error("the list does not say a deadline was missed")
	}
}

func TestClosingOnTheScreenIsRefusedOverAnOpenObligation(t *testing.T) {
	srv, token := setup(t)
	kept := wireCases(srv)
	caseAct(t, srv, token, url.Values{"do": {"declare"}, "title": {"x"},
		"grade": {"sev3"}, "regime": {"eu"}})
	var id string
	for k := range kept {
		id = k
	}
	do := func(v url.Values) string {
		v.Set("id", id)
		_, loc := caseAct(t, srv, token, v)
		return loc
	}
	closing := url.Values{"do": {"close"}, "text": {"a public template"},
		"actions": {"deny public ACLs\r\n\r\nreview the other buckets"}}
	if loc := do(closing); !strings.Contains(loc, "e=") ||
		!strings.Contains(loc, "GDPR") {
		t.Fatalf("closed over open obligations: %s", loc)
	}
	for _, v := range []url.Values{
		{"do": {"assign"}, "role": {"commander"}, "who": {"sam"}},
		{"do": {"note"}, "text": {"bucket closed at 10:40"}},
		{"do": {"discharge"}, "regime": {"GDPR Article 33"}, "text": {"sent, ref 881"}},
		{"do": {"waive"}, "regime": {"GDPR Article 34"}, "text": {"no identifiers in the file"}},
		{"do": {"watch"}, "text": {"no access since the policy changed"}},
		{"do": {"reopen"}, "text": {"a second bucket"}},
		closing,
	} {
		if loc := do(v); !strings.Contains(loc, "m=") {
			t.Fatalf("%s: %s", v.Get("do"), loc)
		}
	}
	i := kept[id]
	if i.State != incident.Closed || len(i.Actions) != 2 {
		t.Fatalf("state %s, actions %q", i.State, i.Actions)
	}
	body := get(t, srv, "/security/case/"+id, token).Body.String()
	whole(t, body)
	for _, want := range []string{"Closed.", "review the other buckets",
		"bucket closed at 10:40", "ruled out"} {
		if !strings.Contains(body, want) {
			t.Errorf("the closed page lacks %q", want)
		}
	}
	for _, gone := range []string{"Close it", "Record it, as of now", ">Assign<"} {
		if strings.Contains(body, gone) {
			t.Errorf("a closed incident still offers %q", gone)
		}
	}
	if loc := do(url.Values{"do": {"assign"}, "role": {"scribe"}, "who": {"li"}}); !strings.Contains(loc, "e=") {
		t.Error("a closed incident was changed")
	}
	if code, _ := caseAct(t, srv, token, url.Values{"do": {"erase"}, "id": {id}}); code != http.StatusBadRequest {
		t.Errorf("an unknown action answered %d", code)
	}
	if code, _ := caseAct(t, srv, token, url.Values{"do": {"note"},
		"id": {"../../audit"}, "text": {"x"}}); code != http.StatusBadRequest {
		t.Errorf("a path as an incident answered %d", code)
	}
	if w := get(t, srv, "/security/case/inc-20260930-ffffff", token); w.Code != http.StatusNotFound {
		t.Errorf("an incident that does not exist answered %d", w.Code)
	}
}

func TestOnlyAnAdministratorSeesOrChangesAnIncident(t *testing.T) {
	srv, token := setup(t)
	kept := wireCases(srv)
	caseAct(t, srv, token, url.Values{"do": {"declare"},
		"title": {"Payroll export reachable"}, "grade": {"sev2"}})
	var id string
	for k := range kept {
		id = k
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/security/cases", "/security/case/" + id} {
		w := get(t, srv, path, secret)
		if w.Code == 200 || strings.Contains(w.Body.String(), "Payroll") {
			t.Errorf("an author opened %s: %d", path, w.Code)
		}
	}
	before := len(kept[id].Log)
	_, loc := caseAct(t, srv, secret, url.Values{"do": {"note"}, "id": {id},
		"text": {"nothing to see"}})
	caseAct(t, srv, secret, url.Values{"do": {"declare"}, "title": {"mine"},
		"grade": {"sev4"}})
	if len(kept[id].Log) != before || len(kept) != 1 ||
		strings.HasPrefix(loc, "/security/case/") {
		t.Error("an author wrote to an incident, or declared one")
	}
}
