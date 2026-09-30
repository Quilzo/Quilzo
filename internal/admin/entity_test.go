// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/incident"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/vuln"
)

// entityEstate is a store where okta:dana has a finding, an incident about
// it, a hundred and one sign-ins, and okta:sam has one of each of his own.
func entityEstate(t *testing.T, srv *Server) (viewed *[]map[string]string) {
	t.Helper()
	mine := detectionFinding("dana", "sign-in failed", telemetry.SeverityHigh)
	other := detectionFinding("sam", "sign-in failed", telemetry.SeverityLow)
	other.Title = "Something about somebody else"
	fr := newFakeRegister(mine, other)
	srv.Findings = fr.wire()
	q, _, _ := srv.Findings.Queue(time.Now().UTC())
	var mineID string
	for _, f := range q {
		if f.Entity.Value == "dana" {
			mineID = f.ID
		}
	}
	kept := wireCases(srv)
	i, _ := incident.Declare("inc-20260930-00000a", "Dana's account",
		incident.Sev3, "li", time.Now().UTC())
	i.Findings = []string{mineID}
	kept[i.ID] = i
	j, _ := incident.Declare("inc-20260930-00000b", "Unrelated outage",
		incident.Sev3, "li", time.Now().UTC())
	kept[j.ID] = j

	huntStore(t, srv)
	now := time.Now().UTC()
	adv := vuln.Advisory{ID: "CVE-2026-1001", Summary: "x",
		Known: now.Add(-72 * time.Hour), EPSS: 0.1, EPSSAt: now,
		Affects: []vuln.Range{{Ecosystem: "npm", Package: "left-pad",
			Introduced: "1.0.0", Fixed: "1.3.0"}}}
	inv := []vuln.Component{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.2.0",
			Where: telemetry.ID{Issuer: "okta", Value: "dana"}},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.2.0",
			Where: telemetry.ID{Issuer: "okta", Value: "sam"}}}
	srv.Vulns = &Vulns{Load: func(now time.Time) (VulnView, error) {
		return VulnView{Advisories: []vuln.Advisory{adv}, Components: 2,
			Matched:      vuln.Match([]vuln.Advisory{adv}, inv, nil, now),
			AdvisoriesAt: now, InventoryAt: now}, nil
	}}
	var seen []map[string]string
	srv.Audit = func(action, resource string, d map[string]string) {
		if action == "entity.viewed" {
			seen = append(seen, d)
		}
	}
	return &seen
}

func TestAnEntityPageGathersWhatIsAboutItAndNothingAboutAnybodyElse(t *testing.T) {
	srv, token := setup(t)
	viewed := entityEstate(t, srv)
	body := get(t, srv, "/security/entity/okta:dana", token).Body.String()
	whole(t, body)
	for _, want := range []string{"Failed sign-in to a privileged account",
		"Dana&#39;s account", "101 where it acted", "203.0.113.66",
		"CVE-2026-1001", "okta/system"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, other := range []string{"Something about somebody else",
		"Unrelated outage"} {
		if strings.Contains(body, other) {
			t.Errorf("the page carries %q, which is not about this entity", other)
		}
	}
	// The address used once is above the one used a hundred times.
	if odd, usual := strings.Index(body, "<code>203.0.113.66</code>"),
		strings.Index(body, "<code>198.51.100.7</code>"); odd < 0 || odd > usual {
		t.Error("the addresses are not rarest first")
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("an event's message reached the page as markup")
	}
	if len(*viewed) != 1 || (*viewed)[0]["subject"] != "okta:dana" ||
		(*viewed)[0]["by"] == "" {
		t.Errorf("opening it was recorded as %v", *viewed)
	}

	// The same name under another issuer is another entity.
	elsewhere := get(t, srv, "/security/entity/github:dana", token).Body.String()
	whole(t, elsewhere)
	if !strings.Contains(elsewhere, "Nothing here names it") ||
		strings.Contains(elsewhere, "Failed sign-in") {
		t.Error("github:dana was shown okta:dana's findings")
	}
	if !strings.Contains(elsewhere, "not evidence the entity is clean") {
		t.Error("an empty page reads as a clean one")
	}
	// A bare value matches any issuer, and says that it does.
	bare := get(t, srv, "/security/entity/dana", token).Body.String()
	if !strings.Contains(bare, "under every issuer") ||
		!strings.Contains(bare, "Failed sign-in") {
		t.Error("a bare name did not match, or did not say how it matched")
	}
}

func TestTheLookupLandsOnThePathAndRefusesWhatIsNotAName(t *testing.T) {
	srv, token := setup(t)
	viewed := entityEstate(t, srv)
	form := get(t, srv, "/security/entity/", token)
	whole(t, form.Body.String())
	if !strings.Contains(form.Body.String(), `name="q"`) {
		t.Error("no lookup form")
	}
	w := get(t, srv, "/security/entity/?q=okta%3Adana", token)
	if w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/security/entity/okta:dana" {
		t.Errorf("lookup: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := get(t, srv, "/security/entity/?q=okta%3A", token); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "issuer:value") {
		t.Errorf("an issuer with no value: %d", w.Code)
	}
	if w := get(t, srv, "/security/entity/okta:", token); w.Code != http.StatusNotFound {
		t.Errorf("a name with no value answered %d", w.Code)
	}
	if len(*viewed) != 0 {
		t.Errorf("a lookup that showed nobody was recorded as a view: %v", *viewed)
	}
}

func TestOnlyAnAdministratorOpensAnEntityAndAnAuthorLeavesNoRecord(t *testing.T) {
	srv, _ := setup(t)
	viewed := entityEstate(t, srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	w := get(t, srv, "/security/entity/okta:dana", secret)
	if w.Code == 200 || strings.Contains(w.Body.String(), "Failed sign-in") ||
		strings.Contains(w.Body.String(), "203.0.113") {
		t.Errorf("an author opened an entity: %d", w.Code)
	}
	if len(*viewed) != 0 {
		t.Error("a refused view was recorded as a view")
	}
}

// With no event store the page says so, and still shows the rest.
func TestAnEntityPageWithoutEventsSaysSoAndShowsTheRest(t *testing.T) {
	srv, token := setup(t)
	entityEstate(t, srv)
	srv.Events = &Events{Open: func() (*spool.Spool, func() error, error) {
		return nil, nil, ErrNeverCollected
	}}
	body := get(t, srv, "/security/entity/okta:dana", token).Body.String()
	whole(t, body)
	if !strings.Contains(body, "not the same as this entity having done nothing") ||
		!strings.Contains(body, "Failed sign-in") {
		t.Error("no events was shown as no activity, or hid the findings")
	}
}
