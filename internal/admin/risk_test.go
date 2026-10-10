// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// riskEstate is a register where one person has three medium findings from
// three rules under two identifiers, and somebody else has one high one.
func riskEstate(t *testing.T, srv *Server) {
	t.Helper()
	mk := func(issuer, who, rule, title string, sev telemetry.Severity) finding.Finding {
		f := detectionFinding(who, "evidence", sev)
		f.Entity = telemetry.ID{Issuer: issuer, Value: who}
		f.Source, f.Title = rule, title
		f.First = time.Now().UTC().Add(-time.Hour)
		return f
	}
	med, high := telemetry.SeverityMedium, telemetry.SeverityHigh
	srv.Findings = newFakeRegister(
		mk("okta", "00u1", "okta.api-token-created", "An API token was created", med),
		mk("okta", "00u1", "okta.signin-through-proxy", "A sign-in through a proxy", high),
		mk("github", "dana-gh", "github.deploy-key-added", `A deploy key <script>alert(1)</script>`, high),
		mk("okta", "00u2", "okta.mfa-reset", "A factor was reset", high),
		// One critical finding by itself: high risk, and still one finding.
		mk("okta", "00u3", "okta.policy-weakened", "A policy was switched off",
			telemetry.SeverityCritical),
	).wire()
	srv.People = func() map[string]string {
		return map[string]string{"okta:00u1": "dana@acme.com",
			"github:dana-gh": "dana@acme.com"}
	}
}

func TestRiskIsOneRowPerPersonWithTheFindingsItIsMadeOf(t *testing.T) {
	srv, token := setup(t)
	riskEstate(t, srv)
	kept := wireCases(srv)
	body := get(t, srv, "/security/risk", token).Body.String()
	whole(t, body)
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("a finding's title reached the page as markup")
	}
	dana, other := strings.Index(body, "<code>dana@acme.com</code>"),
		strings.Index(body, "<code>okta:00u2</code>")
	if dana < 0 || other < 0 || dana > other {
		t.Fatalf("the person with three findings is not above the one with one (%d, %d)", dana, other)
	}
	for _, want := range []string{"3 findings worth 95", "3 different rules",
		"github:dana-gh", "okta:00u1", `href="/security/entity/person:dana@acme.com"`,
		"These look like one thing", "An account somebody else is using"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// One finding is not offered as an incident.
	if strings.Count(body, "These look like one thing") != 1 {
		t.Error("a single finding was offered as an incident")
	}

	// Declared from here it gathers all three and proposes the playbook.
	q, _, _ := srv.Findings.Queue(time.Now().UTC())
	form := url.Values{"do": {"declare"}, "title": {"3 findings about dana"},
		"grade": {"sev3"}, "playbook": {"account-compromise"}}
	for _, f := range q {
		if f.Entity.Value != "00u2" && f.Entity.Value != "00u3" {
			form.Add("finding", f.ID)
		}
	}
	w := postForm(t, srv, "/security/cases/act", token, form.Encode())
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "m=") {
		t.Fatalf("declare: %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(kept) != 1 {
		t.Fatalf("%d incidents", len(kept))
	}
	for _, i := range kept {
		if len(i.Findings) != 3 || len(i.Runs) != 1 || i.Runs[0].Approved != nil ||
			strings.Join(i.Regimes, ",") != "eu" {
			t.Errorf("findings %d, runs %+v, regimes %v", len(i.Findings), i.Runs, i.Regimes)
		}
	}
	// Gathered, they are not offered again.
	body = get(t, srv, "/security/risk", token).Body.String()
	if strings.Contains(body, "These look like one thing") {
		t.Error("findings an incident already gathers were offered again")
	}
	if !strings.Contains(body, `href="/security/case/inc-`) {
		t.Error("the rows do not say which incident gathers them")
	}
}

func TestAPersonsPageGathersEveryIdentifierTheyAreKnownBy(t *testing.T) {
	srv, token := setup(t)
	riskEstate(t, srv)
	body := get(t, srv, "/security/entity/person:dana@acme.com", token).Body.String()
	whole(t, body)
	for _, want := range []string{"An API token was created",
		"A sign-in through a proxy", "A deploy key", "this page is all of them together",
		`href="/security/entity/github:dana-gh"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the person's page lacks %q", want)
		}
	}
	if strings.Contains(body, "A factor was reset") {
		t.Error("somebody else's finding is on the person's page")
	}
	one := get(t, srv, "/security/entity/github:dana-gh", token).Body.String()
	if !strings.Contains(one, `href="/security/entity/person:dana@acme.com"`) ||
		strings.Contains(one, "An API token was created") {
		t.Error("an identifier's page does not say whose it is, or shows " +
			"the other identifier's findings as its own")
	}
	stranger := get(t, srv, "/security/entity/person:nobody@acme.com", token).Body.String()
	if !strings.Contains(stranger, "Nothing here names it") {
		t.Error("an unknown person was shown something")
	}
}

func TestOnlyAnAdministratorSeesRisk(t *testing.T) {
	srv, _ := setup(t)
	riskEstate(t, srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	w := get(t, srv, "/security/risk", secret)
	if w.Code == 200 || strings.Contains(w.Body.String(), "dana@acme.com") {
		t.Errorf("an author read the risk list: %d", w.Code)
	}
}
