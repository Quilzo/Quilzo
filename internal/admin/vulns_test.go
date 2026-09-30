// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/vuln"
)

// wireVulns gives the server three advisories against one library on two
// machines, and keeps what the screen records.
func wireVulns(srv *Server) *[]vuln.Assessment {
	now := time.Now().UTC()
	adv := func(id, fixed, summary string, epss float64) vuln.Advisory {
		return vuln.Advisory{ID: id, Summary: summary,
			Known: now.Add(-72 * time.Hour), CVSS: 7.5, EPSS: epss,
			EPSSAt: now.Add(-time.Hour),
			Affects: []vuln.Range{{Ecosystem: "npm", Package: "left-pad",
				Introduced: "1.0.0", Fixed: fixed}}}
	}
	advs := []vuln.Advisory{
		adv("CVE-2026-1001", "1.2.5", "padding overflows", 0.10),
		adv("CVE-2026-1002", "1.4.0", `<script>alert(1)</script> in a summary`, 0.20),
		adv("CVE-2026-1003", "1.3.1", "quadratic padding", 0.05),
	}
	advs[1].Exploited = []vuln.Attestation{{By: "cisa-kev", At: now}}
	inv := []vuln.Component{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.2.0",
			Where: telemetry.ID{Issuer: "mdm", Value: "LAPTOP-1"}},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.1.0",
			Where: telemetry.ID{Issuer: "mdm", Value: "LAPTOP-2"}},
	}
	said := &[]vuln.Assessment{}
	srv.Vulns = &Vulns{
		Load: func(now time.Time) (VulnView, error) {
			return VulnView{Advisories: advs, Components: len(inv),
				Matched:     vuln.Match(advs, inv, *said, now),
				Assessments: *said, AdvisoriesAt: now.Add(-time.Hour),
				InventoryAt: now.Add(-time.Hour),
				History: []vuln.Tally{
					{At: now.Add(-48 * time.Hour), Vulnerabilities: 5},
					{At: now, Vulnerabilities: 3}}}, nil
		},
		Assess: func(a vuln.Assessment) error {
			if err := a.Validate(); err != nil {
				return err
			}
			*said = append(*said, a)
			return nil
		},
	}
	return said
}

func whole(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "render error") || !strings.Contains(body, "</html>") {
		t.Fatalf("the page did not render to the end:\n%s", firstLines(body, 12))
	}
}

func TestTheWorkbenchLeadsWithTheChangeAndNotTheList(t *testing.T) {
	srv, token := setup(t)
	wireVulns(srv)
	body := get(t, srv, "/security/vulns", token).Body.String()
	whole(t, body)
	plan, queue := strings.Index(body, "What to change"), strings.Index(body, "The queue")
	if plan < 0 || queue < plan {
		t.Error("the upgrades are not above the queue")
	}
	for _, want := range []string{"<code>1.4.0</code>", "1.1.0, 1.2.0",
		`href="/security/vuln/CVE-2026-1002"`, "exploited", "100%",
		"Open vulnerabilities, over time", "<polyline"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The exploited one is first in the queue.
	if a, b := strings.Index(body[queue:], "CVE-2026-1002"),
		strings.Index(body[queue:], "CVE-2026-1001"); a < 0 || a > b {
		t.Error("the exploited vulnerability is not at the top of the queue")
	}
	// The overview does not print advisory text at all.
	if strings.Contains(body, "alert(1)") {
		t.Error("an advisory summary is on the overview")
	}
}

func TestOneVulnerabilityShowsItsWorkingAndEscapesTheAdvisory(t *testing.T) {
	srv, token := setup(t)
	wireVulns(srv)
	body := get(t, srv, "/security/vuln/CVE-2026-1002", token).Body.String()
	whole(t, body)
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("an advisory's summary reached the page as markup")
	}
	for _, want := range []string{"Why it ranks where it does", "Exploited",
		"Probability", "cisa-kev", "mdm:LAPTOP-1", "mdm:LAPTOP-2",
		"At most 14 days", "vulnerable_code_not_in_execute_path"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// One that is not being exploited may be left for longer.
	other := get(t, srv, "/security/vuln/CVE-2026-1001", token).Body.String()
	if !strings.Contains(other, "At most 90 days") {
		t.Error("the ordinary ceiling is not shown")
	}
	if w := get(t, srv, "/security/vuln/CVE-1999-0001", token); w.Code != http.StatusNotFound {
		t.Errorf("an unknown advisory answered %d", w.Code)
	}
}

func TestADecisionOnTheScreenIsAPersonsAndHasItsEdges(t *testing.T) {
	srv, token := setup(t)
	said := wireVulns(srv)
	day := func(n int) string {
		return time.Now().UTC().AddDate(0, 0, n).Format("2006-01-02")
	}
	act := func(v url.Values) (int, string) {
		v.Set("advisory", "CVE-2026-1001")
		v.Set("component", "npm:left-pad")
		w := postForm(t, srv, "/security/vulns/act", token, v.Encode())
		return w.Code, w.Header().Get("Location")
	}
	code, loc := act(url.Values{"do": {"accept"}, "owner": {"sam"},
		"until": {day(30)}, "because": {"replaced in November"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "m=") ||
		!strings.HasPrefix(loc, "/security/vuln/CVE-2026-1001?") {
		t.Fatalf("accept: %d %s", code, loc)
	}
	if len(*said) != 1 || !(*said)[0].Accepted() || (*said)[0].By == "" ||
		(*said)[0].Owner != "sam" {
		t.Fatalf("recorded: %+v", *said)
	}
	body := get(t, srv, "/security/vulns", token).Body.String()
	whole(t, body)
	decided := strings.Index(body, "<h2>Decided</h2>")
	if decided < 0 || !strings.Contains(body[decided:], "CVE-2026-1001") ||
		!strings.Contains(body[decided:], "accepted") {
		t.Error("the accepted vulnerability is not under Decided")
	}
	if q := body[strings.Index(body, "The queue"):decided]; strings.Contains(q, "CVE-2026-1001") {
		t.Error("the accepted vulnerability is still in the queue")
	}

	// The edges: no owner, no date, too long, no reason from the list.
	for name, v := range map[string]url.Values{
		"no owner": {"do": {"accept"}, "until": {day(5)}, "because": {"x"}},
		"no date":  {"do": {"accept"}, "owner": {"sam"}, "because": {"x"}},
		"too long": {"do": {"accept"}, "owner": {"sam"}, "until": {day(200)},
			"because": {"x"}},
		"no reason": {"do": {"not_affected"}, "reason": {"looked fine"},
			"because": {"x"}},
		"no evidence": {"do": {"not_affected"},
			"reason": {"component_not_present"}},
		"long look": {"do": {"investigate"}, "until": {day(40)},
			"because": {"x"}},
	} {
		before := len(*said)
		if _, loc := act(v); !strings.Contains(loc, "e=") || len(*said) != before {
			t.Errorf("%s was recorded (%s)", name, loc)
		}
	}
	if code, _ := act(url.Values{"do": {"dismiss"}}); code != http.StatusBadRequest {
		t.Errorf("an unknown decision answered %d", code)
	}
	// Putting it back is one more statement, and the newest wins.
	if _, loc := act(url.Values{"do": {"reopen"}, "because": {"plan changed"}}); !strings.Contains(loc, "m=") {
		t.Fatalf("reopen: %s", loc)
	}
	body = get(t, srv, "/security/vulns", token).Body.String()
	if q := body[strings.Index(body, "The queue"):strings.Index(body, "<h2>Decided</h2>")]; !strings.Contains(q, "CVE-2026-1001") {
		t.Error("reopened, it is not back in the queue")
	}
	if w := get(t, srv, "/security/vulns/act", token); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET to the action answered %d", w.Code)
	}
}

func TestOnlyAnAdministratorSeesOrDecidesVulnerabilities(t *testing.T) {
	srv, _ := setup(t)
	said := wireVulns(srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/security/vulns", "/security/vuln/CVE-2026-1001"} {
		w := get(t, srv, path, secret)
		if body := w.Body.String(); w.Code == 200 ||
			strings.Contains(body, "LAPTOP") || strings.Contains(body, "left-pad") {
			t.Errorf("an author opened %s: %d", path, w.Code)
		}
	}
	w := postForm(t, srv, "/security/vulns/act", secret, url.Values{
		"do": {"fixed"}, "advisory": {"CVE-2026-1001"},
		"component": {"npm:left-pad"}, "because": {"x"}}.Encode())
	if strings.HasPrefix(w.Header().Get("Location"), "/security/vuln/") {
		t.Error("an author's decision got as far as being considered")
	}
	if len(*said) != 0 {
		t.Error("an author decided a vulnerability does not apply")
	}
}

// Nothing loaded, and a list gone stale, are both said: neither is a clean
// estate.
func TestAnUnloadedOrStaleStoreIsNotShownAsClean(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/security/vulns", token).Body.String()
	whole(t, body)
	if !strings.Contains(body, "without the") || strings.Contains(body, "Nothing is open") {
		t.Error("an unwired store was shown as a clean one")
	}
	srv.Vulns = &Vulns{Load: func(time.Time) (VulnView, error) {
		return VulnView{}, nil
	}}
	body = get(t, srv, "/security/vulns", token).Body.String()
	whole(t, body)
	if !strings.Contains(body, "Nothing has been loaded") ||
		strings.Contains(body, "Nothing is open") {
		t.Error("an empty store was shown as a clean one")
	}
	wireVulns(srv)
	load := srv.Vulns.Load
	srv.Vulns.Load = func(now time.Time) (VulnView, error) {
		v, err := load(now)
		v.AdvisoriesAt = now.Add(-30 * 24 * time.Hour)
		return v, err
	}
	body = get(t, srv, "/security/vulns", token).Body.String()
	if !strings.Contains(body, "Anything published since is not here") {
		t.Error("a month-old advisory list was not called out")
	}
}

// What reading the source established is shown with its limit, and offered
// as grounds for a decision rather than made into one.
func TestAReachResultIsShownAsGroundsAndNotAsAVerdict(t *testing.T) {
	srv, token := setup(t)
	wireVulns(srv)
	load := srv.Vulns.Load
	srv.Vulns.Load = func(now time.Time) (VulnView, error) {
		v, err := load(now)
		v.Matched = vuln.ApplyReach(v.Matched, []vuln.Reach{
			{Advisory: "CVE-2026-1001", Component: "npm:left-pad",
				Where: "mdm:LAPTOP-1", Symbols: 2},
			{Advisory: "CVE-2026-1003", Component: "npm:left-pad",
				Where: "mdm:LAPTOP-1", Referenced: true, Symbols: 1,
				Found: []string{"leftpad.Pad"}, Files: []string{"main.go"}},
		}, now)
		return v, err
	}
	body := get(t, srv, "/security/vuln/CVE-2026-1001", token).Body.String()
	whole(t, body)
	for _, want := range []string{"not named in its source",
		"its dependencies were not read", "In 1 open place(s)",
		"which was not checked"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if !strings.Contains(body, ">open<") {
		t.Error("a place left the queue on a reading of its source")
	}
	used := get(t, srv, "/security/vuln/CVE-2026-1003", token).Body.String()
	if !strings.Contains(used, "leftpad.Pad") || !strings.Contains(used, "main.go") ||
		strings.Contains(used, "open place(s) the asset") {
		t.Error("a symbol the source uses is not shown as used, or was " +
			"offered as grounds for dismissal")
	}
}
