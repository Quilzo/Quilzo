// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/shield"
)

// wireShield gives a test server a shield in a fresh store, and a second
// administrator, lee, to approve what the first proposes.
func wireShield(t *testing.T, srv *Server) (root, second string) {
	t.Helper()
	root = t.TempDir()
	srv.ShieldAdmin = &ShieldAdmin{Root: root,
		History: func(int) ([]shield.Signal, error) {
			var out []shield.Signal
			for i := 0; i < 3; i++ {
				out = append(out, shield.Signal{Name: "chatbot-injection", Handle: "p_0123456789abcdef0123456789abcdef",
					At: time.Now().Add(-time.Hour + time.Duration(i)*time.Minute)})
			}
			return out, nil
		}}
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return root, secret
}

func TestTheShieldScreenShowsWhatIsInForceAndLiftsIt(t *testing.T) {
	srv, token := setup(t)
	root, _ := wireShield(t, srv)
	page := getPage(t, srv, "/security/shield", token)
	for _, want := range []string{"Nothing in force", "Prompt injection against a chatbot", "Acts", "Watches",
		"Try on the last 30 days", "Protect by hand", "Hold every playbook"} {
		if !strings.Contains(page, want) {
			t.Errorf("the screen lacks %q", want)
		}
	}
	w := postForm(t, srv, "/security/shield/act", token, url.Values{"do": {"apply"}, "kind": {"block"},
		"target": {"203.0.113.0/24"}, "where": {"site"}, "for": {"1h"}, "reason": {"probing"}}.Encode())
	if w.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	st, _ := shield.Load(root)
	if len(st.Protections) != 1 || st.Protections[0].By != "editor" || st.Protections[0].Auto {
		t.Fatalf("%+v", st.Protections)
	}
	page = getPage(t, srv, "/security/shield", token)
	if !strings.Contains(page, "Blocked the network 203.0.113.0/24 on the site") || !strings.Contains(page, "1 in force") {
		t.Fatalf("not shown in force")
	}
	postForm(t, srv, "/security/shield/act", token, "do=lift&id="+st.Protections[0].ID)
	st, _ = shield.Load(root)
	if len(st.Active(time.Now())) != 0 {
		t.Fatal("not lifted")
	}
}

func TestAPlaybookChangeOnTheScreenTakesASecondAdministrator(t *testing.T) {
	srv, token := setup(t)
	root, lee := wireShield(t, srv)
	postForm(t, srv, "/security/shield/act", token, "do=mode&name=chatbot-flood&mode=act&why=seen+it+work")
	bk, _ := shield.LoadBook(root)
	if len(bk.Pending) != 1 {
		t.Fatalf("not proposed: %+v", bk.Pending)
	}
	id := bk.Pending[0].ID
	// The proposer is offered no approve button, and approving anyway fails.
	if page := getPage(t, srv, "/security/shield", token); strings.Contains(page, `value="approve"`) {
		t.Fatal("the proposer was offered approval")
	}
	postForm(t, srv, "/security/shield/act", token, "do=approve&id="+id)
	if bk, _ := shield.LoadBook(root); len(bk.Pending) != 1 {
		t.Fatal("approved by the person who proposed it")
	}
	if page := getPage(t, srv, "/security/shield", lee); !strings.Contains(page, `value="approve"`) {
		t.Fatal("the second administrator was not offered approval")
	}
	postForm(t, srv, "/security/shield/act", lee, "do=approve&id="+id)
	bk, _ = shield.LoadBook(root)
	for _, pb := range bk.InForce() {
		if pb.Name == "chatbot-flood" && pb.Mode != "act" {
			t.Fatalf("not applied: %s", pb.Mode)
		}
	}
}

func TestHoldingTakesOneAndLettingThemActTakesTwoOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	root, lee := wireShield(t, srv)
	postForm(t, srv, "/security/shield/act", token, "do=hold&why=a+block+looked+wrong")
	if st, _ := shield.Load(root); st.Watching == nil || st.Watching.By != "editor" {
		t.Fatal("not held")
	}
	if page := getPage(t, srv, "/security/shield", token); !strings.Contains(page, "Held to watching") {
		t.Fatal("the screen does not say so")
	}
	postForm(t, srv, "/security/shield/act", token, "do=release&why=fixed")
	bk, _ := shield.LoadBook(root)
	if len(bk.Pending) != 1 || !bk.Pending[0].Release {
		t.Fatal("release not proposed")
	}
	postForm(t, srv, "/security/shield/act", lee, "do=approve&id="+bk.Pending[0].ID)
	if st, _ := shield.Load(root); st.Watching != nil {
		t.Fatal("still held")
	}
}

func TestADecoyIsShownOnceAndNeverInARedirect(t *testing.T) {
	srv, token := setup(t)
	root, _ := wireShield(t, srv)
	w := postForm(t, srv, "/security/shield/act", token, "do=decoy-add&where=the+deploy+job")
	body := w.Body.String()
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(body, "qz_") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	st, _ := shield.Load(root)
	if len(st.Decoys) != 1 || strings.Contains(body, st.Decoys[0].Hash) {
		t.Fatal("not kept, or kept as more than a hash")
	}
	if page := getPage(t, srv, "/security/shield", token); strings.Contains(page, "qz_") {
		t.Fatal("the decoy is on the screen again")
	}
}

func TestAnAnalystReadsTheShieldAndCannotChangeIt(t *testing.T) {
	srv, token := asJob(t, "analyst")
	root, _ := wireShield(t, srv)
	page := getPage(t, srv, "/security/shield", token)
	if !strings.Contains(page, "Prompt injection against a chatbot") || strings.Contains(page, "Protect by hand") {
		t.Fatal("an analyst's page")
	}
	for _, body := range []string{"do=hold&why=x", "do=apply&kind=freeze&for=1h&reason=x",
		"do=decoy-add&where=x", "do=trust-add&network=198.51.100.0/24", "do=mode&name=chatbot-flood&mode=act&why=x"} {
		postForm(t, srv, "/security/shield/act", token, body)
	}
	st, _ := shield.Load(root)
	bk, _ := shield.LoadBook(root)
	if st.Watching != nil || len(st.Protections) != 0 || len(st.Decoys) != 0 || len(st.Trusted) != 0 || len(bk.Pending) != 0 {
		t.Fatalf("an analyst changed the shield: %+v %+v", st, bk)
	}
}

func TestTryingAPlaybookOnTheHistoryAppliesNothing(t *testing.T) {
	srv, token := setup(t)
	root, _ := wireShield(t, srv)
	page := getPage(t, srv, "/security/shield?try=chatbot-injection", token)
	if !strings.Contains(page, "What they would have done") || !strings.Contains(page, "would have responded 1 time") {
		t.Fatalf("no dry run shown")
	}
	if st, _ := shield.Load(root); len(st.Protections) != 0 || len(st.Responses) != 0 {
		t.Fatal("a dry run applied something")
	}
}

func TestALockdownNobodyCanGetPastIsRefusedOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	root, _ := wireShield(t, srv)
	postForm(t, srv, "/security/shield/act", token, "do=apply&kind=lockdown&for=1h&reason=x")
	if st, _ := shield.Load(root); len(st.Protections) != 0 {
		t.Fatal("locked everybody out from the screen")
	}
	srv.ShieldAdmin.CanLockdown = func() bool { return true }
	postForm(t, srv, "/security/shield/act", token, "do=apply&kind=lockdown&for=1h&reason=x")
	if st, _ := shield.Load(root); len(st.Protections) != 1 {
		t.Fatal("not locked down when somebody can get past it")
	}
}

func TestTheAdminNamesWhereViolationsGoAndTakesThemWithoutACookie(t *testing.T) {
	srv, token := setup(t)
	var got []public.Violation
	srv.Reports = public.ReportsHandler(func(v public.Violation, r *http.Request) { got = append(got, v) })
	w := get(t, srv, "/security/shield", token)
	if w.Header().Get("Reporting-Endpoints") == "" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "report-to csp") {
		t.Fatalf("headers %v", w.Header())
	}
	// A report arrives with no credential and no Sec-Fetch-Site, as
	// browsers send them; it is taken, and answered 204.
	req := httptest.NewRequest(http.MethodPost, "http://admin.example/.quilzo/reports",
		strings.NewReader(`{"csp-report":{"document-uri":"http://admin.example/pages","blocked-uri":"https://evil.example/x.js","effective-directive":"script-src-elem"}}`))
	req.Header.Set("Content-Type", "application/csp-report")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || len(got) != 1 || got[0].Blocked != "https://evil.example" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
}

// A palette below 4.5:1 is refused by the browser's publish as by the
// command line's; before, `theme set --force` said the gate would refuse it
// and the browser published it.
func TestPublishingFromTheBrowserChecksTheThemesContrast(t *testing.T) {
	srv, _ := setup(t)
	designFake(srv, map[string]string{"on-surface": "#bbbbbb", "surface": "#ffffff"})
	got := srv.themeBlockers()
	if len(got) == 0 {
		t.Fatal("light grey text on white passed")
	}
	designFake(srv, map[string]string{})
	if got := srv.themeBlockers(); len(got) != 0 {
		t.Fatalf("the shipped palette was refused: %+v", got)
	}
	srv.DesignSet.OwnStylesheet = func() bool { return true }
	designFake(srv, map[string]string{"on-surface": "#bbbbbb"})
	srv.DesignSet.OwnStylesheet = func() bool { return true }
	if got := srv.themeBlockers(); len(got) != 0 {
		t.Fatal("a hand-written stylesheet was judged by tokens it does not use")
	}
}
