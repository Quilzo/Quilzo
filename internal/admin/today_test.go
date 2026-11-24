// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/connect"
)

// Today lists what waits first, what cannot be taken back before what
// only reads, and then counts what is happening, each figure a link to
// the records it counts.
func TestTodayPutsWhatWaitsFirstAndLinksEveryFigure(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	now := time.Now()
	read := agent.Action{Op: "read_page", Input: map[string]any{"page": "x"}}
	waitingRun(st, "run-20261014-000000c1", "librarian", read, "it asks first", now.Add(-time.Hour))
	pay := agent.Action{Op: "browser_click", Input: map[string]any{"ref": "e9"}}
	waitingRun(st, "run-20261014-000000c2", "buyer", pay,
		`it presses button "Pay now" on shop.example.com, and it is called "Pay now"`, now)
	st.runs["run-20261014-000000c3"] = agent.Keep("run-20261014-000000c3", "dana", "m", now,
		agent.Trace{Agent: "tidy", Goal: "tidy", Complete: true}, agent.Receipt{Did: 1})
	st.runs["run-20261014-000000c4"] = agent.Keep("run-20261014-000000c4", "dana", "m", now.Add(-48*time.Hour),
		agent.Trace{Agent: "tidy", Goal: "tidy", Complete: true}, agent.Receipt{Did: 1})

	body := get(t, srv, "/today", token).Body.String()
	whole(t, body)
	buyer, librarian := strings.Index(body, ">buyer<"), strings.Index(body, ">librarian<")
	if buyer < 0 || librarian < 0 || buyer > librarian {
		t.Errorf("a payment waiting is not listed before a read that waited longer (%d, %d)", buyer, librarian)
	}
	if !strings.Contains(body, `<dt>Agent run finished in the last day</dt><dd><a href="/agents">1</a></dd>`) {
		t.Errorf("the finished run is not counted once, as a link:\n%s", firstLines(body[strings.Index(body, "happening"):], 8))
	}
	if !strings.Contains(body, `href="/today"`) {
		t.Error("Today is not in the menu")
	}
}

// Somebody whose work is one area sees Today, and no figure for a screen
// they cannot open.
func TestTodayCountsOnlyWhatSomebodyCanOpen(t *testing.T) {
	srv, token := asJob(t, "analyst")
	w := get(t, srv, "/today", token)
	if w.Code != http.StatusOK {
		t.Fatalf("an analyst cannot open Today: %d", w.Code)
	}
	body := w.Body.String()
	whole(t, body)
	for _, never := range []string{"Agent run", "changed in the draft", "Visitors waiting"} {
		if strings.Contains(body, never) {
			t.Errorf("an analyst is shown %q", never)
		}
	}
	if !strings.Contains(body, `href="/today"`) {
		t.Error("Today is not in an analyst's menu")
	}
}

// Somebody chooses where a sign-in lands, and can choose again.
func TestWhereSomebodyStartsIsTheirChoice(t *testing.T) {
	srv, token := setup(t)
	w := postForm(t, srv, "/today/start", token, url.Values{"to": {"pages"}}.Encode())
	var set *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == StartCookie {
			set = c
		}
	}
	if w.Code != http.StatusSeeOther || set == nil || set.Value != "pages" || !set.HttpOnly {
		t.Fatalf("%d %+v", w.Code, set)
	}
	r := requestFor(t, "/today")
	r.AddCookie(set)
	if startPath(r) != "/" {
		t.Error("choosing Pages did not move the start")
	}
	w = postForm(t, srv, "/today/start", token, url.Values{"to": {"today"}}.Encode())
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == StartCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("choosing Today again did not clear the choice")
	}
	if w := postForm(t, srv, "/today/start", token, "to=elsewhere"); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown start answered %d", w.Code)
	}
}

func requestFor(t *testing.T, path string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Every way to start something on Today lands where it is done. The
// buttons say what they do, "Upload a picture" and "Add a feature", and
// opened the top of Media, Make and Chatbots: a screen with another name,
// and on Make the form for a feature five sections down. Each now lands
// on the part of its screen that does it, as Write a page always did, or
// opens a screen whose name its own begins with.
func TestEveryStartLandsWhereItIsDone(t *testing.T) {
	srv, token := fullyWired(t)
	wireFeatures(srv)
	srv.Assistants = (&fakeAssistants{set: &assistant.Set{}}).wire()
	starts := startsOnToday(t, srv, token)
	if starts == nil {
		t.Fatal("Today shows no way to start something")
	}
	for _, m := range starts {
		landsWhereItIsDone(t, srv, token, m[0], m[1])
	}
	if len(starts) < 5 {
		t.Fatalf("only %d ways to start something", len(starts))
	}
}

// Today counts the person's own connections that stop working within a
// week, or have stopped, as a link to Your accounts; one whose end is not
// known, or is further off, is not counted.
func TestTodayListsConnectionsExpiringWithinAWeek(t *testing.T) {
	srv, token := setup(t)
	now := time.Now().UTC()
	var asked []string
	srv.Connections = &Connections{
		Providers: func() ([]connect.Provider, error) { return nil, nil },
		Mine: func(person string) ([]ConnectedAccount, error) {
			asked = append(asked, person)
			return []ConnectedAccount{
				{Provider: "instagram", Expires: connect.Ends{Access: now.Add(3 * 24 * time.Hour)}},
				{Provider: "linkedin", Expires: connect.Ends{Access: now.Add(time.Hour), Refresh: now.Add(6 * 24 * time.Hour), Renews: true}},
				{Provider: "lapsed", Expires: connect.Ends{Access: now.Add(-time.Hour)}},
				{Provider: "google", Expires: connect.Ends{Access: now.Add(time.Hour), Renews: true}},
				{Provider: "far", Expires: connect.Ends{Access: now.Add(30 * 24 * time.Hour)}},
				{Provider: "old"},
			}, nil
		},
	}
	body := get(t, srv, "/today", token).Body.String()
	whole(t, body)
	if !strings.Contains(body, `<dt>Connected accounts to connect again within a week</dt><dd><a href="/connections">3</a></dd>`) {
		t.Errorf("the connections ending soon are not counted as a link:\n%s", firstLines(body[strings.Index(body, "happening"):], 12))
	}
	if len(asked) == 0 || asked[0] != "editor" {
		t.Errorf("asked about %v", asked)
	}
}

// Today offers somebody only the ways to start something they can do.
//
// They were offered to whoever could open the screen each lands on. A
// reader was given Write a page, which landed on Pages with no New page
// box, Upload a picture, on Media with no file to choose, and Review and
// publish, on a screen that said they could review but not publish; an
// author was given Review and publish, and Add a chatbot, on a screen with
// no form for one. Where a store asks for approval, an author is offered
// what they can do instead: offering the draft for review.
func TestTodayOffersOnlyWhatSomebodyCanDo(t *testing.T) {
	for _, c := range []struct {
		role     auth.Role
		approval bool
		want     []string
	}{
		{auth.RoleReader, false, nil},
		{auth.RoleReader, true, nil},
		{auth.RoleAuthor, false, []string{"Write a page", "Upload a picture"}},
		{auth.RoleAuthor, true, []string{"Write a page", "Upload a picture", "Offer for review"}},
		{auth.RolePublisher, false, []string{"Write a page", "Upload a picture", "Add a chatbot", "Review and publish"}},
		{auth.RoleAdmin, false, []string{"Write a page", "Upload a picture", "Add a feature", "Add a chatbot", "Review and publish"}},
	} {
		t.Run(fmt.Sprintf("%s/approval=%v", c.role, c.approval), func(t *testing.T) {
			srv, token := asRole(t, c.role)
			wireFeatures(srv)
			srv.Assistants = (&fakeAssistants{set: &assistant.Set{}}).wire()
			if c.approval {
				srv.Approvals = &Approvals{
					Policy:  func() (collab.Policy, error) { return collab.Policy{Required: 1}, nil },
					Current: func() (*collab.Proposal, error) { return nil, nil },
					Save:    func(*collab.Proposal) error { return nil },
				}
			}
			var got []string
			for _, m := range startsOnToday(t, srv, token) {
				got = append(got, m[0])
				landsWhereItIsDone(t, srv, token, m[0], m[1])
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("somebody with the %s role is offered %q, not %q", c.role, got, c.want)
			}
		})
	}
}

// startsOnToday is each way to start something Today offers, as its label
// and where it goes.
func startsOnToday(t *testing.T, srv *Server, token string) [][2]string {
	t.Helper()
	body := get(t, srv, "/today", token).Body.String()
	whole(t, body)
	nav := regexp.MustCompile(`(?s)<nav class="glance-starts"[^>]*>(.*?)</nav>`).FindStringSubmatch(body)
	if nav == nil {
		return nil
	}
	var out [][2]string
	for _, m := range regexp.MustCompile(`<a [^>]*href="([^"]+)"[^>]*>([^<]+)</a>`).FindAllStringSubmatch(nav[1], -1) {
		out = append(out, [2]string{html.UnescapeString(m[2]), html.UnescapeString(m[1])})
	}
	return out
}

// landsWhereItIsDone checks that a way to start something goes to the part
// of a screen that does it, for the person it was offered to: the place it
// names is on the screen they are shown, or the screen is called what the
// button begins with, and a button that says it publishes lands where they
// can.
func landsWhereItIsDone(t *testing.T, srv *Server, token, label, href string) {
	t.Helper()
	path, frag, _ := strings.Cut(href, "#")
	w := get(t, srv, path, token)
	if w.Code != http.StatusOK {
		t.Errorf("%q goes to %s, which answered %d", label, path, w.Code)
		return
	}
	page := w.Body.String()
	if strings.Contains(label, "publish") && !strings.Contains(page, `action="/publish"`) {
		t.Errorf("%q goes to %s, which offers no way to publish", label, path)
	}
	if frag != "" {
		if !strings.Contains(page, `id="`+frag+`"`) {
			t.Errorf("%q goes to #%s, which %s does not have", label, frag, path)
		}
		return
	}
	h1 := ""
	if h := regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`).FindStringSubmatch(page); h != nil {
		h1 = strings.TrimSpace(h[1])
	}
	if h1 == "" || !strings.HasPrefix(label, h1) {
		t.Errorf("%q opens the top of a screen called %q", label, h1)
	}
}

// Today offers to start on Pages only to somebody who may open Pages, and
// always the way back to starting on Today.
//
// It offered "Open Pages first when I sign in" to everybody who signs in,
// so the approver, on the screen the front door now sends them to, could
// choose to start on a screen that refuses them: the front door went on
// sending them to Approvals, and the way up on every screen became a link
// called Pages that went there too.
func TestTodayOffersStartingOnPagesOnlyToWhoMayOpenIt(t *testing.T) {
	srv, _ := setup(t)
	for _, b := range []auth.Binding{
		{Principal: "aria", Permission: auth.ActApprove, Resource: "/"},
		{Principal: "rita", Role: auth.RoleReader, Resource: "/"},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	today := func(name, cookie string) string {
		t.Helper()
		tok, _, err := srv.Tokens.IssueSession("passkey:"+name, name, srv.roleFor(name), "/", time.Hour,
			auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/today", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: StartCookie, Value: cookie})
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s opened Today and was answered %d", name, w.Code)
		}
		return w.Body.String()
	}
	const pagesFirst, todayFirst = "Open Pages first when I sign in", "Open Today first when I sign in"

	if body := today("aria", ""); strings.Contains(body, pagesFirst) {
		t.Error("the approver, who may not open Pages, is offered to start there")
	}
	if body := today("rita", ""); !strings.Contains(body, pagesFirst) {
		t.Error("a reader is no longer offered to start on Pages")
	}
	// Chosen before, or by somebody who could then: the way back stays.
	for _, name := range []string{"aria", "rita"} {
		if body := today(name, "pages"); !strings.Contains(body, todayFirst) {
			t.Errorf("%s, starting on Pages, is not offered the way back to Today", name)
		}
	}
}
