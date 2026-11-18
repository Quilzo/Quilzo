// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/vault"
)

// What waits for a person is one list, read by the command line, Approvals,
// Today and the assistant's card alike.
//
// It was built twice, once for `quilzo approvals` and once for the admin,
// and the two had drifted. A question asked too long ago to agree to was
// dropped from the command line and shown on the screen. The screen asked
// whether the person might decide a held call, a newsletter issue, an
// install or the change waiting for review, and not whether the session
// might, so a read-only credential, or one confined to /blog or capped at
// reader, was offered all of them and refused each when it tried. The
// command line offered the review to anybody who could edit the draft,
// though approving it takes the publish permission. The same item had a
// different name on each, and the review said it had waited since the
// moment the screen was opened.
//
// These tests build the admin the way `quilzo serve` does, over the same
// store, and ask both for the same person through the same session.

// waitingEverywhere is a store with something waiting from every source:
// a run waiting on a write, a question asked too long ago, a tool call held
// for a second person, an install and a proposed feature, the change to
// the site waiting for two approvals, a newsletter issue an agent proposed,
// and two memories held until somebody confirms them.
func waitingEverywhere(t *testing.T) (root string, s *store.Store, now time.Time) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root = demoStore(t)
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"},
		[2]string{"eve", "author"}, [2]string{"rae", "reader"})
	standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	now = time.Now().UTC()
	if _, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	old, err := runAgentOnce(root, "tidy", "write a page about the shop", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := loadAgentRun(root, old)
	if err != nil || rec.Trace.Waiting == nil {
		t.Fatalf("the second run is not waiting: %v", err)
	}
	rec.Trace.Waiting.Kind = agent.WaitQuestion
	rec.Trace.Waiting.Questions = []agent.Question{{Name: "city", Ask: "Which city is the shop in?", Confidence: 0.4}}
	rec.Trace.Waiting.Since = now.Add(-agent.PendingTTL - time.Hour)
	if err := writeAgentRun(root, rec); err != nil {
		t.Fatal(err)
	}

	if err := saveGatewayState(root, &gatewayState{Held: []heldCall{{ID: "0123456789abcdef",
		Integration: "crm", Tool: "create_contact", Principal: "rae", Client: "desk-app",
		Digest: "d", Args: "{}", Asked: now.Add(-time.Hour)}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, writePackage(t, nil), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if pend, err := pendingFeatures(root); err != nil || len(pend) != 1 {
		t.Fatalf("the install is not waiting: %v %v", pend, err)
	}
	body, err := os.ReadFile(writePackage(t, func(p *feature.Package) { p.Name, p.Title = "lab-notes", "Lab notebook" }))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := proposeFeature(root, body, "a feature an agent wrote", nil, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}

	setStaffConfig(t, root, "review.required_approvals", "2")
	s, err = store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := site.SaveDraft(s, map[string]any{"index": map[string]any{"title": "Crumb, open late"}},
		"open late on Fridays", "sam")
	if err != nil {
		t.Fatal(err)
	}
	if err := saveProposal(root, s, &collab.Proposal{Content: draft, Author: "sam", AuthorKind: "human",
		CreatedAt: now.Add(-3 * time.Hour).Unix(), Message: "open late on Fridays"}); err != nil {
		t.Fatal(err)
	}

	list, err := openNewsletter(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := list.NewIssue("index", "Autumn at the bakery", newsletter.Proposed, "writer",
		"the new loaves, for this month's issue", now); err != nil {
		t.Fatal(err)
	}

	for i, text := range []string{"Dana prefers rye", "Dana's shop opens at nine"} {
		if _, err := memoryStore(root).Remember(memory.Entry{Agent: "tidy", About: "dana", Kind: memory.Episodic,
			Text: text, Run: old, By: "dana", Held: true, Sources: "a page somebody else wrote"},
			24*time.Hour, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	return root, s, now
}

// approvalsScreen is one way of building the admin over the store.
type approvalsScreen struct {
	name string
	srv  *admin.Server
}

// approvalsScreens are the admin as `quilzo serve` builds it, which reads
// the command line's own list, and the same admin without that hook, which
// builds the list by the same rules from the hooks the screens already had.
func approvalsScreens(t *testing.T, root string, s *store.Store) ([]approvalsScreen, *auth.TokenStore) {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	served := hookedAdmin(t, root, s, pol, toks)
	served.Waiting = waitingHook(root, s)
	return []approvalsScreen{{"as quilzo serve builds it", served},
		{"from its own hooks", hookedAdmin(t, root, s, pol, toks)}}, toks
}

// hookedAdmin is the admin with the hooks serve.go gives it that the list
// of what waits reads.
func hookedAdmin(t *testing.T, root string, s *store.Store, pol *auth.Policy, toks *auth.TokenStore) *admin.Server {
	t.Helper()
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	signedIn := sessionCaller
	srv.Memory = memoryAdmin(root)
	srv.Features = featureHooks(root, signedIn)
	srv.Newsletter = newsletterHooks(root, signedIn)
	srv.Approvals = approvalsHooks(root, s)
	srv.Agents = &admin.Agents{
		Load: func() (map[string]agent.Manifest, error) {
			set, err := loadAgents(root)
			if err != nil {
				return nil, err
			}
			return set.Agents, nil
		},
		Runs:   func(name string) ([]agent.Record, error) { return listAgentRuns(root, name, 0) },
		RunGet: func(id string) (agent.Record, error) { return loadAgentRun(root, id) },
		MayApprove: func(rec agent.Record, by admin.Actor) bool {
			return mayApprove(root, signedIn(by), rec) == nil
		},
	}
	srv.Integrations = &admin.Integrations{
		Held: func() ([]admin.GatewayHeld, error) {
			held, err := heldCalls(root, time.Now())
			var out []admin.GatewayHeld
			for _, h := range held {
				out = append(out, admin.GatewayHeld{ID: h.ID, Integration: h.Integration, Tool: h.Tool,
					For: h.Principal, App: h.Client, Args: h.Args, Asked: h.Asked})
			}
			return out, err
		},
		Declared: func() (agent.Integrations, error) {
			set, err := loadIntegrations(root)
			if err != nil {
				return agent.Integrations{}, err
			}
			return *set, nil
		},
	}
	return srv
}

// waitingSession is one person signed in through one kind of credential.
type waitingSession struct {
	name  string
	actor admin.Actor
}

var waitingSessions = []waitingSession{
	{"dana", admin.Actor{Name: "dana", Role: auth.RoleAdmin, Scope: "/"}},
	{"sam", admin.Actor{Name: "sam", Role: auth.RoleAdmin, Scope: "/"}},
	{"dana, read-only", admin.Actor{Name: "dana", Role: auth.RoleAdmin, Scope: "/", Limits: auth.Scope{ReadOnly: true}}},
	{"dana, confined to /blog", admin.Actor{Name: "dana", Role: auth.RoleAdmin, Scope: "/blog"}},
	{"dana, capped at reader", admin.Actor{Name: "dana", Role: auth.RoleReader, Scope: "/"}},
	{"eve, who may edit the draft and not publish", admin.Actor{Name: "eve", Role: auth.RoleAuthor, Scope: "/"}},
	{"rae, a reader", admin.Actor{Name: "rae", Role: auth.RoleReader, Scope: "/"}},
}

// tokenFor signs the session in to the admin.
func tokenFor(t *testing.T, toks *auth.TokenStore, ws waitingSession) string {
	t.Helper()
	secret, tok, err := toks.IssueSession("passkey:"+ws.actor.Name, ws.actor.Name, ws.actor.Role, ws.actor.Scope,
		time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	// A session made from a read-only token carries its limits, as
	// exchanging one for a session does.
	for i := range toks.Tokens {
		if toks.Tokens[i].ID == tok.ID {
			toks.Tokens[i].Scope = ws.actor.Limits
		}
	}
	return secret
}

func adminGet(t *testing.T, srv *admin.Server, path, token string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s answered %d:\n%s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// waitingRow is one row of what waits, as a person reads it.
type waitingRow struct {
	Commits, What, Why string
	Expired            bool
	When               string
}

func (r waitingRow) String() string {
	e := ""
	if r.Expired {
		e = " (asked too long ago)"
	}
	return fmt.Sprintf("%s | %s | %s%s", r.Commits, r.What, r.Why, e)
}

var approvalRow = regexp.MustCompile(`(?s)<th scope="row"><a href="[^"]*">(.*?)</a>(.*?)</th>\s*` +
	`<td><span class="wf-word[^"]*">(.*?)</span>.*?</td>\s*<td>(.*?)</td>\s*<td class="when">(.*?)</td>`)

// screenRows are the rows Approvals shows.
func screenRows(body string) []waitingRow {
	var out []waitingRow
	for _, m := range approvalRow.FindAllStringSubmatch(body, -1) {
		out = append(out, waitingRow{What: html.UnescapeString(m[1]),
			Expired: strings.Contains(m[2], "asked too long ago to agree to"),
			Commits: html.UnescapeString(m[3]), Why: html.UnescapeString(m[4]), When: m[5]})
	}
	return out
}

// lineRows are what the command line lists, as the screen shows them: the
// held memories, a line each on the command line, are one row on the
// screen, which says how many there are and opens the page that decides
// them.
func lineRows(items []waitingItem, now time.Time) []waitingRow {
	var out []waitingRow
	memories := 0
	for _, it := range items {
		if it.Source == "memory" {
			memories++
			continue
		}
		out = append(out, waitingRow{Commits: it.Commits, What: it.What, Why: it.Why,
			Expired: it.Source == "run" && now.Sub(it.Since) > agent.PendingTTL})
	}
	if memories > 0 {
		out = append(out, waitingRow{Commits: "writes",
			What: fmt.Sprintf("Confirm or forget %d held %s", memories, map[bool]string{true: "memory", false: "memories"}[memories == 1]),
			Why:  "learnt after reading somebody else's words, and not recalled until a person confirms it"})
	}
	return out
}

func sortedRows(rows []waitingRow) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.String())
	}
	slices.Sort(out)
	return out
}

// The same store, the same person, the same session: the command line and
// Approvals list the same things, by the same names, with the same reasons,
// and mark the same ones as asked too long ago.
func TestTheCLIAndTheAdminListTheSameWaitingItems(t *testing.T) {
	root, s, now := waitingEverywhere(t)
	screens, toks := approvalsScreens(t, root, s)
	for _, sc := range screens {
		for _, ws := range waitingSessions {
			t.Run(sc.name+"/"+ws.name, func(t *testing.T) {
				items, err := waitingFor(root, sessionCaller(ws.actor), now)
				if err != nil {
					t.Fatal(err)
				}
				line := sortedRows(lineRows(items, now))
				screen := sortedRows(screenRows(adminGet(t, sc.srv, "/approvals", tokenFor(t, toks, ws))))
				if !slices.Equal(line, screen) {
					t.Errorf("the command line lists\n  %s\nand Approvals lists\n  %s",
						strings.Join(line, "\n  "), strings.Join(screen, "\n  "))
				}
			})
		}
	}
}

// Each item is offered to whoever may decide it through the session they
// are using, on both surfaces: a read-only credential decides nothing, the
// change waiting for review is for those who may publish, and a session
// confined to part of the site or capped at a lesser role is offered only
// what it could then do.
func TestTheCLIAndTheAdminShowEachWaitingItemToTheSamePeople(t *testing.T) {
	root, s, now := waitingEverywhere(t)
	screens, toks := approvalsScreens(t, root, s)
	srv := screens[0].srv
	sources := func(rows []waitingRow) map[string]bool {
		out := map[string]bool{}
		for _, r := range rows {
			out[r.What] = true
		}
		return out
	}
	for _, c := range []struct {
		session      waitingSession
		none, review bool
	}{
		{waitingSessions[0], false, true},
		{waitingSessions[2], true, false},
		{waitingSessions[5], true, false},
		{waitingSessions[6], true, false},
	} {
		t.Run(c.session.name, func(t *testing.T) {
			items, err := waitingFor(root, sessionCaller(c.session.actor), now)
			if err != nil {
				t.Fatal(err)
			}
			for surface, rows := range map[string][]waitingRow{
				"the command line": lineRows(items, now),
				"Approvals":        screenRows(adminGet(t, srv, "/approvals", tokenFor(t, toks, c.session))),
			} {
				if c.none && len(rows) > 0 {
					t.Errorf("%s offers %s things to decide that the session could not: %v",
						surface, c.session.name, sortedRows(rows))
				}
				if got := sources(rows)["Approve the change to the site"]; got != c.review {
					t.Errorf("%s offers %s the change waiting for review: %v (%v)", surface, c.session.name, got,
						sortedRows(rows))
				}
			}
		})
	}
}

// A question asked too long ago to agree to is listed, and said to be, on
// the command line as on the screen: it holds its run up until somebody
// clears it, and a list that leaves it out leaves the run waiting unseen.
func TestAnExpiredQuestionIsListedAsExpiredOnTheCommandLineAndTheScreen(t *testing.T) {
	root, s, now := waitingEverywhere(t)
	asOnly(t, root, "sam")
	_, read := captureStdout(t)
	if err := cmdApprovals(root, nil); err != nil {
		t.Fatal(err)
	}
	said := read()
	if !strings.Contains(said, "Which city is the shop in?") || !strings.Contains(said, "asked too long ago to agree to") {
		t.Errorf("quilzo approvals does not list the expired question as expired:\n%s", said)
	}
	screens, toks := approvalsScreens(t, root, s)
	expired := 0
	for _, r := range screenRows(adminGet(t, screens[0].srv, "/approvals", tokenFor(t, toks, waitingSessions[1]))) {
		if r.Expired {
			expired++
			if !strings.Contains(r.What, "Which city is the shop in?") {
				t.Errorf("the screen marks %q as asked too long ago", r.What)
			}
		}
	}
	if expired != 1 {
		t.Errorf("the screen marks %d items as asked too long ago, not 1", expired)
	}
	items, err := waitingFor(root, asAdmin("sam"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Source == "run" && it.Expired && it.Batch != "" {
			t.Errorf("a step asked too long ago is offered to let go ahead with others: %+v", it)
		}
	}
}

// The change waiting for review has waited since it was proposed, on the
// screen as on the command line; the screen said "just now" every time it
// was opened.
func TestTheChangeWaitingForReviewHasWaitedSinceItWasProposed(t *testing.T) {
	root, s, now := waitingEverywhere(t)
	items, err := waitingFor(root, asAdmin("dana"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Source == "review" && now.Sub(it.Since) < 3*time.Hour-time.Minute {
			t.Errorf("the command line says the review has waited since %s", it.Since)
		}
	}
	screens, toks := approvalsScreens(t, root, s)
	found := false
	for _, r := range screenRows(adminGet(t, screens[0].srv, "/approvals", tokenFor(t, toks, waitingSessions[0]))) {
		if r.What == "Approve the change to the site" {
			found = true
			if r.When != "3 hours ago" {
				t.Errorf("the screen says the review has waited since %q, not 3 hours ago", r.When)
			}
		}
	}
	if !found {
		t.Fatal("the review is not on dana's Approvals")
	}
}

var todayCount = regexp.MustCompile(`<h2 id="waiting">Waiting for you(?: <span class="count">(\d+)</span>)?</h2>`)

// Today counts what Approvals lists and what the command line lists, for
// each session.
func TestTodayApprovalsAndTheCommandLineCountTheSameThingsWaiting(t *testing.T) {
	root, s, now := waitingEverywhere(t)
	screens, toks := approvalsScreens(t, root, s)
	srv := screens[0].srv
	for _, ws := range waitingSessions {
		t.Run(ws.name, func(t *testing.T) {
			items, err := waitingFor(root, sessionCaller(ws.actor), now)
			if err != nil {
				t.Fatal(err)
			}
			tok := tokenFor(t, toks, ws)
			m := todayCount.FindStringSubmatch(adminGet(t, srv, "/today", tok))
			if m == nil {
				t.Fatal("Today has no waiting section")
			}
			today := 0
			fmt.Sscan(m[1], &today)
			line, screen := len(lineRows(items, now)), len(screenRows(adminGet(t, srv, "/approvals", tok)))
			if today != screen || screen != line {
				t.Errorf("Today counts %d waiting, Approvals lists %d and the command line %d", today, screen, line)
			}
		})
	}
}

// The screens read what waits from the store the server holds, and do not
// open it again for every page. Opening it reads the key to an encrypted
// store, so a server given its key by a command (a KMS, an HSM, a password
// manager) ran that command whenever anybody opened Approvals, Today or the
// assistant, where it had run it once, as it started.
func TestTheScreensListWhatWaitsWithoutAskingForTheKeyAgain(t *testing.T) {
	root, s, _ := waitingEverywhere(t)
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(keyringPath(root), kr); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	asked, key := filepath.Join(dir, "asked"), filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte(vault.EncodeKey(kr.Keys["k1"].Key)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyCmdEnv, fmt.Sprintf("echo asked >> '%s'; cat '%s'", asked, key))
	screens, toks := approvalsScreens(t, root, s)
	tok := tokenFor(t, toks, waitingSessions[0])
	for _, path := range []string{"/approvals", "/today"} {
		body := adminGet(t, screens[0].srv, path, tok)
		if !strings.Contains(body, "Approve the change to the site") {
			t.Errorf("%s does not list the change waiting for review", path)
		}
	}
	if b, err := os.ReadFile(asked); err == nil {
		t.Errorf("listing what waits ran the key command %d times", strings.Count(string(b), "asked"))
	}
	// The command line opens the store, and asks for the key, as it always
	// has: it holds no store until it opens one.
	items, err := waitingFor(root, asAdmin("dana"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	review := false
	for _, it := range items {
		review = review || it.Source == "review"
	}
	if b, _ := os.ReadFile(asked); !review || strings.Count(string(b), "asked") != 1 {
		t.Errorf("quilzo approvals lists the review: %v, having asked for the key %d times", review,
			strings.Count(string(b), "asked"))
	}
}
