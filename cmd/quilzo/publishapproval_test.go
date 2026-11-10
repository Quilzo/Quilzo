// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// approvalDemo is a store holding the demonstration as an unpublished
// draft, with its templates, so that every gate but the approval one
// passes on every surface.
func approvalDemo(t *testing.T) (root, tpl string, s *store.Store) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir() + "/st"
	tpl = t.TempDir() + "/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false", "-templates", tpl}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { finishBackground(10 * time.Second) })
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, tpl, s
}

// publishOnTheCommandLine is `quilzo publish` on that store.
func publishOnTheCommandLine(t *testing.T, root, tpl string, _ *store.Store) string {
	t.Helper()
	if err := runPublish(t, root, "--templates", tpl); err != nil {
		return err.Error()
	}
	return ""
}

// publishOverMCP is quilzo_publish, asked by an administrator's client.
func publishOverMCP(t *testing.T, root, tpl string, s *store.Store) string {
	t.Helper()
	srv := buildMCP(root, s, asAdmin("dana"), tpl)
	params, _ := json.Marshal(map[string]any{"name": "quilzo_publish",
		"arguments": map[string]any{"operation": "publish"}})
	b, _ := json.Marshal(srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"),
		Method: "tools/call", Params: params}))
	if got := string(b); refused(got) {
		return got
	}
	return ""
}

// publishInTheBrowser is Review → Publish, by a signed-in administrator,
// with the approval hooks and content gates the server wires.
func publishInTheBrowser(t *testing.T, root, tpl string, s *store.Store) string {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !pol.Evaluate("dana", auth.ActPublish, "/").Allowed {
		if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := toks.IssueSession("passkey:dana", "dana", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, design.Layouts)
	if err != nil {
		t.Fatal(err)
	}
	srv.ContentGates = func(ref string) (*gate.Report, []gate.Finding, error) {
		return contentGates(root, s, ref).Run()
	}
	srv.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }
	srv.Approvals = approvalsHooks(root, s)
	form := url.Values{"reason": {"the waivable gates are not what this is about"}}
	req := httptest.NewRequest(http.MethodPost, "/publish", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Published") {
		return rec.Body.String()
	}
	return ""
}

var publishSurfaces = []struct {
	name    string
	publish func(t *testing.T, root, tpl string, s *store.Store) string
}{
	{"the command line", publishOnTheCommandLine},
	{"the machine interface", publishOverMCP},
	{"the browser", publishInTheBrowser},
}

// An approval policy that cannot be read refuses the publish, on every
// surface, rather than letting it through as though nothing were required.
//
// The machine interface refused. The command line checked the policy only
// when it could be read, so a damaged approval.json, a file somebody
// could not read, or one half-written by a crash switched dual
// authorisation off for `quilzo publish` and for every scheduled publish
// behind it. The browser did the same, and said nothing of it on the
// review screen.
func TestAnUnreadableApprovalPolicyRefusesThePublishOnEverySurface(t *testing.T) {
	for _, surface := range publishSurfaces {
		t.Run(surface.name, func(t *testing.T) {
			root, tpl, s := approvalDemo(t)
			if err := os.WriteFile(approvalPolicyPath(root), []byte(`{"required": `), 0o600); err != nil {
				t.Fatal(err)
			}
			refusal := surface.publish(t, root, tpl, s)
			if live := s.GetRef(site.RefLive); live != "" {
				t.Fatalf("%s published with an approval policy it could not read", surface.name)
			}
			if !strings.Contains(refusal, "approval policy could not be read") {
				t.Fatalf("%s refused, but not because the approval policy could not be read:\n%s",
					surface.name, refusal)
			}

			// Control: the same store, with a policy that can be read,
			// publishes, so the refusal above was the policy's.
			if err := os.Remove(approvalPolicyPath(root)); err != nil {
				t.Fatal(err)
			}
			if refusal := surface.publish(t, root, tpl, s); refusal != "" {
				t.Fatalf("control: %s did not publish with no approval file:\n%s", surface.name, refusal)
			}
			if s.GetRef(site.RefLive) == "" {
				t.Fatalf("control: %s said it published and live did not move", surface.name)
			}
		})
	}
}

// A model's draft, on a store nobody configured approvals for, is refused
// on every surface until a person approves it, and then publishes on
// every surface.
//
// The command line and the machine interface refused it. The browser
// asked about approvals only when review.required_approvals was above
// zero, which by default it is not, and put the agent's draft live.
func TestAModelsDraftNobodyApprovedIsRefusedOnEverySurface(t *testing.T) {
	for _, surface := range publishSurfaces {
		t.Run(surface.name, func(t *testing.T) {
			root, tpl, s := approvalDemo(t)
			pages, err := site.PagesAt(s, site.RefDraft)
			if err != nil {
				t.Fatal(err)
			}
			pages["index"].(map[string]any)["title"] = "Rewritten by an agent"
			if _, err := site.SaveDraft(s, pages, collab.AgentPrefix+"rewrote the homepage", "writer"); err != nil {
				t.Fatal(err)
			}
			if err := runCmd(t, root, "provenance", "set", "index",
				"--source", string(provenance.TrainedAlgorithmicMedia), "--author", "writer"); err != nil {
				t.Fatal(err)
			}
			draft := s.GetRef(site.RefDraft)
			// Two administrators, people both: dana publishes, and lee is
			// the person who approves. Holding a binding is what makes a
			// principal a person here (kindOfPrincipal), and with bindings
			// the command line publishes on a token.
			for _, who := range []string{"dana", "lee"} {
				if err := updatePolicyForTest(root, auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
					t.Fatal(err)
				}
			}
			ts, err := loadTokens(root)
			if err != nil {
				t.Fatal(err)
			}
			secret, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveTokens(root, ts); err != nil {
				t.Fatal(err)
			}
			t.Setenv("QUILZO_TOKEN", secret)

			refusal := surface.publish(t, root, tpl, s)
			if live := s.GetRef(site.RefLive); live != "" {
				t.Fatalf("%s put a model's draft live that no person approved", surface.name)
			}
			if !strings.Contains(refusal, "needs approval from a person") {
				t.Fatalf("%s refused, but not for want of a person's approval:\n%s", surface.name, refusal)
			}

			// A person approves it, and it goes live.
			prop, _, err := proposalFor(root, s, draft)
			if err != nil {
				t.Fatal(err)
			}
			if err := prop.Approve("lee", "read it", time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := saveProposal(root, s, prop); err != nil {
				t.Fatal(err)
			}
			if refusal := surface.publish(t, root, tpl, s); refusal != "" {
				t.Fatalf("%s refused a model's draft a person approved:\n%s", surface.name, refusal)
			}
			if live := s.GetRef(site.RefLive); live != draft {
				t.Fatalf("%s: live is %s, not the approved draft %s", surface.name, short(live), short(draft))
			}
		})
	}
}

// A store that asks for two people's approval holds a person's draft on
// every surface until two people have approved it, and then publishes it
// on every surface.
//
// approval.required_humans is a setting of its own, and its text says "Set
// to two, nothing publishes without two people". The command line and the
// machine interface held to it. The browser counted only
// review.required_approvals, and with that at zero answered "not
// configured" for anything a person wrote, so Review -> Publish put live a
// draft nobody had approved.
func TestTwoPeopleRequiredHoldAPersonsDraftOnEverySurface(t *testing.T) {
	for _, surface := range publishSurfaces {
		t.Run(surface.name, func(t *testing.T) {
			root, tpl, s := approvalDemo(t)
			if err := cmdConfig(root, []string{"set", "approval.required_humans", "2"}); err != nil {
				t.Fatal(err)
			}
			draft := s.GetRef(site.RefDraft)
			// Three administrators, people all: dana publishes, and lee and
			// kim are the two who approve.
			for _, who := range []string{"dana", "lee", "kim"} {
				if err := updatePolicyForTest(root, auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
					t.Fatal(err)
				}
			}
			ts, err := loadTokens(root)
			if err != nil {
				t.Fatal(err)
			}
			secret, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveTokens(root, ts); err != nil {
				t.Fatal(err)
			}
			t.Setenv("QUILZO_TOKEN", secret)

			refusal := surface.publish(t, root, tpl, s)
			if live := s.GetRef(site.RefLive); live != "" {
				t.Fatalf("%s put a draft live that the two people the store asks for had not approved", surface.name)
			}
			if !strings.Contains(refusal, "approval(s) from people") {
				t.Fatalf("%s refused, but not for want of two people's approval:\n%s", surface.name, refusal)
			}

			prop, _, err := proposalFor(root, s, draft)
			if err != nil {
				t.Fatal(err)
			}
			for _, who := range []string{"lee", "kim"} {
				if err := prop.Approve(who, "read it", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if err := saveProposal(root, s, prop); err != nil {
				t.Fatal(err)
			}
			if refusal := surface.publish(t, root, tpl, s); refusal != "" {
				t.Fatalf("%s refused a draft two people approved:\n%s", surface.name, refusal)
			}
			if live := s.GetRef(site.RefLive); live != draft {
				t.Fatalf("%s: live is %s, not the approved draft %s", surface.name, short(live), short(draft))
			}
		})
	}
}

// updatePolicyForTest grants a binding in the store's policy file.
func updatePolicyForTest(root string, b auth.Binding) error {
	_, err := updatePolicy(root, func(p *auth.Policy) error { return p.Grant(b) })
	return err
}

// publishByPromoting is `quilzo env promote draft production`, which is a
// publish of the commit it names.
func publishByPromoting(t *testing.T, root, tpl string, _ *store.Store) string {
	t.Helper()
	if err := cmdEnv(root, []string{"promote", "draft", "production", "--templates", tpl}); err != nil {
		return err.Error()
	}
	return ""
}

// publishOnASchedule schedules the draft for an hour from now as dana, and
// fires the schedule as though the hour had passed.
func publishOnASchedule(t *testing.T, root, tpl string, s *store.Store) string {
	t.Helper()
	commit := s.GetRef(site.RefDraft)
	if err := updateSchedule(root, func(sch *schedule.Schedule) error {
		return sch.Add(commit, time.Now().Add(time.Hour),
			schedule.Who{Name: "dana", Kind: "human", Verified: true}, "the launch", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	fired, err := fireDue(root, asAdmin("dana"), inAnHour, fireOptions{templates: tpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) == 0 {
		return "nothing on the schedule fired"
	}
	for _, f := range fired {
		if f.Outcome != "published" {
			return f.Outcome + ": " + f.Reason
		}
	}
	return ""
}

// A model's change is refused on every surface until a person approves it,
// though a person committed something after it, and a person's change
// after that one has gone live publishes with nobody asked.
//
// Every surface judged who wrote a draft by its newest commit alone. An
// agent rewrote the homepage, a person then fixed a typo on another page,
// and the draft's newest commit was the person's: the rule that a person
// approves what a model wrote never applied, and publishing put the
// agent's homepage live with no person having read it, from the browser,
// the command line, the machine interface, a promotion into production
// and a scheduled publish alike.
func TestAModelsChangeUnderAPersonsLaterCommitIsRefusedOnEverySurface(t *testing.T) {
	type surface = struct {
		name    string
		publish func(t *testing.T, root, tpl string, s *store.Store) string
	}
	surfaces := append(append([]surface{}, publishSurfaces...),
		surface{"a promotion into production", publishByPromoting},
		surface{"a scheduled publish", publishOnASchedule})
	for _, surface := range surfaces {
		t.Run(surface.name, func(t *testing.T) {
			root, tpl, s := approvalDemo(t)
			// Two administrators, people both, as in the test above: dana
			// publishes and lee approves.
			for _, who := range []string{"dana", "lee"} {
				if err := updatePolicyForTest(root, auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
					t.Fatal(err)
				}
			}
			ts, err := loadTokens(root)
			if err != nil {
				t.Fatal(err)
			}
			secret, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveTokens(root, ts); err != nil {
				t.Fatal(err)
			}
			t.Setenv("QUILZO_TOKEN", secret)

			// edit changes one page's title in the draft, as whoever, and
			// says where that page came from.
			edit := func(page, title, message, author string, source provenance.SourceType) string {
				t.Helper()
				pages, err := site.PagesAt(s, site.RefDraft)
				if err != nil {
					t.Fatal(err)
				}
				pages[page].(map[string]any)["title"] = title
				if _, err := site.SaveDraft(s, pages, message, author); err != nil {
					t.Fatal(err)
				}
				if err := runCmd(t, root, "provenance", "set", page,
					"--source", string(source), "--author", author); err != nil {
					t.Fatal(err)
				}
				return s.GetRef(site.RefDraft)
			}
			pages, err := site.PagesAt(s, site.RefDraft)
			if err != nil {
				t.Fatal(err)
			}
			other := ""
			for _, name := range sortedKeys(pages) {
				if name != "index" {
					other = name
					break
				}
			}
			if other == "" {
				t.Fatal("the demonstration has no page but the homepage")
			}

			agents := edit("index", "Rewritten by an agent", collab.AgentPrefix+"rewrote the homepage",
				"writer", provenance.TrainedAlgorithmicMedia)
			draft := edit(other, "A typo fixed", "fixed a typo", "dana", provenance.HumanEdits)

			refusal := surface.publish(t, root, tpl, s)
			if live := s.GetRef(site.RefLive); live != "" {
				t.Fatalf("%s put a model's change live that no person approved, because a person "+
					"committed after it", surface.name)
			}
			if !strings.Contains(refusal, "needs approval from a person") {
				t.Fatalf("%s refused, but not for want of a person's approval:\n%s", surface.name, refusal)
			}
			if !strings.Contains(refusal, short(agents)) || !strings.Contains(refusal, "writer") {
				t.Errorf("%s's refusal does not name the model's change %s and who wrote it:\n%s",
					surface.name, short(agents), refusal)
			}

			// A person approves what is proposed, and it goes live.
			prop, _, err := proposalFor(root, s, draft)
			if err != nil {
				t.Fatal(err)
			}
			if prop.AuthorKind != "ai" {
				t.Errorf("the proposal for a draft holding a model's change is %q, not ai", prop.AuthorKind)
			}
			if err := prop.Approve("lee", "read it", time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := saveProposal(root, s, prop); err != nil {
				t.Fatal(err)
			}
			if refusal := surface.publish(t, root, tpl, s); refusal != "" {
				t.Fatalf("%s refused a draft a person approved:\n%s", surface.name, refusal)
			}
			if live := s.GetRef(site.RefLive); live != draft {
				t.Fatalf("%s: live is %s, not the approved draft %s", surface.name, short(live), short(draft))
			}

			// A person's own change, with no model's change since what is
			// live, still needs nobody else.
			mine := edit(other, "Another typo fixed", "fixed another typo", "dana", provenance.HumanEdits)
			if refusal := surface.publish(t, root, tpl, s); refusal != "" {
				t.Fatalf("%s refused a person's change made after the model's had been approved "+
					"and published:\n%s", surface.name, refusal)
			}
			if live := s.GetRef(site.RefLive); live != mine {
				t.Fatalf("%s: live is %s, not the person's draft %s", surface.name, short(live), short(mine))
			}
		})
	}
}
