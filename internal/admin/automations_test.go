// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/automate"
)

func wireAutomations(t *testing.T, srv *Server) *automate.Engine {
	t.Helper()
	ok := func(automate.Event, map[string]string) (string, error) { return "done", nil }
	e := &automate.Engine{Path: filepath.Join(t.TempDir(), "automate.json"), Actions: map[string]automate.Action{
		"step-up":             {ID: "step-up", Name: "Make them prove it is them", Does: "step up", Kinds: []string{"signin", "finding", "person"}, Inline: true, Access: true, Run: ok},
		"end-sessions":        {ID: "end-sessions", Name: "Sign them out", Does: "sign out", Kinds: []string{"signin", "finding", "person"}, Access: true, Run: ok},
		"notify":              {ID: "notify", Name: "Tell somebody", Does: "tell", Kinds: []string{"signin", "finding", "device", "person"}, Params: []automate.Param{{Name: "to", Choices: []string{"security", "person"}}}, Run: ok},
		"open-case":           {ID: "open-case", Name: "Open a case", Does: "open", Kinds: []string{"signin", "finding", "device", "person"}, Run: ok},
		"okta-suspend-user":   {ID: "okta-suspend-user", Name: "Suspend in Okta", Does: "ask", Kinds: []string{"finding"}, Access: true, Run: ok},
		"okta-clear-sessions": {ID: "okta-clear-sessions", Name: "End Okta sessions", Does: "ask", Kinds: []string{"finding"}, Access: true, Run: ok},
	}}
	srv.Automations = &AutomationsAdmin{Engine: e}
	return e
}

// An analyst runs security operations and is not an administrator of the
// whole site: they may add a rule that opens cases, and not one that acts
// on people's access, and may not approve one that waits.
func TestAnAnalystCannotAutomatePeoplesAccess(t *testing.T) {
	srv, token := asJob(t, "analyst")
	e := wireAutomations(t, srv)
	postForm(t, srv, "/security/automations/act", token, "do=template&id=tpl-impossible-travel")
	postForm(t, srv, "/security/automations/act", token, "do=template&id=tpl-critical-case")
	rules, _ := e.Rules()
	if len(rules) != 1 || rules[0].Name != "A critical finding: open a case" {
		t.Fatalf("an analyst added %+v", rules)
	}
	// A watching copy is theirs to write; turning it to act is not.
	w := postForm(t, srv, "/security/automations/act", token,
		"do=save&name=mine&when=signin&field0=signin:signal&op0=is&value0=impossible-travel&action0=step-up&mode=watch")
	if w.Code != 303 {
		t.Fatalf("saving a watching rule: %d", w.Code)
	}
	rules, _ = e.Rules()
	var mine automate.Rule
	for _, r := range rules {
		if r.Name == "mine" {
			mine = r
		}
	}
	postForm(t, srv, "/security/automations/act", token, "do=mode&id="+mine.ID+"&mode=act")
	rules, _ = e.Rules()
	for _, r := range rules {
		if r.Name == "mine" && r.Mode != "watch" {
			t.Error("an analyst set a rule on people's access to act")
		}
	}
	// A run waiting to sign somebody out is not theirs to approve.
	e.Save(automate.Rule{Name: "leaver", Enabled: true, Mode: "ask", When: "finding",
		Then: []automate.Step{{Action: "end-sessions"}}}, "boss")
	out, _ := e.Handle(automate.Event{Kind: "finding", Subject: "dee"})
	postForm(t, srv, "/security/automations/act", token, "do=approve&id="+out.Runs[0].ID)
	runs, _ := e.Runs()
	for _, r := range runs {
		if r.ID == out.Runs[0].ID && r.State != "waiting" {
			t.Errorf("an analyst's approval was taken: %s", r.State)
		}
	}
}

// An administrator of the whole site may do all of it.
func TestASiteAdministratorAutomatesAccess(t *testing.T) {
	srv, token := setup(t)
	e := wireAutomations(t, srv)
	postForm(t, srv, "/security/automations/act", token, "do=template&id=tpl-impossible-travel")
	rules, _ := e.Rules()
	if len(rules) != 1 || rules[0].Mode != "act" {
		t.Fatalf("rules %+v", rules)
	}
	page := get(t, srv, "/security/automations", token).Body.String()
	if !strings.Contains(page, "Impossible travel") || !strings.Contains(page, `aria-pressed="true" class="on">Act`) {
		t.Error("the rule and its mode are not shown")
	}
}

// Vouching for somebody takes at least their standing.
func TestAnAnalystCannotLetAnAdministratorPastAStepUp(t *testing.T) {
	srv, token := asJob(t, "analyst")
	if err := srv.Policy.Grant(auth.Binding{Principal: "boss", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	_, tok, err := srv.Tokens.IssueSession("s", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Tokens.RequireStepUp(tok.ID, "Sydney"); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/security/signins/act", token, "do=letin&session="+tok.ID)
	for _, x := range srv.Tokens.Snapshot() {
		if x.ID == tok.ID && x.StepUp == "" {
			t.Error("an analyst let a site administrator in")
		}
	}
}
