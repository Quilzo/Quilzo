// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/incident"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// okta is a stand-in for the tool an action is sent to.
type okta struct {
	code  int
	calls []string
	auth  []string
}

func (o *okta) Do(r *http.Request) (*http.Response, error) {
	o.calls = append(o.calls, r.Method+" "+r.URL.String())
	o.auth = append(o.auth, r.Header.Get("Authorization"))
	return &http.Response{StatusCode: o.code, Header: http.Header{},
		Body:    io.NopCloser(strings.NewReader(`{"errorSummary":"secret detail"}`)),
		Request: r}, nil
}

const danaOkta = "00u1a2b3c4d5e6f7"

// actionSite is a store with one finding about an Okta account, an
// incident gathering it, two actions installed, and a stand-in Okta.
func actionSite(t *testing.T) (root, id string, tool *okta) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	e := signIn("okta/system", "admin-x", telemetry.DispositionFailed,
		"sign-in failed", at)
	e.Actor = telemetry.ID{Issuer: "okta", Value: danaOkta}
	root, rules := siemSite(t, nil)
	// The site's rule names admin-* accounts; this one is about any.
	rule := strings.Replace(privilegedFailRule,
		`{"match": {"field": "actor.value", "op": "prefix", "values": ["admin-"]}}`,
		`{"match": {"field": "source", "op": "equals", "values": ["okta/system"]}}`, 1)
	if err := os.WriteFile(rules+"/privileged.json", []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{{"dana", true, e}})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	fid := queue(t, root)[0].ID
	i, err := declareIncident(root, human("dana"), "Dana's account",
		incident.Sev2, nil, []string{fid}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"okta-suspend-user", "okta-clear-sessions"} {
		if err := cmdAction(root, []string{"add", name, "--org", "acme"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("QUILZO_CONNECT_SECRET", "00actiontokenABCDEFGHIJKLMNOPQRSTUVWXYZ012")
	if err := cmdConnect(root, []string{"secret", "okta-action-token"}); err != nil {
		t.Fatal(err)
	}
	tool = &okta{code: 200}
	saved := actionDoer
	actionDoer = func() actionSender { return tool }
	t.Cleanup(func() { actionDoer = saved })
	return root, i.ID, tool
}

func TestAnActionIsSentOnlyAfterSomebodyElseApprovesTheExactCall(t *testing.T) {
	root, id, tool := actionSite(t)
	now := time.Now().UTC()
	target := "okta:" + danaOkta
	if err := requestAct(root, id, human("dana"), "okta-suspend-user", target,
		"sessions from two countries", now); err != nil {
		t.Fatal(err)
	}
	if len(tool.calls) != 0 {
		t.Fatal("asking for an action sent it")
	}
	if _, err := approveAct(root, id, human("dana"), 1, now); err == nil ||
		len(tool.calls) != 0 {
		t.Fatalf("whoever asked also approved (%d calls): %v", len(tool.calls), err)
	}
	ai := &Caller{Name: "agent", Kind: audit.KindAI, Verified: true}
	if _, err := approveAct(root, id, ai, 1, now); err == nil || len(tool.calls) != 0 {
		t.Fatal("a model approved an action")
	}
	if requestAct(root, id, ai, "okta-clear-sessions", target, "tidy up", now) == nil {
		t.Error("a model asked for an action")
	}
	code, err := approveAct(root, id, human("sam"), 1, now)
	if err != nil || code != 200 {
		t.Fatalf("approve: %d %v", code, err)
	}
	want := "POST https://acme.okta.com/api/v1/users/" + danaOkta + "/lifecycle/suspend"
	if len(tool.calls) != 1 || tool.calls[0] != want {
		t.Fatalf("sent %v, want %s", tool.calls, want)
	}
	if !strings.HasPrefix(tool.auth[0], "SSWS 00actiontoken") {
		t.Errorf("the credential was sent as %q", tool.auth[0])
	}
	i, _ := loadIncident(root, id)
	if a := i.Acts[0]; a.State != incident.ActDone || a.Code != 200 ||
		a.Approved.By != "sam" || a.Says != want {
		t.Errorf("%+v", a)
	}
	// Undone by anybody, with a reason.
	if _, err := undoAct(root, id, human("dana"), 1, "", now); err == nil {
		t.Error("undone with no reason")
	}
	if _, err := undoAct(root, id, human("dana"), 1, "cleared by the owner", now); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(tool.calls[len(tool.calls)-1], "/lifecycle/unsuspend") {
		t.Errorf("undo sent %s", tool.calls[len(tool.calls)-1])
	}
	if i, _ = loadIncident(root, id); i.Acts[0].State != incident.ActUndone {
		t.Errorf("after undoing: %s", i.Acts[0].State)
	}
	// The log says who asked, who approved, what was sent and what came
	// back, and nothing the tool said or the credential.
	events, _ := audit.Read(auditPath(root))
	seen := map[string]int{}
	for _, e := range events {
		if !strings.HasPrefix(e.Action, "incident.act") &&
			!strings.HasPrefix(e.Action, "action.") {
			continue
		}
		seen[e.Action]++
		for k, v := range e.Detail {
			if strings.Contains(v, "actiontoken") || strings.Contains(v, "secret detail") {
				t.Errorf("%s carries %s=%q", e.Action, k, v)
			}
			if k == "subject" && strings.Contains(v, danaOkta) {
				t.Errorf("%s names the account in clear", e.Action)
			}
		}
	}
	for _, want := range []string{"incident.act-request", "incident.act-approve",
		"action.sent", "incident.act-undo", "action.undone", "action.installed"} {
		if seen[want] == 0 {
			t.Errorf("no record of %s", want)
		}
	}
}

// An action cannot be pointed at an account by typing its name: only one
// the incident is already about.
func TestAnActionIsOnlyEverTakenOnAnAccountTheIncidentIsAbout(t *testing.T) {
	root, id, tool := actionSite(t)
	now := time.Now().UTC()
	for name, target := range map[string]string{
		"another account":       "okta:00u9z9z9z9z9z9z9",
		"another platform's id": "github:dana-gh",
		"a path":                "okta:" + danaOkta + "/../00u9",
		"an address":            "okta:dana@acme.com",
		"nothing":               "",
	} {
		if err := requestAct(root, id, human("dana"), "okta-suspend-user",
			target, "x", now); err == nil {
			t.Errorf("an action was requested on %s (%s)", name, target)
		}
	}
	if requestAct(root, id, human("dana"), "okta-delete-user",
		"okta:"+danaOkta, "x", now) == nil {
		t.Error("an action nobody installed was requested")
	}
	if i, _ := loadIncident(root, id); len(i.Acts) != 0 || len(tool.calls) != 0 {
		t.Fatalf("%d acts recorded, %d calls", len(i.Acts), len(tool.calls))
	}
	// Another identifier of the same person is theirs too.
	other := "00u7k7k7k7k7k7k7"
	aliases := map[string]alias{
		"okta:" + danaOkta:      {Person: "dana@acme.com", How: "learned"},
		"okta:" + other:         {Person: "dana@acme.com", How: "learned"},
		"okta:00u9z9z9z9z9z9z9": {Person: "sam@acme.com", How: "learned"},
	}
	if err := saveAliases(root, aliases); err != nil {
		t.Fatal(err)
	}
	if err := requestAct(root, id, human("dana"), "okta-suspend-user",
		"okta:"+other, "her other account", now); err != nil {
		t.Errorf("the same person's other identifier was refused: %v", err)
	}
	if requestAct(root, id, human("dana"), "okta-suspend-user",
		"okta:00u9z9z9z9z9z9z9", "x", now) == nil {
		t.Error("somebody else's account was accepted")
	}
}

// The tool refuses, the credential is missing, the action changed after it
// was shown: each is said, and none is recorded as done.
func TestWhatGoesWrongIsRecordedAsWhatItWas(t *testing.T) {
	root, id, tool := actionSite(t)
	now := time.Now().UTC()
	target := "okta:" + danaOkta
	if err := requestAct(root, id, human("dana"), "okta-suspend-user", target,
		"x", now); err != nil {
		t.Fatal(err)
	}
	// The action is edited after the request was shown to somebody.
	path := actionsDir(root) + "/okta-suspend-user.json"
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(b),
		"/lifecycle/suspend", "/lifecycle/deactivate", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := approveAct(root, id, human("sam"), 1, now); err == nil ||
		!strings.Contains(err.Error(), "changed since") || len(tool.calls) != 0 {
		t.Fatalf("a call other than the one shown was sent: %v %v", err, tool.calls)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	i, _ := loadIncident(root, id)
	if i.Acts[0].State != incident.ActRequested {
		t.Fatalf("a refused approval left the act %s", i.Acts[0].State)
	}
	// The tool says no.
	tool.code = 403
	if _, err := approveAct(root, id, human("sam"), 1, now); err == nil ||
		!strings.Contains(err.Error(), "403") {
		t.Fatalf("a refusal by the tool: %v", err)
	}
	if i, _ = loadIncident(root, id); i.Acts[0].State != incident.ActFailed ||
		i.Acts[0].Code != 403 {
		t.Errorf("after a 403: %+v", i.Acts[0])
	}
	if _, err := undoAct(root, id, human("dana"), 1, "x", now); err == nil {
		t.Error("something that never happened was undone")
	}
	// No credential: refused before anything is recorded as approved.
	if err := requestAct(root, id, human("dana"), "okta-clear-sessions",
		target, "x", now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(secretsPath(root)); err != nil {
		t.Fatal(err)
	}
	calls := len(tool.calls)
	if _, err := approveAct(root, id, human("sam"), 2, now); err == nil ||
		len(tool.calls) != calls {
		t.Fatalf("approved with no credential: %v", err)
	}
	if i, _ = loadIncident(root, id); i.Acts[1].State != incident.ActRequested {
		t.Errorf("with no credential the act became %s", i.Acts[1].State)
	}
	if cmdAction(root, []string{"list"}) != nil ||
		cmdAction(root, []string{"catalogue"}) != nil {
		t.Error("list")
	}
	if err := cmdAction(root, []string{"remove", "okta-clear-sessions"}); err != nil {
		t.Fatal(err)
	}
	if cmdAction(root, []string{"add", "okta-suspend-user"}) == nil {
		t.Error("installed for no organisation")
	}
}
