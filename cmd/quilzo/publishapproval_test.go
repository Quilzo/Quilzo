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

// updatePolicyForTest grants a binding in the store's policy file.
func updatePolicyForTest(root string, b auth.Binding) error {
	_, err := updatePolicy(root, func(p *auth.Policy) error { return p.Grant(b) })
	return err
}
