// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// proposeRisk raises an accepted risk as dana, on the store at root, and
// returns its identifier.
func proposeRisk(t *testing.T, root, ref string) register.ID {
	t.Helper()
	r := registerOn(t, root)
	people := approval.PeopleAt(root)
	dana, err := people.Pseudonym("dana")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := r.Propose(register.Actor{Name: "dana", Subject: dana, Kind: audit.KindHuman,
		May: func(auth.Action, string) error { return nil }}, "raised at the risk review",
		register.Risk{Ref: ref, Title: "Payroll supplier outage", Owner: dana, Raised: dana, Likelihood: 3, Impact: 2, Status: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	return rc.Written[0].ID
}

// An administrator at the console approves by typing back the hash show
// gave them: another hash approves nothing, and the record says the
// approval was given at the console; the evidence checks again offline.
func TestTheConsoleApprovesAtTheCommandLine(t *testing.T) {
	root, token := accessStore(t)
	id := proposeRisk(t, root, "R-31")
	o, e, code := cliRun(t, root, token, "approval", "show", string(id), "--json")
	if code != 0 {
		t.Fatalf("approval show: %s", e)
	}
	var shown struct {
		Surface register.Digest
		Needed  int
		Approve string
		Shown   *approval.Surface
	}
	if err := json.Unmarshal([]byte(o), &shown); err != nil || !shown.Surface.Valid() || shown.Shown == nil {
		t.Fatalf("approval show gave no hash: %v\n%s", err, firstLines(o, 6))
	}
	if shown.Shown.Digest() != shown.Surface {
		t.Fatal("the hash show gives is not the hash of the surface it shows")
	}
	other := "sha256:" + strings.Repeat("0", 64)
	if _, e, code := cliRun(t, root, token, "approval", "approve", string(id), "--surface", other); code != 3 ||
		!strings.Contains(e, "not the hash") {
		t.Fatalf("another hash approved it: exit %d: %s", code, e)
	}
	o, e, code = cliRun(t, root, token, "approval", "approve", string(id), "--surface", string(shown.Surface), "--json")
	if code != 0 {
		t.Fatalf("approval approve: exit %d: %s", code, e)
	}
	var out approval.Outcome
	if err := json.Unmarshal([]byte(o), &out); err != nil || !out.Done || out.Receipt == nil ||
		len(out.Receipt.Approved) != 1 || out.Receipt.Approved[0] != shown.Surface {
		t.Fatalf("the receipt does not carry the hash typed: %v %+v", err, out)
	}
	e2, err := registerOn(t, root).Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if s := register.ApprovalOf(e2.Record).Signers[0]; s.Method != "console" {
		t.Errorf("the console's approval is recorded as given by %q", s.Method)
	}
	o, e, code = cliRun(t, root, token, "approval", "check", string(id), "--json")
	if code != 0 || !strings.Contains(o, `"holds": true`) || strings.Contains(o, `"holds": false`) {
		t.Fatalf("the evidence does not check: exit %d %s %s", code, o, e)
	}
	if _, _, code := cliRun(t, root, token, "approval", "show", "00000000000000000000000000000000"); code != 4 {
		t.Errorf("a decision that is not there exited %d", code)
	}
	if o, _, code := cliRun(t, root, token, "approval", "policy", "--json"); code != 0 || !strings.Contains(o, `"declared": false`) ||
		!strings.Contains(o, "risk-acceptance") {
		t.Errorf("the default policy is not shown: %s", firstLines(o, 4))
	}
	if o, _, code := cliRun(t, root, token, "approval", "list", "--json"); code != 0 || !strings.Contains(o, string(id)) {
		t.Errorf("the approved decision is not listed as held: %s", firstLines(o, 4))
	}
}

// Over the agent interface the approvals are read and never given: the
// operation that would approve says where the person approves instead.
func TestApprovingOverTheAgentInterfaceIsRefused(t *testing.T) {
	root, _ := accessStore(t)
	id := proposeRisk(t, root, "R-32")
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	owner := human("owner")
	owner.Role, owner.Scope = auth.RoleAdmin, "/"
	srv := buildMCP(root, s, owner, "")
	text, refused := callTool(t, srv, "quilzo_read", "approval_list", nil)
	if refused != nil || !strings.Contains(text, string(id)) {
		t.Fatalf("approval_list does not list what waits: %v %s", refused, firstLines(text, 4))
	}
	_, refused = callTool(t, srv, "quilzo_write", "approval_approve", map[string]any{"id": string(id)})
	if refused == nil || !strings.Contains(refused.Message, "passkey") || !strings.Contains(refused.Message, "/register/approvals/item/"+string(id)) {
		t.Fatalf("approval_approve did not refuse with where to approve: %+v", refused)
	}
	if registerOn(t, root).Head() != "" {
		t.Fatal("something was approved over the agent interface")
	}
}

// A separation policy declared from a file is read back, and one that asks
// for something no rule allows is refused and leaves the default.
func TestASeparationPolicyIsDeclaredAtTheConsole(t *testing.T) {
	root, token := accessStore(t)
	pol := approval.Default()
	pol.Seconds = []approval.Second{{Principal: "head-of-risk", As: "risk"}}
	good := policyFile(t, pol)
	pol.Rules[0].Level = 7
	bad := policyFile(t, pol)
	if _, e, code := cliRun(t, root, token, "approval", "policy", "set", bad); code == 0 || !strings.Contains(e, "level 7") {
		t.Fatalf("a policy at level 7 was declared: %d %s", code, e)
	}
	if _, e, code := cliRun(t, root, token, "approval", "policy", "set", good); code != 0 {
		t.Fatalf("approval policy set: %s", e)
	}
	o, _, _ := cliRun(t, root, token, "approval", "policy", "--json")
	if !strings.Contains(o, `"declared": true`) || !strings.Contains(o, "head-of-risk") {
		t.Errorf("the declared policy is not read back: %s", firstLines(o, 4))
	}
}

func policyFile(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/policy.json"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A reader of the register reads its approvals, and nothing a reader runs
// gives one, rejects one or declares who may: the separation policy is an
// administrator's to declare, as approving at the console is.
func TestOnlyAnAdministratorDeclaresTheSeparationPolicy(t *testing.T) {
	root, token := accessStore(t)
	id := proposeRisk(t, root, "R-33")
	if _, e, code := cliRun(t, root, token, "auth", "grant", "rita", "reader", "--on", "/@compliance"); code != 0 {
		t.Fatalf("auth grant: %s", e)
	}
	reader := issueToken(t, root, token, "rita-token", "rita", "reader")
	for _, line := range [][]string{{"approval"}, {"approval", "list"}, {"approval", "show", string(id)}, {"approval", "policy"}} {
		if _, e, code := cliRun(t, root, reader, append(line, "--json")...); code != 0 {
			t.Errorf("a reader could not run quilzo %s: exit %d: %s", strings.Join(line, " "), code, firstLines(e, 2))
		}
	}
	good := policyFile(t, approval.Default())
	for _, line := range [][]string{{"approval", "policy", "set", good}, {"approval", "reject", string(id)},
		{"approval", "approve", string(id), "--surface", "sha256:" + strings.Repeat("0", 64)}} {
		if _, _, code := cliRun(t, root, reader, line...); code != 3 {
			t.Errorf("a reader ran quilzo %s: exit %d", strings.Join(line, " "), code)
		}
	}
	if _, err := os.Stat(approval.PolicyPath(root)); err == nil {
		t.Fatal("a reader declared the separation policy")
	}
	if _, _, code := cliRun(t, root, token, "approval", "policy", "set", good); code != 0 {
		t.Fatal("the administrator could not declare the separation policy")
	}
}
