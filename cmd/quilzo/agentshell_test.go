// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/shell"
)

// keeperRun declares an agent with a workspace and a model that writes a
// note, lists the workspace, removes the note and says it is done.
func keeperRun(t *testing.T) string {
	t.Helper()
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	for _, p := range []string{"ls", "rm"} {
		if _, err := os.Stat("/bin/" + p); err != nil {
			if _, err := os.Stat("/usr/bin/" + p); err != nil {
				t.Skip(p + " is not installed here")
			}
		}
	}
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	testBackend = n
	t.Cleanup(func() { testBackend = nil })

	var mu sync.Mutex
	turn := 0
	plan := []string{
		`{"op":"file_write","input":{"path":"notes.md","text":"Ship the shell.\n"}}`,
		`{"op":"shell_run","input":{"program":"ls","args":["-1"]}}`,
		`{"op":"shell_run","input":{"program":"rm","args":["notes.md"]}}`,
	}
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		choice := `{"op":"done","say":"tidied"}`
		if turn < len(plan) {
			choice = plan[turn]
		}
		turn++
		mu.Unlock()
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	m := agent.Manifest{Name: "keeper", Kind: agent.KindTask, Purpose: "Keep the notes folder tidy",
		Capabilities: agent.ShellCapabilities, Autonomy: agent.AutonomyDraft,
		Shell:  &agent.Shell{Programs: []string{"ls", "rm"}},
		Budget: agent.Budget{Steps: 8, Tools: 1, Duration: agent.Duration(2 * time.Minute)}}
	if err := declareAgent(root, m, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root
}

// A model works in its workspace through a real run: it writes, lists, and
// removing a file waits for a person, who agrees. What each command
// printed is kept, and its digest is in the step's record.
func TestAnAgentWorksInItsWorkspace(t *testing.T) {
	root := keeperRun(t)
	answered := answerAgentWhenAsked(t, root, "keeper", true, "lee")
	id, out, err := runAgentKeptBy(context.Background(), root, "keeper", "tidy the notes", true, false, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v\n%s", aerr, describeRun(out.Trace))
	}
	if err != nil || !out.Trace.Complete {
		t.Fatalf("%v\n%s", err, describeRun(out.Trace))
	}
	set, _ := loadAgents(root)
	ws, _ := workspaceDir(root, set.Agents["keeper"])
	if _, err := os.Stat(filepath.Join(ws, "notes.md")); !os.IsNotExist(err) {
		t.Errorf("the note is still there: %v", err)
	}
	if !strings.Contains(out.Trace.Steps[1].Result, "notes.md") {
		t.Errorf("ls did not show the note: %q", out.Trace.Steps[1].Result)
	}
	outs, err := loadRunOutputs(root, id)
	if err != nil || len(outs) != 2 || outs[1].Command != "rm notes.md" || outs[1].Kind != "destroys" {
		t.Fatalf("%+v %v", outs, err)
	}
	if b, err := runOutputText(root, id, 1); err != nil || !strings.Contains(string(b), "notes.md") {
		t.Errorf("the kept output: %q %v", b, err)
	}
	events, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range events {
		if e.Action == "agent.action" && e.Detail["op"] == "shell_run" && e.Detail["output_sha256"] == outs[0].Digest {
			found = true
		}
	}
	if !found {
		t.Error("no step record names the output's digest")
	}
	// The workspace is let go when the run ends.
	c, err := shell.ClaimWorkspace(claimPath(root, ws), "next")
	if err != nil {
		t.Errorf("the workspace is still claimed: %v", err)
	} else {
		c.Release()
	}
	// The run's home went with it.
	if homes, _ := os.ReadDir(filepath.Join(root, "workspaces", ".home", "keeper")); len(homes) != 0 {
		t.Errorf("the run's home outlived it: %v", homes)
	}
}

// Declined, the file stays, and the model is told who declined.
func TestRemovingAFileWaitsForAPerson(t *testing.T) {
	root := keeperRun(t)
	answered := answerAgentWhenAsked(t, root, "keeper", false, "lee")
	_, out, err := runAgentKeptBy(context.Background(), root, "keeper", "tidy the notes", true, false, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v\n%s", aerr, describeRun(out.Trace))
	}
	if err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	ws, _ := workspaceDir(root, set.Agents["keeper"])
	if _, err := os.Stat(filepath.Join(ws, "notes.md")); err != nil {
		t.Errorf("the note was removed after a person declined: %v", err)
	}
	declined := false
	for _, st := range out.Trace.Steps {
		declined = declined || strings.Contains(st.Why, "lee declined this")
	}
	if !declined {
		t.Errorf("%s", describeRun(out.Trace))
	}
}

// A workspace may not be the store, hold it, or sit inside it outside the
// workspaces' own folder.
func TestAWorkspaceIsNeverTheStore(t *testing.T) {
	root := t.TempDir()
	abs, _ := filepath.Abs(root)
	for _, ws := range []string{abs, filepath.Dir(abs), filepath.Join(abs, "objects")} {
		m := agent.Manifest{Name: "x", Shell: &agent.Shell{Workspace: ws}}
		if _, err := workspaceDir(root, m); err == nil {
			t.Errorf("%s was taken as a workspace", ws)
		}
	}
	// Nor by a link to it.
	link := filepath.Join(t.TempDir(), "looks-elsewhere")
	if err := os.Symlink(abs, link); err != nil {
		t.Fatal(err)
	}
	if _, err := workspaceDir(root, agent.Manifest{Name: "x", Shell: &agent.Shell{Workspace: link}}); err == nil {
		t.Error("a link to the store was taken as a workspace")
	}
	// Inside the store, only an agent's own: not another's, not the homes
	// or the claims.
	for _, ws := range []string{"shared", ".home", ".claims", "other"} {
		m := agent.Manifest{Name: "x", Shell: &agent.Shell{Workspace: filepath.Join(abs, "workspaces", ws)}}
		if _, err := workspaceDir(root, m); err == nil {
			t.Errorf("workspaces/%s was taken as x's workspace", ws)
		}
	}
	if _, err := workspaceDir(root, agent.Manifest{Name: "x", Shell: &agent.Shell{Workspace: filepath.Join(abs, "workspaces", "x")}}); err != nil {
		t.Errorf("x's own folder: %v", err)
	}
	// Reached through a link to somewhere that is not the store: refused
	// all the same, since a link can be changed.
	elsewhere := t.TempDir()
	viaLink := filepath.Join(t.TempDir(), "via")
	_ = os.Symlink(elsewhere, viaLink)
	if _, err := workspaceDir(root, agent.Manifest{Name: "x", Shell: &agent.Shell{Workspace: viaLink}}); err == nil {
		t.Error("a workspace reached through a link was taken")
	}
	// A name that would be a path is not one.
	for _, name := range []string{"..", ".home", "a/b", ""} {
		if _, err := workspaceDir(root, agent.Manifest{Name: name}); err == nil {
			t.Errorf("an agent named %q has a workspace", name)
		}
	}
	if got, _ := workspaceDir(root, agent.Manifest{Name: "x"}); got != filepath.Join(abs, "workspaces", "x") {
		t.Errorf("the default is %s", got)
	}
}

// Something private written into the workspace stays private to the next
// run on it: the breaker remembers across runs.
func TestAWorkspaceRemembersWhatWasPrivate(t *testing.T) {
	root := keeperRun(t)
	set, _ := loadAgents(root)
	m := set.Agents["keeper"]
	sess := agent.NewSession(m, nil)
	sess.HoldsPrivate("a customer's address")
	rs, err := newRunShell(root, m, sess, asAdmin("dana"), nil, "run-20261011-00000001")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := rs.driver.Perform(nil)(ctx, agent.Action{Op: "file_write", Input: map[string]any{"path": "notes.md", "text": "Main Street 4"}}); err != nil {
		t.Fatal(err)
	}
	rs.end()
	next := agent.NewSession(m, nil)
	rs2, err := newRunShell(root, m, next, asAdmin("dana"), nil, "run-20261011-00000002")
	if err != nil {
		t.Fatal(err)
	}
	defer rs2.end()
	if p := strings.Join(next.Private(), ","); !strings.Contains(p, "run-20261011-00000001") {
		t.Errorf("the next run does not hold it: %q", p)
	}
}
