// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package shell

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

func coder(sh *agent.Shell) agent.Manifest {
	return agent.Manifest{Name: "coder", Kind: agent.KindTask, Purpose: "keep the notes tidy",
		Capabilities: agent.ShellCapabilities, Autonomy: agent.AutonomyDraft, Shell: sh,
		Budget: agent.Budget{Steps: 20, Tools: 1, Duration: agent.Duration(time.Minute)}}
}

func testDriver(t *testing.T, sh *agent.Shell) (*Driver, *[]Kept) {
	t.Helper()
	b := testBox(t)
	w, err := OpenWorkspace(b.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	var kept []Kept
	d := &Driver{Session: agent.NewSession(coder(sh), nil), Workspace: w, Box: b,
		Keep: func(k Kept) { kept = append(kept, k) }}
	return d, &kept
}

func do(t *testing.T, d *Driver, op string, in map[string]any) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return d.Perform(nil)(ctx, agent.Action{Op: op, Input: in})
}

// The workspace's actions, end to end: a file written, listed, read, and a
// command run against it, kept by its digest; reading taints the run.
func TestTheWorkspacesActionsAreDone(t *testing.T) {
	d, kept := testDriver(t, &agent.Shell{Programs: []string{"ls", "cat"}})
	out, err := do(t, d, "file_write", map[string]any{"path": "notes/today.md", "text": "Ship the shell.\n"})
	if err != nil || !strings.Contains(out, "added notes/today.md") {
		t.Fatalf("%q %v", out, err)
	}
	if d.Session.Tainted() {
		t.Error("tainted before anything was read")
	}
	if out, err := do(t, d, "file_list", map[string]any{"path": "notes"}); err != nil || !strings.Contains(out, "today.md (16 bytes)") {
		t.Errorf("%q %v", out, err)
	}
	if !d.Session.Tainted() {
		t.Error("listing the workspace did not taint the run: names are words too")
	}
	if out, err := do(t, d, "file_read", map[string]any{"path": "notes/today.md"}); err != nil || out != "Ship the shell.\n" {
		t.Errorf("%q %v", out, err)
	}
	out, err = do(t, d, "shell_run", map[string]any{"program": "cat", "args": []any{"notes/today.md"}})
	if err != nil || !strings.Contains(out, "exit 0") || !strings.Contains(out, "Ship the shell.") {
		t.Fatalf("%q %v", out, err)
	}
	if len(*kept) != 1 || (*kept)[0].Kind != "reads" || !strings.HasPrefix((*kept)[0].Digest, "sha256:") {
		t.Errorf("%+v", *kept)
	}
}

// What it may not run, it does not; a run that only reads writes nothing;
// a command that would reach the network does not when no host is named.
func TestOnlyWhatIsDeclaredRuns(t *testing.T) {
	d, _ := testDriver(t, &agent.Shell{Programs: []string{"ls", "rm", "git"}})
	if _, err := do(t, d, "shell_run", map[string]any{"program": "cat", "args": []any{"x"}}); err == nil ||
		!strings.Contains(err.Error(), "not a program this agent may run") {
		t.Errorf("an undeclared program: %v", err)
	}
	if _, err := do(t, d, "shell_run", map[string]any{"program": "/bin/ls"}); err == nil {
		t.Error("a program named by its path ran")
	}
	if _, err := Find("git"); err == nil {
		if _, err := do(t, d, "shell_run", map[string]any{"program": "git", "args": []any{"fetch"}}); err == nil ||
			!strings.Contains(err.Error(), "may reach no host") {
			t.Errorf("a network command with no host: %v", err)
		}
	}
	ro, _ := testDriver(t, (&agent.Shell{Programs: []string{"ls", "rm"}}).ReadOnlyCopy())
	if _, err := do(t, ro, "file_write", map[string]any{"path": "a", "text": "b"}); err == nil {
		t.Error("a read-only run wrote a file")
	}
	if _, err := do(t, ro, "shell_run", map[string]any{"program": "rm", "args": []any{"-rf", "."}}); err == nil ||
		!strings.Contains(err.Error(), "only reads") {
		t.Errorf("a read-only run removed: %v", err)
	}
	if out, err := do(t, ro, "shell_run", map[string]any{"program": "ls"}); err != nil {
		t.Errorf("a read-only run could not read: %q %v", out, err)
	}
}

// A workspace over its quota takes no more writes, and may still be cleared.
func TestAWorkspaceOverItsQuotaTakesNoMore(t *testing.T) {
	d, _ := testDriver(t, &agent.Shell{Programs: []string{"rm"}, QuotaMB: 1})
	big := strings.Repeat("x", MaxWrite)
	if _, err := do(t, d, "file_write", map[string]any{"path": "a.txt", "text": big}); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, d, "file_write", map[string]any{"path": "b.txt", "text": big + "x"[:0]}); err != nil {
		t.Fatal(err) // still under, before this one
	}
	if _, err := do(t, d, "file_write", map[string]any{"path": "c.txt", "text": "more"}); err == nil || !strings.Contains(err.Error(), "over its") {
		t.Errorf("wrote past the quota: %v", err)
	}
	if out, err := do(t, d, "shell_run", map[string]any{"program": "rm", "args": []any{"a.txt", "b.txt"}}); err != nil {
		t.Errorf("could not remove to get under the quota: %q %v", out, err)
	}
}

// What waits for a person: whatever destroys, always; a shell, always; the
// network and writing when the declaration asks; nothing that only reads.
func TestWhatACommandCommitsToIsWeighed(t *testing.T) {
	d, _ := testDriver(t, &agent.Shell{Programs: []string{"ls", "rm", "sh", "git", "make"}, Hosts: []string{"github.com"},
		Ask: []string{"network"}})
	weigh := func(program string, args ...any) string {
		return d.Weighs(agent.Action{Op: "shell_run", Input: map[string]any{"program": program, "args": args}})
	}
	if why := weigh("ls", "-la"); why != "" {
		t.Errorf("ls was weighed: %q", why)
	}
	if why := weigh("rm", "notes.txt"); !strings.Contains(why, "deletes or rewrites history") {
		t.Errorf("rm: %q", why)
	}
	if why := weigh("sh", "-c", "ls"); !strings.Contains(why, "deletes") {
		t.Errorf("a shell: %q", why)
	}
	if why := weigh("git", "push", "origin", "main"); !strings.Contains(why, "reaches the network (github.com)") {
		t.Errorf("git push: %q", why)
	}
	if why := weigh("make"); why != "" {
		t.Errorf("make was weighed with writing not asked about: %q", why)
	}
	if why := weigh("cat", "x"); why != "" {
		t.Errorf("an undeclared program was weighed (it is refused instead): %q", why)
	}
	// Once the run holds something private and has read somebody else's
	// words, reaching the network carries the breaker's reason.
	d.Session.ReadFiles("README.md")
	d.Session.HoldsPrivate("a customer's address")
	if why := weigh("git", "push"); !strings.Contains(why, "a customer's address") {
		t.Errorf("the breaker is not in the reason: %q", why)
	}
	w, _ := testDriver(t, &agent.Shell{Programs: []string{"make"}, Ask: []string{"write"}})
	if why := w.Weighs(agent.Action{Op: "file_write", Input: map[string]any{"path": "x.go"}}); !strings.Contains(why, "writes x.go") {
		t.Errorf("a write asked about: %q", why)
	}
}

// A command that goes over the workspace's quota while it runs is stopped
// then, not found afterwards; and a reading command leaves nothing in the
// run's home for a later one to find.
func TestACommandIsStoppedWhenItGoesOverTheQuota(t *testing.T) {
	if _, err := Find("sh"); err != nil {
		t.Skip(err)
	}
	d, _ := testDriver(t, &agent.Shell{Programs: []string{"sh", "sed"}, QuotaMB: 1})
	start := time.Now()
	out, err := do(t, d, "shell_run", map[string]any{"program": "sh",
		"args": []any{"-c", "head -c 3000000 /dev/zero > big; sleep 60"}})
	if err != nil || !strings.Contains(out, "went over the workspace's 1 MiB") || time.Since(start) > 30*time.Second {
		t.Errorf("%q %v after %v", out, err, time.Since(start))
	}
	_ = d.Workspace.Write("in.txt", "hello\n")
	if _, err := Find("sed"); err == nil {
		planted := d.Box.Home + "/planted"
		_, _ = do(t, d, "shell_run", map[string]any{"program": "sed", "args": []any{"-n", "w " + planted, "in.txt"}})
		if _, err := os.Stat(planted); err == nil {
			t.Error("a reading command wrote the run's home")
		}
	}
}
