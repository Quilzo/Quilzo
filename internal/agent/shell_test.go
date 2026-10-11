// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func shelled(caps []string, sh *Shell) Manifest {
	return Manifest{Name: "coder", Kind: KindTask, Purpose: "tidy the repository",
		Capabilities: caps, Autonomy: AutonomyDraft, Shell: sh,
		Budget: Budget{Steps: 20, Tools: 1, Duration: Duration(time.Minute)}}
}

// A workspace declaration says exactly what may run and where it may
// reach, and nothing that cannot mean what it appears to is accepted.
func TestAShellDeclarationMeansWhatItSays(t *testing.T) {
	run := []string{"shell_run"}
	ok := []Manifest{
		shelled(run, &Shell{Programs: []string{"git", "go"}}),
		shelled([]string{"file_read", "file_list"}, nil),
		shelled(run, &Shell{Programs: []string{"git"}, Hosts: []string{"github.com"}, Ask: []string{"network", "write"},
			Workspace: "/srv/work/site", Timeout: Duration(5 * time.Minute), MemoryMB: 4096, QuotaMB: 512}),
	}
	for _, m := range ok {
		if err := m.Validate(nil); err != nil {
			t.Errorf("%+v: %v", m.Shell, err)
		}
	}
	for _, c := range []struct {
		m    Manifest
		want string
	}{
		{shelled(run, nil), "names no program"},
		{shelled(run, &Shell{}), "names no program"},
		{shelled(nil, &Shell{Programs: []string{"git"}}), "holds none of its capabilities"},
		{shelled(run, &Shell{Programs: []string{"/usr/bin/git"}}), "not a program's name"},
		{shelled(run, &Shell{Programs: []string{"../git"}}), "not a program's name"},
		{shelled(run, &Shell{Programs: []string{"git", "git"}}), "twice"},
		{shelled(run, &Shell{Programs: []string{"git"}, Hosts: []string{"*.github.com"}}), "not one host name"},
		{shelled(run, &Shell{Programs: []string{"git"}, Ask: []string{"everything"}}), `"network" and "write"`},
		{shelled(run, &Shell{Programs: []string{"git"}, Workspace: "relative/dir"}), "clean absolute path"},
		{shelled(run, &Shell{Programs: []string{"git"}, Workspace: "/srv/../etc"}), "clean absolute path"},
		{shelled(run, &Shell{Programs: []string{"git"}, Workspace: "/etc"}), "system folder"},
		{shelled(run, &Shell{Programs: []string{"git"}, Timeout: Duration(time.Hour)}), "at most"},
		{shelled(run, &Shell{Programs: []string{"git"}, QuotaMB: 1 << 20}), "at most"},
	} {
		err := c.m.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.m.Shell, err, c.want)
		}
	}
	m := shelled(run, &Shell{Programs: []string{"git"}})
	m.Program = &Program{Command: []string{"/usr/bin/true"}}
	if err := m.Validate(nil); err == nil || !strings.Contains(err.Error(), "has a program") {
		t.Errorf("a program with a workspace: %v", err)
	}
}

// Handing work on narrows the workspace too; a run that may only read
// reaches nothing.
func TestAShellIsNarrowedLikeEverythingElse(t *testing.T) {
	parent := &Shell{Programs: []string{"git", "go", "make"}, Hosts: []string{"github.com", "proxy.golang.org"},
		Ask: []string{"network"}, Timeout: Duration(10 * time.Minute)}
	child := &Shell{Programs: []string{"go", "curl"}, Hosts: []string{"proxy.golang.org", "evil.example.net"},
		Ask: []string{"write"}, Timeout: Duration(time.Minute)}
	got := narrowShell(parent, child)
	want := &Shell{Programs: []string{"go"}, Hosts: []string{"proxy.golang.org"}, Ask: []string{"network", "write"},
		Timeout: Duration(time.Minute), MemoryMB: 2048, QuotaMB: 2048}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("narrowed to %+v, want %+v", got, want)
	}
	ro := parent.ReadOnlyCopy()
	if !ro.ReadOnly || ro.Reaches("github.com") || len(ro.Hosts) != 0 || !ro.Runs("git") {
		t.Errorf("read-only: %+v", ro)
	}
	if parent.ReadOnly || len(parent.Hosts) != 2 {
		t.Error("the read-only copy changed the declaration")
	}
}

// An agent holding file_write with no "shell" block reads only when its
// run may only read, like one with a block.
func TestNoShellBlockStillReadsOnly(t *testing.T) {
	var none *Shell
	if ro := none.ReadOnlyCopy(); ro == nil || !ro.ReadOnly {
		t.Errorf("read-only of no declaration: %+v", ro)
	}
	if got := narrowShell(&Shell{ReadOnly: true}, nil); got == nil || !got.ReadOnly {
		t.Errorf("narrowed with no declaration: %+v", got)
	}
	if narrowShell(nil, nil) != nil {
		t.Error("two absent declarations made one")
	}
}

// A file's whole text is not kept in the run's record: its size and digest
// are.
func TestAFilesTextIsNotKeptWhole(t *testing.T) {
	text := strings.Repeat("<", MaxStored*3)
	tr := Trace{Agent: "coder", Steps: []Step{{N: 1, Action: Action{Op: "file_write", Input: map[string]any{"path": "a", "text": text}}}},
		Waiting: &Pending{N: 2, Action: Action{Op: "file_write", Input: map[string]any{"path": "b", "text": text}}}}
	rec := Keep("run-1", "dana", "", time.Now(), tr, Receipt{})
	for _, a := range []Action{rec.Trace.Steps[0].Action, rec.Trace.Waiting.Action} {
		kept, _ := a.Input["text"].(string)
		if len(kept) > 200 || !strings.Contains(kept, "sha256:") || a.Input["path"] == nil {
			t.Errorf("kept %q", kept)
		}
	}
	if tr.Steps[0].Action.Input["text"] != text {
		t.Error("keeping the record changed the run's own action")
	}
}
