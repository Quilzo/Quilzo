// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func programManifest(p *Program) Manifest {
	return Manifest{Name: "coder", Kind: KindTask, Purpose: "fix the docs", Capabilities: []string{"read_page"},
		Autonomy: AutonomyDraft, Budget: Budget{Steps: 5, Tools: 1, Duration: Duration(time.Hour)}, Program: p}
}

func TestAProgramIsDeclaredSoItCanBeConfined(t *testing.T) {
	known := map[string]bool{"read_page": true}
	ok := &Program{Command: []string{"/opt/agent/bin/run", "--fast"}, Backend: "native",
		Read: []string{"/opt/agent"}, Env: map[string]string{"AGENT_MODE": "docs"}, MemoryMB: 512}
	m := programManifest(ok)
	if err := m.Validate(known); err != nil {
		t.Fatal(err)
	}
	bad := map[string]*Program{
		"relative":       {Command: []string{"run"}},
		"unclean":        {Command: []string{"/opt/../bin/sh"}},
		"no command":     {},
		"backend":        {Command: []string{"/bin/x"}, Backend: "docker"},
		"read root":      {Command: []string{"/bin/x"}, Read: []string{"/"}},
		"read relative":  {Command: []string{"/bin/x"}, Read: []string{"opt"}},
		"proxy setting":  {Command: []string{"/bin/x"}, Env: map[string]string{"HTTPS_PROXY": "http://evil"}},
		"quilzo setting": {Command: []string{"/bin/x"}, Env: map[string]string{"QUILZO_RUN_TOKEN": "x"}},
		"loader":         {Command: []string{"/bin/x"}, Env: map[string]string{"LD_PRELOAD": "/tmp/x.so"}},
		"lowercase":      {Command: []string{"/bin/x"}, Env: map[string]string{"mode": "x"}},
		"two lines":      {Command: []string{"/bin/x"}, Env: map[string]string{"MODE": "a\nb"}},
		"huge memory":    {Command: []string{"/bin/x"}, MemoryMB: 1 << 20},
	}
	for name, p := range bad {
		m := programManifest(p)
		if err := m.Validate(known); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	sup := programManifest(ok)
	sup.Kind, sup.Delegates = KindSupervisor, []string{"other"}
	if err := sup.Validate(known); err == nil || !strings.Contains(err.Error(), "supervisor") {
		t.Errorf("a supervisor with a program: %v", err)
	}
}

func TestARunAProgramDecidesIsTaintedFromTheStart(t *testing.T) {
	s := NewSession(programManifest(nil), nil)
	if s.Tainted() {
		t.Fatal("tainted before anything")
	}
	digest := "sha256:" + strings.Repeat("0f", 32)
	s.DecidedBy("/opt/agent/bin/run", digest)
	if !s.Tainted() {
		t.Fatal("a program's run is not tainted")
	}
	if p := Provenance(s.sourcesLocked(), 0); !strings.Contains(p, "decided by the program /opt/agent/bin/run ("+digest+")") {
		t.Fatalf("provenance %q", p)
	}
}

// A program was a path and nothing else, so the file at it could be
// replaced between the review and the run with nothing recorded. It is
// pinned to the file a person reviewed, and a file that is not that one
// any more, or was never pinned, is refused with how to review it again.
func TestAProgramIsPinnedToTheFileAPersonReviewed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho reviewed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := &Program{Command: []string{path}}
	if _, err := p.Check("coder"); err == nil || !strings.Contains(err.Error(), "never pinned") {
		t.Errorf("an unpinned program: %v", err)
	}
	if err := p.Pin(); err != nil || !strings.HasPrefix(p.Digest, "sha256:") {
		t.Fatalf("pinned %q: %v", p.Digest, err)
	}
	if now, err := p.Check("coder"); err != nil || now != p.Digest {
		t.Fatalf("the reviewed file was refused: %s %v", now, err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho replaced\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	now, err := p.Check("coder")
	if err == nil || now == p.Digest || !strings.Contains(err.Error(), "changed since it was reviewed") ||
		!strings.Contains(err.Error(), "quilzo agent program coder --pin") {
		t.Errorf("a replaced program: %s %v", now, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Check("coder"); err == nil {
		t.Error("a program that is not there was let run")
	}
	// A digest is a digest, and a sandbox's program is pinned by its image.
	known := map[string]bool{"read_page": true}
	for name, bad := range map[string]*Program{
		"a malformed digest":  {Command: []string{path}, Digest: "sha256:xyz"},
		"a sandbox's program": {Command: []string{path}, Backend: "openshell", Digest: "sha256:" + strings.Repeat("0f", 32)},
	} {
		m := programManifest(bad)
		if err := m.Validate(known); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	sandboxed := &Program{Command: []string{"/sandbox/run"}, Backend: "openshell"}
	if err := sandboxed.Pin(); err != nil || sandboxed.Digest != "" {
		t.Errorf("a sandbox's program was pinned to a file here: %q %v", sandboxed.Digest, err)
	}
	if _, err := sandboxed.Check("coder"); err != nil {
		t.Errorf("a sandbox's program: %v", err)
	}
	// Another file at the same path is a widening, like another command.
	old, new := programManifest(&Program{Command: []string{path}, Digest: "sha256:" + strings.Repeat("0f", 32)}),
		programManifest(&Program{Command: []string{path}, Digest: "sha256:" + strings.Repeat("1e", 32)})
	if d := DeltaOf(old, new); !d.Widens || !strings.Contains(d.Lines(), "not the one reviewed") {
		t.Errorf("a different file at the same path: %+v", d)
	}
}

// A script an interpreter runs is the program a person reviewed there. The
// pin covered only the command's first word, so "/usr/bin/python3
// /opt/agent/run.py" was pinned to python3, and run.py could be replaced
// after the review and still run, under a card and a receipt that said the
// program was pinned. Every file the command line names is pinned with it;
// a program whose command line names no other file keeps the file's own
// digest, which its author can work out with sha256sum.
func TestAScriptAnInterpreterRunsIsPinnedWithIt(t *testing.T) {
	dir := t.TempDir()
	interpreter, script := filepath.Join(dir, "interpreter"), filepath.Join(dir, "run.py")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(interpreter, "#!/bin/sh\nexec cat \"$@\"\n")
	write(script, "print('reviewed')\n")
	p := &Program{Command: []string{interpreter, "-u", script, "--goal", "tidy"}}
	if err := p.Pin(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Check("coder"); err != nil {
		t.Fatalf("the reviewed script was refused: %v", err)
	}
	write(script, "print('replaced')\n")
	if _, err := p.Check("coder"); err == nil || !strings.Contains(err.Error(), "changed since it was reviewed") {
		t.Errorf("a replaced script: %v", err)
	}
	write(script, "print('reviewed')\n")
	if _, err := p.Check("coder"); err != nil {
		t.Errorf("the reviewed script, put back: %v", err)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Check("coder"); err == nil {
		t.Error("a script that is not there any more was let run")
	}

	alone := &Program{Command: []string{interpreter, "--fast"}}
	if err := alone.Pin(); err != nil {
		t.Fatal(err)
	}
	if own, _ := FileDigest(interpreter); alone.Digest != own {
		t.Errorf("a program naming no other file is pinned to %s, not its own digest %s", alone.Digest, own)
	}
}
