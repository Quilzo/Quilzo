// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
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
	s.DecidedBy("/opt/agent/bin/run")
	if !s.Tainted() {
		t.Fatal("a program's run is not tainted")
	}
	if p := Provenance(s.sourcesLocked(), 0); !strings.Contains(p, "decided by the program /opt/agent/bin/run") {
		t.Fatalf("provenance %q", p)
	}
}
