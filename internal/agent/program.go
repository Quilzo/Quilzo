// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Program is an agent's own program: a coding agent's command line, a
// script, a runtime somebody built an agent in. It decides for itself
// instead of a model choosing from the manifest, and it runs in a box
// (internal/agentbox), reaching the store only through the run's own
// interface, so the manifest bounds it exactly as it bounds a model.
type Program struct {
	// Command is the program and its arguments; the program is an
	// absolute path.
	Command []string `json:"command"`
	// Backend is where the box is: "native" (the default) or "openshell".
	Backend string `json:"backend,omitempty"`
	// Read are further paths it may read, beyond the system's own: the
	// directory it is installed in, say.
	Read []string `json:"read,omitempty"`
	// Env are its settings. Never a secret: a secret here is a secret in
	// the store's history. The run's credential is handed in by Quilzo.
	Env map[string]string `json:"env,omitempty"`
	// Image is what an OpenShell sandbox is made from (its --from): a
	// community sandbox's name or an image reference. The native box runs
	// the program from this machine.
	Image string `json:"image,omitempty"`
	// MemoryMB and CPUSeconds bound it; zero is Quilzo's default.
	MemoryMB   int `json:"memory_mb,omitempty"`
	CPUSeconds int `json:"cpu_seconds,omitempty"`
}

// Backends a program may run on.
var Backends = map[string]bool{"native": true, "openshell": true}

var reEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

var reImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)

// reservedEnv are names Quilzo sets in the box, which a declaration may
// not set for it.
var reservedEnv = []string{"QUILZO_", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"OPENAI_", "ANTHROPIC_", "HOME", "TMPDIR", "PATH", "LD_", "SSL_CERT"}

func (p *Program) validate(name string) error {
	if p == nil {
		return nil
	}
	if len(p.Command) == 0 || !filepath.IsAbs(p.Command[0]) || filepath.Clean(p.Command[0]) != p.Command[0] {
		return fmt.Errorf("%s's program is named by an absolute path, like /opt/agent/bin/run", name)
	}
	if len(p.Command) > 64 {
		return fmt.Errorf("%s's program has more than 64 arguments", name)
	}
	for _, a := range p.Command {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return fmt.Errorf("an argument of %s's program is not one", name)
		}
	}
	if p.Backend != "" && !Backends[p.Backend] {
		return fmt.Errorf("%q is not a backend; a program runs on native or openshell", p.Backend)
	}
	if len(p.Read) > 32 {
		return fmt.Errorf("%s's program reads more than 32 paths", name)
	}
	for _, r := range p.Read {
		if !filepath.IsAbs(r) || filepath.Clean(r) != r || r == "/" {
			return fmt.Errorf("%q is not a path %s's program may read: an absolute path, below the root", r, name)
		}
	}
	if len(p.Env) > 64 {
		return fmt.Errorf("%s's program has more than 64 settings", name)
	}
	for k, v := range p.Env {
		if !reEnvName.MatchString(k) {
			return fmt.Errorf("%q is not a setting's name (capitals, digits and _)", k)
		}
		for _, r := range reservedEnv {
			if k == r || strings.HasPrefix(k, r) && strings.HasSuffix(r, "_") {
				return fmt.Errorf("%s is set by Quilzo in the box, not by the declaration", k)
			}
		}
		if len(v) > 1024 || strings.ContainsAny(v, "\x00\n\r") {
			return fmt.Errorf("the setting %s is longer than a line", k)
		}
	}
	if p.Image != "" && (p.Backend != "openshell" || !reImage.MatchString(p.Image)) {
		return fmt.Errorf("%q is not an image an OpenShell sandbox is made from (and only that backend takes one)", p.Image)
	}
	if p.MemoryMB < 0 || p.MemoryMB > 65536 || p.CPUSeconds < 0 || p.CPUSeconds > 86400 {
		return fmt.Errorf("%s's program asks for limits out of range", name)
	}
	return nil
}

// FromProgram is a run whose every decision was a program's.
const FromProgram SourceKind = "program"

// DecidedBy marks a run as decided by a program. Like reading stored
// content, it taints the run from the start: what the program chose to do
// is not evidence anybody reviewed, so what the run produced goes live
// only when a person says so.
func (s *Session) DecidedBy(program string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tainted = true
	s.note(FromProgram, program, "")
}
