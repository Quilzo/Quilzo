// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// An agent's workspace and the commands it may run there, as its
// declaration says.
//
// The agent never holds a shell. It names a program it was given and the
// arguments, and Quilzo runs that one command in a box of its own against
// the agent's workspace (internal/shell): no shell to interpret anything,
// unless the declaration names one; no network unless the command is one
// that reaches it and the declaration names where; nothing left running
// when it ends. Files are read and written by Quilzo itself, through a
// handle on the workspace that cannot be walked out of.

// ShellCapabilities are the workspace's actions, each a capability.
var ShellCapabilities = []string{"file_list", "file_read", "file_write", "shell_run"}

// IsShell reports whether a capability is one of the workspace's.
func IsShell(op string) bool { return slices.Contains(ShellCapabilities, op) }

// Shell is what a declaration says about its workspace and commands.
type Shell struct {
	// Programs are the only ones it may run, by name, found on the box's
	// own path. A shell is a program like any other, and has to be named.
	Programs []string `json:"programs,omitempty"`
	// Hosts are what a command that reaches the network may reach, through
	// the run's proxy. None means no network for any command.
	Hosts []string `json:"hosts,omitempty"`
	// Ask is which kinds of command wait for a person: "network" and
	// "write". A command that deletes or rewrites history always does.
	Ask []string `json:"ask,omitempty"`
	// Workspace is the agent's folder, kept between runs: its own under
	// the store's directory when empty, or a folder named here.
	Workspace string `json:"workspace,omitempty"`
	// Timeout bounds each command (two minutes when zero); MemoryMB what it
	// may write in memory (2048); QuotaMB the workspace's size (2048).
	Timeout  Duration `json:"timeout,omitempty"`
	MemoryMB int      `json:"memory_mb,omitempty"`
	QuotaMB  int      `json:"quota_mb,omitempty"`
	// ReadOnly is set for a run that may only read (an evaluation, an agent
	// held to proposing, a read-only credential): only commands that read
	// run, and nothing is written. Never declared.
	ReadOnly bool `json:"-"`
}

// Bounds on a shell declaration.
const (
	MaxShellPrograms = 64
	MaxShellTimeout  = 30 * time.Minute
	MaxShellMemoryMB = 16 << 10
	MaxShellQuotaMB  = 64 << 10
)

var reProgram = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// Asks reports whether a kind of command waits for a person.
func (s *Shell) Asks(kind string) bool { return s != nil && slices.Contains(s.Ask, kind) }

// Runs reports whether the declaration names a program.
func (s *Shell) Runs(program string) bool { return s != nil && slices.Contains(s.Programs, program) }

// Reaches reports whether a command may reach host.
func (s *Shell) Reaches(host string) bool {
	return s != nil && !s.ReadOnly && slices.Contains(s.Hosts, strings.ToLower(host))
}

// CommandTimeout is how long each command may take.
func (s *Shell) CommandTimeout() time.Duration {
	if s == nil || s.Timeout <= 0 {
		return 2 * time.Minute
	}
	return time.Duration(s.Timeout)
}

// Memory is what each command may write in memory, in MiB.
func (s *Shell) Memory() int {
	if s == nil || s.MemoryMB <= 0 {
		return 2048
	}
	return s.MemoryMB
}

// Quota is the workspace's size, in MiB.
func (s *Shell) Quota() int {
	if s == nil || s.QuotaMB <= 0 {
		return 2048
	}
	return s.QuotaMB
}

// ReadOnlyCopy is the declaration for a run that may only read.
func (s *Shell) ReadOnlyCopy() *Shell {
	if s == nil {
		// No declaration is the empty one, and reading only holds for it
		// too: an agent may hold file_write with no "shell" block.
		return &Shell{ReadOnly: true}
	}
	c := *s
	c.Programs, c.Hosts, c.Ask = slices.Clone(s.Programs), nil, slices.Clone(s.Ask)
	c.ReadOnly = true
	return &c
}

// validateShell refuses a shell declaration that cannot mean what it
// appears to.
func (m *Manifest) validateShell() error {
	uses := map[string]bool{}
	for _, c := range m.Capabilities {
		if IsShell(c) {
			uses[c] = true
		}
	}
	sh := m.Shell
	if len(uses) == 0 {
		if sh != nil {
			return fmt.Errorf("%s declares a workspace and holds none of its capabilities (%s)",
				m.Name, strings.Join(ShellCapabilities, ", "))
		}
		return nil
	}
	if m.Program != nil {
		return fmt.Errorf("%s has a program and holds the workspace's capabilities; a program "+
			"already runs in its own box, and these are for agents Quilzo drives", m.Name)
	}
	if sh == nil {
		sh = &Shell{}
	}
	if uses["shell_run"] && len(sh.Programs) == 0 {
		return fmt.Errorf(`%s holds shell_run and names no program it may run: declare "shell": {"programs": [...]}`, m.Name)
	}
	if len(sh.Programs) > MaxShellPrograms {
		return fmt.Errorf("%s may run %d programs; at most %d", m.Name, len(sh.Programs), MaxShellPrograms)
	}
	seen := map[string]bool{}
	for _, p := range sh.Programs {
		switch {
		case !reProgram.MatchString(p):
			return fmt.Errorf("%s's shell names %q, which is not a program's name: a name, not a path", m.Name, p)
		case seen[p]:
			return fmt.Errorf("%s's shell names %s twice", m.Name, p)
		}
		seen[p] = true
	}
	if len(sh.Hosts) > MaxBrowserHosts {
		return fmt.Errorf("%s's shell may reach %d hosts; at most %d", m.Name, len(sh.Hosts), MaxBrowserHosts)
	}
	for _, h := range sh.Hosts {
		if h != strings.ToLower(h) || !reBrowserHost.MatchString(h) {
			return fmt.Errorf("%s's shell names %q, which is not one host name: lower case, "+
				"no scheme, port, path or wildcard", m.Name, h)
		}
	}
	for _, a := range sh.Ask {
		if a != "network" && a != "write" {
			return fmt.Errorf(`%s's shell asks about %q; it asks about "network" and "write"`, m.Name, a)
		}
	}
	if w := sh.Workspace; w != "" {
		if !filepath.IsAbs(w) || filepath.Clean(w) != w {
			return fmt.Errorf("%s's workspace is %q, which is not a clean absolute path", m.Name, w)
		}
		for _, sys := range []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
			"/sbin", "/sys", "/usr", "/var", "/home", "/tmp"} {
			if w == sys {
				return fmt.Errorf("%s's workspace is %s, a system folder; name a folder of its own", m.Name, w)
			}
		}
	}
	switch {
	case sh.Timeout < 0 || time.Duration(sh.Timeout) > MaxShellTimeout:
		return fmt.Errorf("%s's commands may take at most %s each", m.Name, MaxShellTimeout)
	case sh.MemoryMB < 0 || sh.MemoryMB > MaxShellMemoryMB:
		return fmt.Errorf("%s's commands may have at most %d MiB each", m.Name, MaxShellMemoryMB)
	case sh.QuotaMB < 0 || sh.QuotaMB > MaxShellQuotaMB:
		return fmt.Errorf("%s's workspace may be at most %d MiB", m.Name, MaxShellQuotaMB)
	}
	return nil
}

// narrowShell is the narrower of two shell declarations: the programs and
// hosts both name, every question either asks, the shorter limits, and the
// workspace only when both say the same.
func narrowShell(m, by *Shell) *Shell {
	if m == nil && by == nil {
		return nil
	}
	// A side with no declaration is the empty one: it narrows the other to
	// nothing it may run, and keeps reading only when it says so.
	if m == nil {
		m = &Shell{}
	}
	if by == nil {
		by = &Shell{}
	}
	out := &Shell{Workspace: m.Workspace, ReadOnly: m.ReadOnly || by.ReadOnly}
	for _, p := range by.Programs {
		if m.Runs(p) {
			out.Programs = append(out.Programs, p)
		}
	}
	for _, h := range by.Hosts {
		if slices.Contains(m.Hosts, h) {
			out.Hosts = append(out.Hosts, h)
		}
	}
	for _, a := range append(slices.Clone(m.Ask), by.Ask...) {
		if !slices.Contains(out.Ask, a) {
			out.Ask = append(out.Ask, a)
		}
	}

	out.Timeout = Duration(min(int64(m.CommandTimeout()), int64(by.CommandTimeout())))
	out.MemoryMB, out.QuotaMB = min(m.Memory(), by.Memory()), min(m.Quota(), by.Quota())
	slices.Sort(out.Programs)
	slices.Sort(out.Hosts)
	slices.Sort(out.Ask)
	return out
}

// FromWorkspace is a run that read its workspace: a file, or what a
// command printed.
const FromWorkspace SourceKind = "workspace"

// ReadFiles records that the run read from its workspace, what: words that
// may be somebody else's (a repository cloned, a file a page gave), so the
// run is tainted from here, as reading stored content taints it.
func (s *Session) ReadFiles(what string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tainted = true
	s.note(FromWorkspace, "workspace", what)
}
