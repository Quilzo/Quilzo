package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// Launching an extension inside a sandbox.
//
// Go cannot restrict a child between fork and exec: os/exec has no pre-exec
// hook, and Landlock applies to a thread rather than a process. So this program
// re-executes itself as a shim. The shim restricts its own locked thread and
// then execve's the extension, which inherits the domain — the only correct
// sequence from Go, and the reason internal/sandbox offers no other.
//
//	quilzo serve
//	  └─ exec: quilzo __sandbox --allow DIR -- /path/to/extension
//	       restrict this thread, then exec the extension
//
// The shim name starts with two underscores because it is not a command
// anybody types. It is in the privilege table with a reason, like every other
// dispatched name, because a name that is dispatched and undeclared is exactly
// the hole that table exists to close.

const sandboxCmd = "__sandbox"

// sandboxWrap returns the ext.Limits hook that puts an extension in a sandbox.
//
// Returns nil when this build cannot confine anything, so the command runs
// directly rather than through a shim that would only add a process. Nil is the
// honest answer: pretending to sandbox is the failure this whole package was
// written to avoid.
func sandboxWrap() func([]string) []string {
	if !sandbox.Supported() {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	// What an extension legitimately needs: the binaries it is made of, and a
	// temporary directory to work in. Deliberately not the store — an
	// extension is handed its input on stdin and answers on stdout, so it has
	// no reason to open the content store, and the store is where the tokens
	// and the key file live.
	allow := []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"}
	var reads []string
	for _, p := range allow {
		if _, err := os.Stat(p); err == nil {
			reads = append(reads, p)
		}
	}

	return func(argv []string) []string {
		out := []string{self, sandboxCmd}
		for _, p := range reads {
			out = append(out, "--allow", p)
		}
		out = append(out, "--allow-write", os.TempDir())
		return append(append(out, "--"), argv...)
	}
}

// cmdSandbox is the shim. It does not return on success.
func cmdSandbox(args []string) error {
	var reads, writes []string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--allow":
			if i+1 < len(args) {
				reads = append(reads, args[i+1])
				i++
			}
		case "--allow-write":
			if i+1 < len(args) {
				writes = append(writes, args[i+1])
				i++
			}
		case "--":
			rest = args[i+1:]
			i = len(args)
		}
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: quilzo %s [--allow DIR]... -- COMMAND [ARG]...",
			sandboxCmd)
	}
	target := rest[0]
	if !filepath.IsAbs(target) {
		// Resolved here rather than left to execve's PATH lookup, because the
		// sandbox may not permit reading the directories PATH names — and a
		// command that fails for that reason looks like a broken sandbox
		// rather than a missing absolute path.
		return fmt.Errorf(
			"%s needs an absolute command; %q would be looked up on PATH, "+
				"which a sandboxed process may not be able to read",
			sandboxCmd, target)
	}

	// The environment is already empty — internal/ext clears it before this
	// process is started — so nothing is passed on here either.
	return sandbox.RestrictAndExec(
		sandbox.Rules{Read: reads, ReadWrite: writes}, target, rest, nil)
}
