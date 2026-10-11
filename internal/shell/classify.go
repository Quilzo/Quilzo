// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package shell runs an agent's commands, one at a time, each in a box of
// its own against the agent's workspace, and reads and writes the
// workspace's files through a handle that cannot be walked out of.
package shell

import (
	"slices"
	"strings"
)

// What a command is, decided before it runs, from the program and its
// arguments alone. Deterministic, and deliberately coarse: a program this
// does not know is taken as writing, and what is taken as reaching the
// network is the only kind of command given a way out at all, so the class
// is enforced by the box and not only used to ask.

// Kind is what a command does.
type Kind struct {
	// Writes changes the workspace.
	Writes bool
	// Network reaches outside, through the run's proxy.
	Network bool
	// Destroys deletes, or rewrites history, in a way not taken back.
	Destroys bool
}

// Reads is a command that only reads.
func (k Kind) Reads() bool { return !k.Writes && !k.Network && !k.Destroys }

// String is the kind in words.
func (k Kind) String() string {
	var parts []string
	switch {
	case k.Destroys:
		parts = append(parts, "destroys")
	case k.Writes:
		parts = append(parts, "writes")
	}
	if k.Network {
		parts = append(parts, "reaches the network")
	}
	if len(parts) == 0 {
		return "reads"
	}
	return strings.Join(parts, ", ")
}

var (
	writes   = Kind{Writes: true}
	network  = Kind{Network: true}
	fetches  = Kind{Writes: true, Network: true}
	destroys = Kind{Writes: true, Destroys: true}
	// anything is a command that runs whatever it is given: a shell, xargs,
	// find -exec, git with configuration that names a command. It can
	// delete as easily as anything else, so it always waits for a person.
	anything = Kind{Writes: true, Network: true, Destroys: true}
	// connects reaches a host and may write what it brings back.
	connects = Kind{Writes: true, Network: true}
)

// readers only read, whatever their arguments: they print.
var readers = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "wc": true, "grep": true, "egrep": true,
	"fgrep": true, "rg": true, "stat": true, "file": true, "diff": true, "cmp": true, "du": true,
	"pwd": true, "echo": true, "printf": true, "true": true, "false": true, "which": true,
	"date": true, "tree": true, "sha256sum": true, "sha1sum": true, "md5sum": true, "basename": true,
	"dirname": true, "realpath": true, "readlink": true, "jq": true, "less": true, "more": true,
	"nl": true, "column": true, "cut": true, "tr": true, "comm": true, "od": true, "xxd": true,
	"strings": true, "uname": true, "id": true, "whoami": true, "seq": true, "test": true, "[": true,
	"gofmt": true,
}

// shells run whatever they are given.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "fish": true, "ksh": true,
	"env": true, "xargs": true, "nohup": true, "timeout": true, "nice": true, "sudo": true, "su": true, "doas": true}

// netters reach the network and may write what they fetch.
var netters = map[string]Kind{
	"curl": network, "wget": fetches, "ssh": anything, "scp": fetches, "sftp": fetches, "ftp": fetches,
	"nc": connects, "ncat": connects, "telnet": connects, "rsync": fetches, "git-lfs": fetches,
	"docker": anything, "podman": anything, "kubectl": anything, "gh": connects,
}

// removers delete, and nothing brings it back.
var removers = map[string]bool{"rm": true, "rmdir": true, "shred": true, "truncate": true, "unlink": true}

// Classify says what a command is.
func Classify(program string, args []string) Kind {
	p := strings.ToLower(program)
	switch {
	case shells[p]:
		return anything
	case removers[p]:
		return destroys
	case readers[p]:
		return classifyReader(p, args)
	}
	if k, ok := netters[p]; ok {
		if p == "curl" && hasAny(args, "-o", "-O", "--output", "--remote-name", "-T", "--upload-file") {
			return fetches
		}
		return k
	}
	switch p {
	case "git":
		return classifyGit(args)
	case "go":
		return classifyGo(args)
	case "npm", "pnpm", "yarn", "bun":
		return classifyNode(args)
	case "pip", "pip3", "uv", "pipx":
		return classifyPip(args)
	case "sed":
		if hasAny(args, "-i", "--in-place") || hasPrefix(args, "-i") {
			return writes
		}
		return Kind{}
	case "sort":
		if hasAny(args, "-o", "--output") || hasPrefix(args, "-o", "--output=") {
			return writes
		}
		return Kind{}
	case "find":
		switch {
		case hasAny(args, "-delete"):
			return destroys
		case hasAny(args, "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"):
			return anything
		}
		return Kind{}
	}
	return writes
}

func classifyReader(p string, args []string) Kind {
	if p == "gofmt" && hasAny(args, "-w") {
		return writes
	}
	return Kind{}
}

// classifyGit reads a git command past its own options.
func classifyGit(args []string) Kind {
	sub, rest := "", args
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "--config-env" || strings.HasPrefix(a, "--exec-path") || strings.HasPrefix(a, "-c"):
			// Configuration given on the command line can make git run
			// anything (an alias, a pager, a command to connect with).
			return anything
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			sub, rest = a, args[i+1:]
			i = len(args)
		}
	}
	switch sub {
	case "status", "log", "diff", "show", "blame", "ls-files", "ls-tree", "rev-parse", "grep", "describe",
		"shortlog", "cat-file", "rev-list", "name-rev", "merge-base", "whatchanged", "count-objects", "help",
		"version", "check-ignore", "var":
		return Kind{}
	case "branch":
		if hasAny(rest, "-d", "-D", "--delete", "-f", "--force", "-M") {
			return destroys
		}
		if len(positional(rest)) == 0 {
			return Kind{}
		}
		return writes
	case "tag":
		if hasAny(rest, "-d", "--delete", "-f", "--force") {
			return destroys
		}
		if len(positional(rest)) == 0 || hasAny(rest, "-l", "--list") {
			return Kind{}
		}
		return writes
	case "config":
		if hasAny(rest, "--get", "--get-all", "--list", "-l", "--get-regexp") {
			return Kind{}
		}
		return writes
	case "stash":
		if len(rest) > 0 && (rest[0] == "list" || rest[0] == "show") {
			return Kind{}
		}
		if len(rest) > 0 && (rest[0] == "drop" || rest[0] == "clear") {
			return destroys
		}
		return writes
	case "worktree":
		if len(rest) > 0 && rest[0] == "list" {
			return Kind{}
		}
		return writes
	case "remote":
		if len(rest) == 0 || hasAny(rest, "-v", "--verbose") && len(positional(rest)) == 0 {
			return Kind{}
		}
		if rest[0] == "show" || rest[0] == "update" || rest[0] == "prune" {
			return fetches
		}
		return writes
	case "fetch", "pull", "clone", "submodule", "ls-remote":
		if sub == "ls-remote" {
			return network
		}
		return fetches
	case "push":
		if hasAny(rest, "-f", "--force", "--force-with-lease", "--force-if-includes", "-d", "--delete", "--mirror", "--prune") ||
			slices.ContainsFunc(positional(rest), func(s string) bool { return strings.HasPrefix(s, "+") || strings.HasPrefix(s, ":") }) {
			return Kind{Writes: true, Network: true, Destroys: true}
		}
		return fetches
	case "reset":
		return destroys
	case "clean":
		if hasAny(rest, "-n", "--dry-run") {
			return Kind{}
		}
		return destroys
	case "checkout", "restore":
		// Over the work tree's own changes, which nothing keeps.
		if slices.Contains(rest, "--") || hasAny(rest, "-f", "--force", ".") || (sub == "restore" && len(positional(rest)) > 0) {
			return destroys
		}
		return writes
	case "rebase", "filter-branch", "filter-repo", "replace", "prune", "gc", "reflog":
		if sub == "reflog" && (len(rest) == 0 || rest[0] == "show") {
			return Kind{}
		}
		return destroys
	case "commit":
		if hasAny(rest, "--amend") {
			return destroys
		}
		return writes
	}
	return writes
}

func classifyGo(args []string) Kind {
	if len(args) == 0 {
		return Kind{}
	}
	switch args[0] {
	case "version", "env", "list", "doc", "help", "vet":
		if args[0] == "env" && hasAny(args[1:], "-w", "-u") {
			return writes
		}
		return Kind{}
	case "get", "install":
		if args[0] == "install" && !slices.ContainsFunc(args[1:], func(s string) bool { return strings.Contains(s, "@") }) {
			return writes
		}
		return fetches
	case "mod":
		if len(args) > 1 && (args[1] == "download" || args[1] == "tidy") {
			return fetches
		}
		if len(args) > 1 && (args[1] == "graph" || args[1] == "why" || args[1] == "verify") {
			return Kind{}
		}
		return writes
	}
	// build, test, run, generate, fmt: they write, and run what they built.
	return writes
}

func classifyNode(args []string) Kind {
	if len(args) == 0 {
		return writes
	}
	switch args[0] {
	case "install", "i", "ci", "add", "update", "upgrade", "up", "dedupe", "rebuild", "exec", "x", "dlx", "create", "init":
		return fetches
	case "publish", "unpublish", "deprecate", "owner", "access", "login", "adduser", "logout":
		return Kind{Writes: true, Network: true, Destroys: args[0] == "unpublish"}
	case "view", "info", "outdated", "audit", "search", "show":
		return network
	case "ls", "list", "why", "explain", "help", "--version", "-v", "config":
		if args[0] == "config" && len(args) > 1 && args[1] != "get" && args[1] != "list" {
			return writes
		}
		return Kind{}
	}
	return writes
}

func classifyPip(args []string) Kind {
	if len(args) == 0 {
		return Kind{}
	}
	switch args[0] {
	case "install", "download", "wheel", "sync", "add", "lock", "pip":
		return fetches
	case "uninstall", "remove":
		return destroys
	case "list", "show", "freeze", "check", "help", "--version", "tree":
		return Kind{}
	}
	return writes
}

// hasAny reports whether any argument is one of the flags.
func hasAny(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if slices.Contains(flags, a) {
			return true
		}
		// Short flags run together: -fd is -f and -d.
		if len(a) > 2 && a[0] == '-' && a[1] != '-' {
			for _, f := range flags {
				if len(f) == 2 && f[0] == '-' && f[1] != '-' && strings.ContainsRune(a[1:], rune(f[1])) {
					return true
				}
			}
		}
	}
	return false
}

func hasPrefix(args []string, prefixes ...string) bool {
	for _, a := range args {
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) && a != p {
				return true
			}
		}
	}
	return false
}

// positional are the arguments that are not flags.
func positional(args []string) []string {
	var out []string
	for i, a := range args {
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}
