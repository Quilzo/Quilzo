// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// shells run whatever they are given: shells, and programs whose job is
// to run another program.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "fish": true, "ksh": true,
	"csh": true, "tcsh": true, "busybox": true, "toybox": true,
	"env": true, "xargs": true, "nohup": true, "timeout": true, "nice": true, "sudo": true, "su": true, "doas": true,
	"stdbuf": true, "setsid": true, "chrt": true, "ionice": true, "taskset": true, "flock": true, "unbuffer": true,
	"script": true, "watch": true, "time": true, "command": true, "exec": true, "strace": true, "ltrace": true,
	"gdb": true, "valgrind": true, "perf": true, "chroot": true, "unshare": true, "nsenter": true, "parallel": true,
	"expect": true, "run-parts": true}

// interpreters run a program; one given its code on the command line is
// a shell by another name.
var interpreters = map[string][]string{
	"python": {"-c"}, "python3": {"-c"}, "python2": {"-c"}, "pypy3": {"-c"},
	"node": {"-e", "--eval", "-p", "--print"}, "deno": {"eval"}, "bun": {"-e", "--eval"},
	"perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"}, "lua": {"-e"}, "Rscript": {"-e"}, "awk": {}, "gawk": {}, "mawk": {},
}

// netters reach the network and may write what they fetch.
var netters = map[string]Kind{
	// curl writes as easily as it reads (-o, -D, -c, --output-dir, -K).
	"curl": fetches, "wget": fetches, "ssh": anything, "scp": fetches, "sftp": fetches, "ftp": fetches,
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
	if flags, ok := interpreters[program]; ok {
		// awk's program is always given inline, and can run commands.
		if len(flags) == 0 || hasAny(args, flags...) || (p == "deno" && len(args) > 0 && args[0] == "eval") {
			return anything
		}
		return writes
	}
	if k, ok := netters[p]; ok {
		if p == "rsync" {
			switch {
			case hasAny(args, "-e", "--rsh", "--rsync-path"):
				return anything
			case hasAny(args, "--delete", "--delete-before", "--delete-during", "--delete-after", "--delete-delay",
				"--delete-excluded", "--remove-source-files", "--del"):
				return Kind{Writes: true, Network: true, Destroys: true}
			}
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
		// A sed script can also write (w) and run commands (e); a command
		// taken as reading gets the workspace read-only and no network,
		// so what it can do there is print.
		return Kind{}
	case "sort":
		switch {
		case hasAny(args, "--compress-program"):
			return anything
		case hasAny(args, "-o", "--output") || hasPrefix(args, "-o"):
			return writes
		}
		return Kind{}
	case "find":
		// find takes its options after its paths, and after "--" too.
		all := withoutDashDash(args)
		switch {
		case slices.Contains(all, "-delete"):
			return destroys
		case slices.ContainsFunc(all, func(a string) bool {
			return slices.Contains([]string{"-exec", "-execdir", "-ok", "-okdir"}, a)
		}):
			return anything
		case slices.ContainsFunc(all, func(a string) bool { return strings.HasPrefix(a, "-fprint") || a == "-fls" }):
			return writes
		}
		return Kind{}
	case "tar", "zip", "unzip", "cpio", "7z", "patch", "install", "cp", "mv", "ln", "mkdir", "touch", "chmod", "chown":
		return writes
	}
	return writes
}

func classifyReader(p string, args []string) Kind {
	switch p {
	case "gofmt":
		if hasAny(args, "-w") {
			return writes
		}
	case "rg":
		if hasAny(args, "--pre", "--hostname-bin", "--search-zip", "-z") {
			return anything
		}
	case "tree":
		if hasAny(args, "-o", "-R") {
			return writes
		}
	case "xxd":
		if hasAny(args, "-r", "-revert") || len(positional(args)) > 1 {
			return writes
		}
	case "less", "more":
		// LESSOPEN and a pager's own commands run programs.
		return anything
	}
	return Kind{}
}

// gitValued are git's own options that take a value as the next argument.
var gitValued = map[string]bool{"-C": true, "--git-dir": true, "--work-tree": true, "--namespace": true,
	"--attr-source": true, "--super-prefix": true, "--list-cmds": true}

// gitBare are git's own options that take no value.
var gitBare = map[string]bool{"-p": true, "--paginate": true, "-P": true, "--no-pager": true, "--bare": true,
	"--no-replace-objects": true, "--literal-pathspecs": true, "--glob-pathspecs": true, "--noglob-pathspecs": true,
	"--icase-pathspecs": true, "--no-optional-locks": true, "--no-advice": true, "--version": true, "--help": true}

// classifyGit reads a git command past its own options.
func classifyGit(args []string) Kind {
	sub, rest := "", []string(nil)
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, _, hasValue := strings.Cut(a, "=")
		switch {
		case gitValued[name]:
			if !hasValue {
				i++
			}
		case gitBare[a]:
		case strings.HasPrefix(a, "-"):
			// Configuration on the command line (-c, --config-env, --exec-path)
			// can make git run anything; so can an option this does not know.
			return anything
		default:
			sub, rest = a, args[i+1:]
			i = len(args)
		}
	}
	// What git runs on another machine, named here, it runs on this one.
	if hasAny(rest, "--upload-pack", "--receive-pack", "--exec") || (sub == "clone" && hasAny(rest, "-u")) {
		return anything
	}
	switch sub {
	case "", "help", "version", "var", "check-ignore", "count-objects", "cat-file", "rev-list", "name-rev",
		"merge-base", "whatchanged", "rev-parse", "describe", "shortlog", "ls-files", "ls-tree", "blame", "status":
		return Kind{}
	case "log", "diff", "show":
		if hasAny(rest, "--output", "--ext-diff", "--textconv") {
			return writes
		}
		return Kind{}
	case "grep":
		if hasAny(rest, "-O", "--open-files-in-pager") || hasPrefix(rest, "-O") {
			return anything
		}
		return Kind{}
	case "branch":
		if hasAny(rest, "-d", "-D", "--delete", "-f", "--force", "-M", "-C", "--set-upstream-to", "-u", "--unset-upstream") {
			return destroys
		}
		if len(positional(rest)) == 0 || hasAny(rest, "-l", "--list", "-a", "--all", "-r", "--remotes", "-v", "--verbose") {
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
		if hasAny(rest, "--get", "--get-all", "--list", "-l", "--get-regexp", "--show-origin") ||
			(len(rest) > 0 && (rest[0] == "get" || rest[0] == "list")) {
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
		if len(rest) > 0 && (rest[0] == "remove" || rest[0] == "prune") {
			return destroys
		}
		return writes
	case "remote":
		if len(rest) == 0 || (hasAny(rest, "-v", "--verbose") && len(positional(rest)) == 0) {
			return Kind{}
		}
		switch rest[0] {
		case "show", "update", "prune":
			return fetches
		case "remove", "rm":
			return destroys
		}
		return writes
	case "ls-remote":
		return network
	case "fetch", "pull", "clone", "submodule":
		if hasAny(rest, "--prune", "-p", "--prune-tags", "--force", "-f") && sub != "clone" {
			return Kind{Writes: true, Network: true, Destroys: true}
		}
		return fetches
	case "push":
		if hasAny(rest, "-f", "--force", "--force-with-lease", "--force-if-includes", "-d", "--delete", "--mirror", "--prune") ||
			slices.ContainsFunc(positional(rest), func(s string) bool { return strings.HasPrefix(s, "+") || strings.HasPrefix(s, ":") }) {
			return Kind{Writes: true, Network: true, Destroys: true}
		}
		return fetches
	case "reset", "rebase", "filter-branch", "filter-repo", "replace", "prune", "gc", "update-ref", "symbolic-ref",
		"rm", "mv", "notes", "am", "cherry-pick", "revert", "merge":
		switch sub {
		case "rm", "mv", "notes", "am", "cherry-pick", "revert", "merge":
			if !hasAny(rest, "--force", "-f", "--abort", "--quit", "--skip") {
				return writes
			}
		case "update-ref", "symbolic-ref":
			if !hasAny(rest, "-d", "--delete") && len(positional(rest)) < 2 {
				return writes
			}
		}
		return destroys
	case "clean":
		if hasAny(rest, "-n", "--dry-run") {
			return Kind{}
		}
		return destroys
	case "checkout", "restore", "switch":
		// Over the work tree's own changes, which nothing keeps.
		if slices.Contains(rest, "--") || slices.Contains(rest, ".") ||
			hasAny(rest, "-f", "--force", "-B", "--discard-changes", "--overwrite-ignore", "-C", "--force-create") ||
			(sub == "restore" && len(positional(rest)) > 0) {
			return destroys
		}
		return writes
	case "reflog":
		if len(rest) == 0 || rest[0] == "show" || rest[0] == "list" {
			return Kind{}
		}
		return destroys
	case "commit":
		if hasAny(rest, "--amend", "--fixup", "--squash") {
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
	// A tool named to run in the build's place runs whatever it is.
	if hasAny(args[1:], "-vettool", "-toolexec", "-exec", "-overlay") {
		return anything
	}
	switch args[0] {
	case "version", "env", "list", "doc", "help", "vet":
		if args[0] == "env" && hasAny(args[1:], "-w", "-u") {
			return writes
		}
		if args[0] == "list" && hasAny(args[1:], "-m", "-u") {
			return network
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

// hasAny reports whether any argument before "--" is one of the flags. A
// long flag is matched as GNU and git parse them: whole, with "=value",
// or by any unambiguous start ("--del" is "--delete"); short flags run
// together are matched one by one ("-fd" is -f and -d). Matching more than
// a program would is the safe way round: the command is asked about.
func hasAny(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if matchFlag(a, flags) {
			return true
		}
	}
	return false
}

func matchFlag(a string, flags []string) bool {
	if slices.Contains(flags, a) {
		return true
	}
	if strings.HasPrefix(a, "--") && len(a) > 2 {
		name, _, _ := strings.Cut(a, "=")
		for _, f := range flags {
			// Go's flag package, and others like it, take --w for -w.
			if len(f) > 1 && f[0] == '-' && f[1] != '-' && name == "-"+f {
				return true
			}
			if !strings.HasPrefix(f, "--") {
				continue
			}
			if name == f || (len(name) >= 4 && strings.HasPrefix(f, name)) {
				return true
			}
		}
		return false
	}
	if len(a) > 2 && a[0] == '-' {
		// -o=value and -ovalue for a short flag that takes one, and short
		// flags run together.
		for _, f := range flags {
			if len(f) == 2 && f[0] == '-' && f[1] != '-' && strings.ContainsRune(a[1:], rune(f[1])) {
				return true
			}
			if len(f) > 2 && f[0] == '-' && f[1] != '-' && (a == f || strings.HasPrefix(a, f+"=")) {
				return true
			}
		}
	}
	return false
}

// withoutDashDash is the arguments with "--" taken out, for a program
// that reads its options wherever they are.
func withoutDashDash(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != "--" {
			out = append(out, a)
		}
	}
	return out
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
