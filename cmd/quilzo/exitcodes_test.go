// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
)

// The exit codes are the ones `quilzo help` documents: 2 for a command line
// that was wrong, 3 for a refusal by a gate, the access policy and the rule
// of two people among them, and 4 for a thing that is not there.
//
// The help tells a script to branch on the code rather than on the wording,
// and the codes were not what it said. A mistyped command, a subcommand
// nobody has, a flag a command does not define and a command missing its
// names all exited 1, as a command that ran and failed does; a reader's
// `publish` and an administrator approving their own request exited 1 too,
// so a script could not tell a refusal from a breakage; `agent show nope`
// exited 1 where nothing by that name is 4; and `siem zzbogus`, a format
// nobody has, exited 3 as though a gate had refused it.
func TestTheDocumentedExitCodes(t *testing.T) {
	root, owner := accessStore(t)

	// A reader, and the owner holding a token capped at publisher.
	if _, e, code := cliRun(t, root, owner, "auth", "grant", "rita", "reader"); code != 0 {
		t.Fatalf("auth grant rita reader: %s", firstLines(e, 3))
	}
	reader := issueToken(t, root, owner, "rt", "rita", "reader")
	capped := issueToken(t, root, owner, "pt", "owner", "publisher")

	// A second administrator, so that the next grant of admin waits for one,
	// and the owner's own request to approve.
	if _, e, code := cliRun(t, root, owner, "auth", "grant", "bob", "admin"); code != 0 {
		t.Fatalf("auth grant bob admin: %s", firstLines(e, 3))
	}
	if _, e, code := cliRun(t, root, owner, "auth", "grant", "carl", "admin"); code != 0 {
		t.Fatalf("auth grant carl admin: %s", firstLines(e, 3))
	}
	o, e, code := cliRun(t, root, owner, "--json", "pending", "list")
	var waiting []struct{ ID string }
	if code != 0 || json.Unmarshal([]byte(o), &waiting) != nil || len(waiting) != 1 {
		t.Fatalf("pending list: %d %s", code, firstLines(o+e, 4))
	}

	for _, c := range []struct {
		token string
		line  []string
		want  int
	}{
		{owner, []string{"pubish"}, out.ExitUsage},
		{owner, []string{"zzbogus"}, out.ExitUsage},
		{owner, []string{"token", "zzbogus"}, out.ExitUsage},
		{owner, []string{"add", "--bogus"}, out.ExitUsage},
		{owner, []string{"move"}, out.ExitUsage},
		{owner, []string{"agent", "show"}, out.ExitUsage},
		{owner, []string{"apps", "allow"}, out.ExitUsage},
		{owner, []string{"siem", "zzbogus"}, out.ExitUsage},

		{owner, []string{"agent", "show", "nope"}, out.ExitNotFound},
		{owner, []string{"auditlog", "show", "99999"}, out.ExitNotFound},
		{owner, []string{"pending", "show", "nope"}, out.ExitNotFound},
		{owner, []string{"member", "show", "nope"}, out.ExitNotFound},
		{owner, []string{"type", "show", "nope"}, out.ExitNotFound},
		{owner, []string{"ext", "remove", "nope"}, out.ExitNotFound},

		{reader, []string{"publish"}, out.ExitBlocked},
		{"", []string{"publish"}, out.ExitBlocked},
		{capped, []string{"config", "set", "today.brief", "false"}, out.ExitBlocked},
		{capped, []string{"auth", "grant", "zed", "reader"}, out.ExitBlocked},
		{owner, []string{"pending", "approve", waiting[0].ID}, out.ExitBlocked},
	} {
		_, e, code := cliRun(t, root, c.token, c.line...)
		if code != c.want {
			t.Errorf("`quilzo %s` exited %d, want %d (%s): %s", strings.Join(c.line, " "),
				code, c.want, out.Describe(c.want), firstLines(e, 2))
		}
	}
}

// issueToken is a token for who, capped at role, issued by the owner.
func issueToken(t *testing.T, root, owner, name, who, role string) string {
	t.Helper()
	o, e, code := cliRun(t, root, owner, "--json", "token", "issue", name, "--principal", who, "--role", role, "--ttl", "1h")
	var tok struct{ Token string }
	if code != 0 || json.Unmarshal([]byte(o), &tok) != nil || tok.Token == "" {
		t.Fatalf("token issue %s: exited %d: %s", name, code, firstLines(e, 3))
	}
	return tok.Token
}

// misuseSaid is whether the first line a command wrote to stderr refuses
// its command line: its usage, a subcommand it does not have, or a flag the
// flag package could not read.
var misuseSaid = regexp.MustCompile(`^(usage: |quilzo [a-z]|unknown [a-z -]*command |there is no "[^"]*" command|` +
	`flag provided but not defined: |flag needs an argument: |invalid value |invalid boolean |bad flag syntax: )`)

// firstErrLine is the first line of what a command wrote to stderr.
func firstErrLine(stderr string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(stderr), "\n")
	return line
}

// Every command line refuses a flag it does not take, and a refusal of the
// command line exits 2.
//
// The rule that a word a command does not take is refused was tried with
// words, and a flag got past it two ways. Most commands refused one with
// the flag package's own words and exit 1, which the help keeps for a
// command that ran and failed, so a script retrying failures retried a
// typo for ever. And the commands that read their names by hand took the
// flag for a name and went on with it, exit 0: `apps allow --zzflag`
// allowed apps from a host called "--zzflag", `checked clear --zzflag` and
// `scim unmap --zzflag` cleared and unmapped it, and `token keygen
// --zzflag` made a key. Every command the program dispatches, and every
// subcommand its code switches on or its help names, is given one.
func TestEveryCommandRefusesAFlagItDoesNotTakeWithTwo(t *testing.T) {
	asks := everyCommandLine(t)
	template := filepath.Join(t.TempDir(), ".quilzo")
	if _, e, code := cliRun(t, template, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	addPage(t, template, "", "index", "v1")
	for _, a := range asks {
		line := strings.Join(append(append([]string{}, a...), "--zzflag"), " ")
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			copyTree(t, template, filepath.Join(dir, ".quilzo"))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], append(append([]string{"quilzo-main"}, a...), "--zzflag")...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=", "NO_COLOR=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("`quilzo %s` did not refuse the flag and went on running", line)
			}
			if err == nil {
				t.Fatalf("`quilzo %s` exited 0:\n%s", line, firstLines(stdout.String()+stderr.String(), 3))
			}
			code := cmd.ProcessState.ExitCode()
			if said := firstErrLine(stderr.String()); misuseSaid.MatchString(said) && code != out.ExitUsage {
				t.Errorf("`quilzo %s` refused its command line and exited %d, not %d: %s",
					line, code, out.ExitUsage, said)
			}
		})
	}
}
