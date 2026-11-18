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

	"github.com/quilzo/quilzo/internal/backup"
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

// A secret shown once is alone on stdout, and what is said about it is on
// stderr.
//
// `token issue ci ... > ci.tok` and `export QUILZO_TOKEN=$(quilzo token
// issue ...)` are how a token is captured, and it is shown only once. Its
// stdout held a notice before it, that the only administrator approved it
// alone, and three lines of prose after it, so the file and the variable
// held something no command would take: `$(head -1 ci.tok)` was the notice.
// `backup key > bk.key` wrote the key and two paragraphs, and the backup the
// file was then named for was refused, "a backup key is 32 bytes, base64".
// `auth recover` already wrote its token alone; every command that shows a
// secret once does now, and `vault rotate`, which wrote its new key only for
// a person, answers it under --json as `vault enable` does.
func TestASecretShownOnceIsAloneOnStdout(t *testing.T) {
	root, owner := accessStore(t)
	addPage(t, root, owner, "index", "v1")
	example, _, code := cliRun(t, root, owner, "booking", "example")
	setup := filepath.Join(t.TempDir(), "booking.json")
	if code != 0 || os.WriteFile(setup, []byte(example), 0o600) != nil {
		t.Fatal("booking example")
	}
	if _, e, code := cliRun(t, root, owner, "booking", "setup", setup); code != 0 {
		t.Fatalf("booking setup: %s", firstLines(e, 3))
	}
	alone := func(t *testing.T, line ...string) string {
		t.Helper()
		o, e, code := cliRun(t, root, owner, line...)
		if code != 0 {
			t.Fatalf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
		secret := strings.TrimSuffix(o, "\n")
		if secret == "" || strings.ContainsAny(secret, "\n ") {
			t.Errorf("`quilzo %s` wrote %d line(s) to stdout, not the secret alone", strings.Join(line, " "),
				strings.Count(o, "\n"))
		}
		if strings.TrimSpace(e) == "" {
			t.Errorf("`quilzo %s` said nothing on stderr of what it showed", strings.Join(line, " "))
		}
		return secret
	}

	// The token works as it was captured.
	tok := alone(t, "token", "issue", "sub", "--principal", "owner", "--ttl", "1h")
	if _, e, code := cliRun(t, root, tok, "log"); code != 0 {
		t.Errorf("the token captured from stdout was refused: %s", firstLines(e, 2))
	}
	session := alone(t, "token", "exchange")
	if _, e, code := cliRun(t, root, session, "log"); code != 0 {
		t.Errorf("the session captured from stdout was refused: %s", firstLines(e, 2))
	}
	// The key reads back as a key.
	if k, err := backup.DecodeKey(alone(t, "backup", "key")); err != nil || len(k) == 0 {
		t.Errorf("the backup key captured from stdout does not read back: %v", err)
	}
	for _, line := range [][]string{
		{"scim", "token"},
		{"webhook", "add", "https://receiver.example/hook"},
		{"share", "index"},
		{"member", "invite"},
		{"auth", "enrol", "owner"},
		{"booking", "feed"},
	} {
		alone(t, line...)
	}

	// The vault's keys, last, since the store needs them from here on: the
	// key captured is the key the store opens with.
	first := alone(t, "vault", "enable", "--id", "k1")
	key := "QUILZO_KEY=k1=" + first
	if _, e, code := cliRunWith(t, []string{key}, root, owner, "log"); code != 0 {
		t.Errorf("the vault key captured from stdout does not open the store: %s", firstLines(e, 2))
	}
	o, e, code := cliRunWith(t, []string{key}, root, owner, "vault", "rotate", "--id", "k2")
	if second := strings.TrimSuffix(o, "\n"); code != 0 || second == "" || strings.ContainsAny(second, "\n ") {
		t.Errorf("`quilzo vault rotate` exited %d and wrote %d line(s) to stdout, not the key alone: %s",
			code, strings.Count(o, "\n"), firstLines(e, 2))
	} else {
		key += ",k2=" + second
	}
	o, e, code = cliRunWith(t, []string{key}, root, owner, "--json", "vault", "rotate", "--id", "k3")
	var doc struct{ ID, Key string }
	if code != 0 || json.Unmarshal([]byte(o), &doc) != nil || doc.ID != "k3" || doc.Key == "" {
		t.Errorf("`quilzo --json vault rotate` did not answer its new key in one document: exit %d, %d bytes: %s",
			code, len(o), firstLines(e, 2))
	}
}

// cliRunWith is cliRun with more of the environment.
func cliRunWith(t *testing.T, env []string, root, token string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"quilzo-main", "--root", root}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN="+token, "NO_COLOR=1"), env...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("`quilzo %s` did not finish", strings.Join(args, " "))
	}
	if err != nil && cmd.ProcessState == nil {
		t.Fatal(err)
	}
	return o.String(), e.String(), cmd.ProcessState.ExitCode()
}

// What goes to stderr is coloured as stderr is.
//
// The colour was decided by stdout alone, and /dev/null, a character device,
// passed for a terminal: `quilzo agent show nope >/dev/null 2>err.txt`, how a
// cron job keeps its errors, wrote the error into err.txt in escape codes.
func TestStderrIsNotColouredForStdout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skip(err)
	}
	defer null.Close()
	for _, line := range [][]string{
		{"agent", "show", "nope"},
		{"publish", "--zzflag"},
	} {
		cmd := exec.Command(os.Args[0], append([]string{"quilzo-main", "--root", root}, line...)...)
		cmd.Dir = t.TempDir()
		var env []string
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "NO_COLOR=") {
				env = append(env, kv)
			}
		}
		cmd.Env = append(env, "HOME="+t.TempDir(), "QUILZO_TOKEN=")
		var stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = null, &stderr
		if err := cmd.Run(); err == nil {
			t.Fatalf("`quilzo %s` exited 0", strings.Join(line, " "))
		}
		if strings.Contains(stderr.String(), "\033") {
			t.Errorf("`quilzo %s >/dev/null 2>FILE` wrote escape codes into the file: %q",
				strings.Join(line, " "), firstLines(stderr.String(), 2))
		}
	}
}

// A setter says what it set, and answers --json with it.
//
// Setting up the model route, the currency, a budget and a chatbot's action
// printed nothing and exited 0, while `config set`, `decide set` and `agent
// declare` each confirm; and the same commands answered --json with
// nothing, so a script could not tell a change made from one not reached.
func TestASetterSaysWhatItSet(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, root, "", "assistant", "add", "nyx", "--title", "Nyx"); code != 0 {
		t.Fatalf("assistant add: %s", firstLines(e, 3))
	}
	for _, c := range []struct {
		line []string
		says string
	}{
		{[]string{"gateway", "currency", "GBP"}, "GBP"},
		{[]string{"gateway", "route", "add", "studio", "--url", "http://127.0.0.1:19999/v1", "--model", "studio", "--personal"}, "studio"},
		{[]string{"gateway", "budget", "agent:front-desk", "--tokens-per-day", "200000", "--money-per-day", "5.00"}, "agent:front-desk"},
		{[]string{"gateway", "budget", "agent:front-desk", "--remove"}, "agent:front-desk"},
		{[]string{"gateway", "route", "remove", "studio"}, "studio"},
		{[]string{"assistant", "action", "nyx", "check-refund", "--kind", "link", "--target", "index", "--description", "how refunds work"}, "check-refund"},
		{[]string{"assistant", "action", "nyx", "check-refund", "--remove"}, "check-refund"},
		{[]string{"assistant", "remove", "nyx"}, "nyx"},
	} {
		name := strings.Join(c.line, " ")
		// Under --json first, on a copy, so the line is run on the store
		// as it stands for each.
		dir := filepath.Join(t.TempDir(), "st")
		copyTree(t, root, dir)
		o, e, code := cliRun(t, dir, "", append([]string{"--json"}, c.line...)...)
		var doc any
		if code != 0 || json.Unmarshal([]byte(o), &doc) != nil || doc == nil {
			t.Errorf("`quilzo --json %s` exited %d and answered %d bytes that are not a document: %s",
				name, code, len(o), firstLines(e, 2))
		}
		o, e, code = cliRun(t, root, "", c.line...)
		if code != 0 {
			t.Fatalf("`quilzo %s` exited %d: %s", name, code, firstLines(e, 3))
		}
		if !strings.Contains(o, c.says) {
			t.Errorf("`quilzo %s` said %q, nothing of what it set", name, firstLines(o, 2))
		}
	}
}

// Under --json a write answers one document, saying what it did.
//
// The help says stdout carries one document under --json, and writes
// answered three ways: a document, prose a parser chokes on (`auth grant
// jj author`, `auth revoke`, `auth deny`, `token revoke`, `provenance set`,
// `menu add`, `agent new`), or nothing at all with exit 0 (`add`,
// `publish`, `redirect add`, `config set`, `env add`, `theme unset`,
// `memory forget`, `schedule add`, `lang init`, `fediverse block`,
// `newsletter export`). `auth grant` was a document for a job and prose for
// a role, and a deployment script could not learn the commit `add` and
// `publish` made. Each is run here, in order, on one store, as a script
// setting a site up runs them.
func TestAWriteAnswersOneDocument(t *testing.T) {
	root, owner := accessStore(t)
	page := filepath.Join(t.TempDir(), "home.json")
	if err := os.WriteFile(page, []byte(`{"title":"Home","body":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := map[string]any{}
	for _, c := range []struct {
		line []string
		// has is a field the document must carry: what the write did.
		has string
	}{
		{[]string{"add", "index=" + page, "-m", "j1"}, "commit"},
		{[]string{"provenance", "set", "index", "--source", "humanEdits", "--author", "owner"}, "page"},
		{[]string{"publish", "--no-a11y-check"}, "commit"},
		{[]string{"auth", "grant", "jj", "author"}, "role"},
		{[]string{"auth", "grant", "kk", "analyst", "--for", "720h"}, ""},
		{[]string{"auth", "revoke", "jj", "author"}, "removed"},
		{[]string{"auth", "deny", "jj", "publisher"}, "role"},
		{[]string{"token", "issue", "ci", "--principal", "owner", "--role", "reader", "--ttl", "1h"}, "id"},
		{[]string{"token", "revoke", "TOKEN-ID"}, "id"},
		{[]string{"menu", "add", "foot", "--label", "Home", "--target", "index"}, "item"},
		{[]string{"redirect", "add", "/old", "/index"}, "from"},
		{[]string{"config", "set", "site.name", "Hello"}, "key"},
		{[]string{"env", "add", "staging"}, "name"},
		{[]string{"theme", "unset", "color.accent"}, "removed"},
		{[]string{"memory", "forget"}, "removed"},
		{[]string{"schedule", "add", "48h"}, "commit"},
		{[]string{"agent", "new", "b1", "--kind", "operator"}, "name"},
		{[]string{"lang", "init", "en"}, "default"},
		{[]string{"fediverse", "block", "bad.example"}, "blocked"},
		{[]string{"newsletter", "export"}, ""},
	} {
		line := append([]string{}, c.line...)
		for i, a := range line {
			if a == "TOKEN-ID" {
				line[i], _ = tok["id"].(string)
			}
		}
		name := strings.Join(c.line, " ")
		o, e, code := cliRun(t, root, owner, append([]string{"--json"}, line...)...)
		if code != 0 {
			t.Errorf("`quilzo --json %s` exited %d: %s", name, code, firstLines(e, 3))
			continue
		}
		dec := json.NewDecoder(strings.NewReader(o))
		var doc any
		if err := dec.Decode(&doc); err != nil {
			t.Errorf("`quilzo --json %s` did not answer a JSON document: %q", name, firstLines(o, 2))
			continue
		}
		if dec.More() {
			t.Errorf("`quilzo --json %s` answered more than one document: %q", name, firstLines(o, 4))
		}
		fields, _ := doc.(map[string]any)
		if c.has != "" {
			if _, ok := fields[c.has]; !ok {
				t.Errorf("`quilzo --json %s` answered %.160s, without %q", name, o, c.has)
			}
		}
		if c.line[0] == "token" && c.line[1] == "issue" {
			tok = fields
		}
	}
}
