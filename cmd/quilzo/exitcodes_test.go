// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
		{[]string{"publish", "--no-a11y-check", "--reason", "no templates in this store"}, "commit"},
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

// A refusal by the rule of two people exits 3 by whichever command it is
// reached, and a thing that is not there exits 4 whichever package said so.
//
// The codes were set where the errors were made in this program, so the
// rule of two people refusing `pending approve` of one's own request was 3
// while the same rule refusing `policy approve`, `feature approve` and
// `shield playbook approve` of one's own change was 1, as was approving
// alone in the day after another administrator was removed. And what was
// not there was 4 when this program said so and 1 when a package did:
// `token revoke`, `shield lift`, `apps disconnect`, `policy approve`,
// `newsletter dismiss`, `research show` and `auditlog prove` of an id
// nobody has. `siem zzbogus` on a new store, whose log is empty, said
// there were no events and exited 3 rather than refuse a format nobody
// has, 2.
func TestEveryRuleOfTwoAndEveryMissingThingHasItsCode(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, fresh, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, fresh, "", "siem", "zzbogus"); code != out.ExitUsage {
		t.Errorf("`quilzo siem zzbogus` on a store with an empty log exited %d, want %d: %s",
			code, out.ExitUsage, firstLines(e, 2))
	}

	root, owner := accessStore(t)
	want := func(code int, line ...string) string {
		t.Helper()
		o, e, got := cliRun(t, root, owner, line...)
		if got != code {
			t.Errorf("`quilzo %s` exited %d, want %d (%s): %s", strings.Join(line, " "),
				got, code, out.Describe(code), firstLines(e, 2))
		}
		return o
	}
	id := func(line ...string) string {
		t.Helper()
		o := want(0, append([]string{"--json"}, line...)...)
		var doc struct{ ID string }
		if json.Unmarshal([]byte(o), &doc) != nil || doc.ID == "" {
			t.Fatalf("`quilzo --json %s` answered no id: %s", strings.Join(line, " "), firstLines(o, 3))
		}
		return doc.ID
	}

	for _, line := range [][]string{
		{"token", "revoke", "nope"},
		{"shield", "lift", "nope"},
		{"shield", "playbook", "approve", "nope"},
		{"apps", "disconnect", "gr_nope"},
		{"policy", "approve", "nope"},
		{"policy", "withdraw", "nope"},
		{"newsletter", "dismiss", "nope"},
		{"research", "show", "nope"},
		{"auditlog", "prove", "99999"},
		{"type", "unbind", "index"},
		{"peer", "adopt", "nope"},
	} {
		want(out.ExitNotFound, line...)
	}

	// A second administrator, so that each change below waits for one, and
	// the owner approving their own is refused.
	want(0, "auth", "grant", "bob", "admin")
	want(out.ExitBlocked, "policy", "approve", id("policy", "propose", "ac-12_odp=8 hours", "--reason", "shorter"))
	example := want(0, "feature", "example")
	pkg := filepath.Join(t.TempDir(), "feature.json")
	if err := os.WriteFile(pkg, []byte(example), 0o600); err != nil {
		t.Fatal(err)
	}
	want(out.ExitBlocked, "feature", "approve", id("feature", "install", pkg))
	want(out.ExitBlocked, "shield", "playbook", "approve",
		id("shield", "playbook", "mode", "signin-attack", "watch", "--why", "quieter"))

	// The owner alone again, a moment after bob stopped being one, when
	// nobody approves alone for a day.
	want(0, "auth", "revoke", "bob", "admin")
	want(out.ExitBlocked, "policy", "approve", id("policy", "propose", "ac-12_odp=4 hours", "--reason", "shorter still"))
}

// A command line that is wrong exits 2 wherever its words are read: a word
// that is not of the kind the command takes, a word it does not take, and a
// flag it needs left out.
//
// `auditlog show ab` exited 2 and `auditlog prove ab` 1, as a command that
// ran and failed does, and so did some thirty others that read their own
// words: an id of the wrong shape (`feature approve`, `agent receipt`,
// `apps receipt`, `inbox show`), a NAME=VALUE without its = (`add`, `site
// fill`, `policy propose`, `records add`), a time or a number that is not
// one (`schedule add`, `engagement open --until`, `review require`), and a
// flag a command cannot go without (`token issue` without --principal,
// `agent new` without --kind, `menu add` without --label, `compliance ssp`
// without --impact). A script retrying failures retried each typo. Two read
// a number by its first digits: `auditlog prove 3x` proved entry 3, and
// `review require 2x` required two approvals and exited 0.
//
// And one rule, one code: `assist` without --author exited 1 where `media
// generate`, `film`, `speak` and `transcribe` refuse the same omission by
// the provenance gate, 3.
func TestAWrongCommandLineExitsTwoWhereverItIsRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	addPage(t, root, "", "index", "v1")
	for _, c := range []struct {
		want int
		line []string
	}{
		{out.ExitUsage, []string{"add", "ab"}},
		{out.ExitUsage, []string{"agent", "new", "b1"}},
		{out.ExitUsage, []string{"agent", "receipt", "ab"}},
		{out.ExitUsage, []string{"apps", "receipt", "ab"}},
		{out.ExitUsage, []string{"auditlog", "export", "ab"}},
		{out.ExitUsage, []string{"auditlog", "prove", "ab"}},
		{out.ExitUsage, []string{"auditlog", "prove", "3x"}},
		{out.ExitUsage, []string{"compliance", "ssp"}},
		{out.ExitUsage, []string{"engagement", "open", "ab"}},
		{out.ExitUsage, []string{"engagement", "open", "ab", "--until", "tomorrow"}},
		{out.ExitUsage, []string{"evolve", "run"}},
		{out.ExitUsage, []string{"feature", "approve", "ab"}},
		{out.ExitUsage, []string{"feature", "decline", "ab"}},
		{out.ExitUsage, []string{"inbox", "show", "ab"}},
		{out.ExitUsage, []string{"menu", "add", "main"}},
		{out.ExitUsage, []string{"newsletter", "remove", "ab"}},
		{out.ExitUsage, []string{"policy", "propose", "ab"}},
		{out.ExitUsage, []string{"posture", "suppress", "f1"}},
		{out.ExitUsage, []string{"records", "add", "ab"}},
		{out.ExitUsage, []string{"records", "add", "ab", "x"}},
		{out.ExitUsage, []string{"review", "require", "ab"}},
		{out.ExitUsage, []string{"review", "require", "2x"}},
		{out.ExitUsage, []string{"schedule", "add", "ab"}},
		{out.ExitUsage, []string{"schedule", "add", "48h", "--reason", "x"}},
		{out.ExitUsage, []string{"shield", "block", "ab"}},
		{out.ExitUsage, []string{"shield", "trust", "add", "ab"}},
		{out.ExitUsage, []string{"signals", "connect"}},
		{out.ExitUsage, []string{"site", "fill", "ab"}},
		{out.ExitUsage, []string{"token", "issue", "ab"}},

		{out.ExitBlocked, []string{"assist", "ab"}},
	} {
		_, e, code := cliRun(t, root, "", c.line...)
		if code != c.want {
			t.Errorf("`quilzo %s` exited %d, want %d (%s): %s", strings.Join(c.line, " "),
				code, c.want, out.Describe(c.want), firstLines(e, 2))
		}
	}
}

// A colour decided by stdout is written only to stdout.
//
// What is written to stderr is coloured as stderr is (noteRed and the
// rest), and the colours were changed at seventy-odd places that wrote to
// os.Stderr. Seven more wrote stdout's colours to stderr another way:
// through w.Err (an unreadable line in the audit log, as `quilzo siem`
// warns of it, and two warnings of `quilzo signals`), through a writer
// named for it (the warning that the store is in a container's own
// filesystem, and the one of a proxy not believed, which `quilzo serve
// 2>>serve.log` logged), or inside an error main then writes there (a
// conflict between two drafts, and `quilzo verify` finding the store
// altered). Each put escape codes into a log whenever stdout was a
// terminal and stderr was not.
func TestAStdoutColourIsWrittenOnlyToStdout(t *testing.T) {
	stdoutColours := map[string]bool{"bold": true, "dim": true, "green": true, "yellow": true, "red": true, "reset": true}
	paths, err := filepath.Glob("*.go")
	if err != nil || len(paths) < 100 {
		t.Fatalf("the package's sources were not found: %d, %v", len(paths), err)
	}
	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if pkg, ok := fn.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
				return true
			}
			// What an error says goes to stderr; what Fprint writes goes
			// where its first argument is.
			var args []ast.Expr
			switch {
			case fn.Sel.Name == "Errorf":
				args = call.Args
			case strings.HasPrefix(fn.Sel.Name, "Fprint"):
				if isStdoutWriter(call.Args[0]) {
					return true
				}
				args = call.Args[1:]
			default:
				return true
			}
			for _, a := range args {
				if id, ok := a.(*ast.Ident); ok && stdoutColours[id.Name] {
					t.Errorf("%s: %s is stdout's colour, written by fmt.%s somewhere else: use note%s",
						fset.Position(call.Pos()), id.Name, fn.Sel.Name,
						strings.ToUpper(id.Name[:1])+id.Name[1:])
				}
			}
			return true
		})
	}
}

// isStdoutWriter is whether a writer is the process's stdout, os.Stdout or w.Out
// (toStdout is whether a path a command was given means stdout).
func isStdoutWriter(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && ((x.Name == "os" && sel.Sel.Name == "Stdout") || (x.Name == "w" && sel.Sel.Name == "Out"))
}

// With stdout a terminal and stderr a file, what is written to the file
// has no escape codes in it: `quilzo siem jsonl -o export.jsonl 2>err.log`,
// at a terminal, of a log with a line in it that is not an entry.
func TestAWarningToAFileIsNotColouredForATerminal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a pseudo-terminal is opened here as Linux opens one")
	}
	tty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip(err)
	}
	defer tty.Close()
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	addPage(t, root, "", "index", "v1")
	f, err := os.OpenFile(auditPath(root), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not an entry\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command(os.Args[0], "quilzo-main", "--root", root, "siem", "jsonl",
		"-o", filepath.Join(t.TempDir(), "export.jsonl"))
	cmd.Dir = t.TempDir()
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "NO_COLOR=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "HOME="+t.TempDir(), "QUILZO_TOKEN=")
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = tty, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("siem jsonl: %v: %s", err, firstLines(stderr.String(), 3))
	}
	if !strings.Contains(stderr.String(), "not an entry") && !strings.Contains(stderr.String(), "not in this export") {
		t.Fatalf("the line that is not an entry was not warned of: %q", firstLines(stderr.String(), 3))
	}
	if strings.Contains(stderr.String(), "\033") {
		t.Errorf("the warning written to a file carried escape codes: %q", firstLines(stderr.String(), 2))
	}
}

// No templates to render against is a dependency missing, 5, which is what
// the help says 5 is for and the one example it gives.
//
// Nothing returned 5. `ipfs id`, `a11y`, `site`, `theme show` and `theme
// set` of a store with no templates exited 1, the code of a render that
// broke, so a script could not tell "start a site first" from a failure
// worth retrying. Publishing is still refused by its gate, 3: the check
// that could not run is the accessibility gate's.
func TestNoTemplatesIsADependencyMissing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	addPage(t, root, "", "index", "v1")
	for _, line := range [][]string{
		{"provenance", "set", "index", "--source", "humanEdits", "--author", "owner"},
		{"publish", "--no-a11y-check", "--reason", "this test has no templates"},
	} {
		if _, e, code := cliRun(t, root, "", line...); code != 0 {
			t.Fatalf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	for _, c := range []struct {
		want int
		line []string
	}{
		{out.ExitUnavailable, []string{"a11y"}},
		{out.ExitUnavailable, []string{"ipfs", "id"}},
		{out.ExitUnavailable, []string{"ipfs", "write", "-o", filepath.Join(t.TempDir(), "site")}},
		{out.ExitUnavailable, []string{"compliance", "accessibility"}},
		{out.ExitUnavailable, []string{"site", "--addr", "127.0.0.1:0"}},
		{out.ExitUnavailable, []string{"theme", "show"}},
		{out.ExitUnavailable, []string{"theme", "check"}},
		{out.ExitUnavailable, []string{"theme", "set", "scheme", "dark"}},

		{out.ExitBlocked, []string{"publish"}},
	} {
		_, e, code := cliRun(t, root, "", c.line...)
		if code != c.want {
			t.Errorf("`quilzo %s` with no templates exited %d, want %d (%s): %s", strings.Join(c.line, " "),
				code, c.want, out.Describe(c.want), firstLines(e, 2))
		}
	}
}
