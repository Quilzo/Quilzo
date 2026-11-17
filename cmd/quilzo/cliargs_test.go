// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// cliRun is the command line itself, run as a caller runs it, with what it
// printed and the code it exited with. These findings were about what the
// whole line did, global flags and dispatch included, so a test of one
// command's function would have missed half of them.
func cliRun(t *testing.T, root, token string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	full := append([]string{"quilzo-main"}, args...)
	if root != "" {
		full = append([]string{"quilzo-main", "--root", root}, args...)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], full...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN="+token, "NO_COLOR=1")
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("`quilzo %s` did not finish: %s", strings.Join(args, " "), firstLines(o.String()+e.String(), 6))
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return o.String(), e.String(), code
}

// accessStore is a store with an administrator and a token for them, which
// is the store these commands were run on when they went wrong: with access
// control on, every command needs one.
func accessStore(t *testing.T) (root, token string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init", "--admin", "owner"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	o, e, code := cliRun(t, root, "", "token", "issue", "boot", "--principal", "owner", "--role", "admin", "--json")
	if code != 0 {
		t.Fatalf("token issue: %s", e)
	}
	var tok struct{ Token string }
	if err := json.Unmarshal([]byte(o), &tok); err != nil || tok.Token == "" {
		t.Fatalf("token issue answered no token: %v", err)
	}
	return root, tok.Token
}

// bindingsOf is what the policy holds for one principal, as role, resource
// and whether it denies.
func bindingsOf(t *testing.T, root, who string) []string {
	t.Helper()
	p, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range p.Bindings {
		if b.Principal == who {
			s := string(b.Role) + " " + b.Resource
			if b.Deny {
				s += " deny"
			}
			got = append(got, s)
		}
	}
	return got
}

// `auth deny` granted the role it was asked to deny whenever any word
// followed its flags.
//
// It was authGrant with "--deny" appended to the end of the line, and Go's
// flag parser stops at the first word that is not a flag. So `auth deny dana
// publisher --note contract ended` stopped at "ended", never reached the
// --deny, and made dana a publisher; `auth deny erin admin everywhere` made
// erin an administrator. A deny that grants is the worst thing an access
// tool can do with a typo, so the deny is a parameter now rather than a word
// on the line, and the stray word is refused.
func TestAuthDenyNeverGrants(t *testing.T) {
	root, token := accessStore(t)
	for _, line := range [][]string{
		{"auth", "deny", "dana", "publisher", "--note", "contract", "ended"},
		{"auth", "deny", "erin", "admin", "everywhere"},
		{"auth", "deny", "ann", "publisher", "--on", "/legal", "/blog"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code == 0 {
			t.Errorf("`quilzo %s` exited 0; a word it does not take is refused", strings.Join(line, " "))
		}
		if !strings.Contains(e, "usage") {
			t.Errorf("`quilzo %s` was refused without its usage: %s", strings.Join(line, " "), e)
		}
		if got := bindingsOf(t, root, line[2]); len(got) != 0 {
			t.Errorf("`quilzo %s` left %v in the policy", strings.Join(line, " "), got)
		}
	}
	// The spellings the help shows still deny, flags before the names too.
	for _, line := range [][]string{
		{"auth", "deny", "dana", "publisher", "--note", "contract ended"},
		{"auth", "deny", "--on", "/legal", "ann", "publisher"},
		{"auth", "grant", "erin", "admin", "--deny"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Fatalf("`quilzo %s`: %s", strings.Join(line, " "), e)
		}
	}
	for who, want := range map[string]string{"dana": "publisher / deny", "ann": "publisher /legal deny", "erin": "admin / deny"} {
		if got := bindingsOf(t, root, who); !slices.Equal(got, []string{want}) {
			t.Errorf("%s holds %v, want [%s]", who, got, want)
		}
	}
}

// A word a command does not take is refused, never dropped.
//
// Go's flag parser stops at the first word that is not a flag and the
// commands never looked at what was left, so `--note covering for Bea --for
// 30d --on /news` kept the note "covering" and dropped the expiry and the
// scope with it: a permanent grant on the whole site, exit 0. The same
// silence kept the first word of a note, a lock's reason and a room's
// purpose, rolled the site back one step for `rollback 2`, made ./.quilzo
// for `init mysite` and checked the whole store for `verify everything`.
func TestAWordACommandDoesNotTakeIsRefused(t *testing.T) {
	root, token := accessStore(t)
	addPage(t, root, token, "index", "v1")
	for _, line := range [][]string{
		{"auth", "grant", "fay", "publisher", "--note", "covering", "for", "Bea", "--for", "30d", "--on", "/news"},
		{"auth", "revoke", "fay", "publisher", "now"},
		{"auth", "explain", "dana", "publish", "/blog"},
		{"token", "issue", "ci", "--principal", "owner", "--role", "reader", "--ttl", "1h", "for", "the", "CI", "job", "--on", "/docs"},
		{"note", "add", "index", "the", "price", "is", "wrong"},
		{"lock", "about", "--note", "editing", "hero", "image"},
		{"checked", "set", "index", "--note", "looks", "right", "to", "me"},
		{"room", "open", "r1", "--purpose", "plan", "the", "launch"},
		{"verify", "everything"},
		{"diff", "about"},
		{"config", "show", "site.name"},
		{"assistant", "remove", "help", "now"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code == 0 {
			t.Errorf("`quilzo %s` exited 0; a word it does not take is refused", strings.Join(line, " "))
			continue
		}
		if !strings.Contains(e, "usage") {
			t.Errorf("`quilzo %s` was refused without its usage: %s", strings.Join(line, " "), firstLines(e, 3))
		}
	}
	if got := bindingsOf(t, root, "fay"); len(got) != 0 {
		t.Errorf("the refused grant left %v in the policy", got)
	}
	o, _, _ := cliRun(t, root, token, "note", "list", "--json")
	if strings.Contains(o, `"the"`) {
		t.Errorf("the refused note was kept as its first word: %s", o)
	}
	o, _, _ = cliRun(t, root, token, "token", "list", "--json")
	if strings.Contains(o, `"ci"`) {
		t.Errorf("the refused token was issued: %s", o)
	}

	// init is the one command that makes a store, and the word it was given
	// was where the store was meant to go.
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "quilzo-main", "init", "mysite")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=")
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("`quilzo init mysite` exited 0: %s", b)
	}
	if !strings.Contains(string(b), "--root mysite init") {
		t.Errorf("`quilzo init mysite` did not say where a store goes: %s", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("`quilzo init mysite` made %s", entries[0].Name())
	}
}

// No command runs on words it does not take.
//
// The rule was made in the helpers and a script moved the commands over to
// them, and the commands it did not reach went on as before: `agents today`
// and `audit pages`, two of the commands the report named, `log 5`, `publish
// COMMIT extra`, `scim token 30`, and some fifty that list or show something
// and take nothing. A test of the lines in the report passes with every one
// of those still dropping its words. So every command the program
// dispatches, and every subcommand its code switches on, is given six words
// that mean nothing, on the real command line in a store of its own, and
// has to refuse. The few that take as many words as they are given are
// named here, each with what its words are.
func TestNoCommandRunsOnWordsItDoesNotTake(t *testing.T) {
	takesAny := map[string]string{
		"find":        "its words are what is searched for",
		"theme unset": "each word is a token to put back, and one that was not set is said, not refused",
	}

	asks := everyCommandLine(t)
	// A store with a page in it, published, so that a command about a page
	// or about what is live gets as far as its words.
	template := filepath.Join(t.TempDir(), ".quilzo")
	if _, e, code := cliRun(t, template, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	addPage(t, template, "", "index", "v1")
	for _, line := range [][]string{
		{"provenance", "set", "index", "--source", "humanEdits", "--author", "owner"},
		{"publish", "--no-a11y-check"},
	} {
		if _, e, code := cliRun(t, template, "", line...); code != 0 {
			t.Fatalf("`quilzo %s`: %s", strings.Join(line, " "), firstLines(e, 3))
		}
	}
	strays := []string{"zzw1", "zzw2", "zzw3", "zzw4", "zzw5", "zzw6"}

	used := map[string]bool{}
	for _, a := range asks {
		name := strings.Join(a, " ")
		if takesAny[name] != "" {
			used[name] = true
			continue
		}
		// The words alone, and after the page: a command that takes a page
		// refuses the first for not being one, and says nothing of the rest.
		for _, words := range [][]string{strays, append([]string{"index"}, strays...)} {
			line := strings.Join(append(append([]string{}, a...), words...), " ")
			t.Run(line, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				copyTree(t, template, filepath.Join(dir, ".quilzo"))
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], append(append([]string{"quilzo-main"}, a...), words...)...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=", "NO_COLOR=1")
				var said bytes.Buffer
				cmd.Stdout, cmd.Stderr = &said, &said
				err := cmd.Run()
				if ctx.Err() != nil {
					t.Fatalf("`quilzo %s` did not refuse them and went on running", line)
				}
				if err == nil {
					t.Errorf("`quilzo %s` exited 0:\n%s", line, firstLines(said.String(), 3))
				}
			})
		}
	}
	for name := range takesAny {
		if !used[name] {
			t.Errorf("%q is listed as taking any words and is not a command that was tried", name)
		}
	}
}

// everyCommandLine is every command the program dispatches, alone and with
// each subcommand its code switches on or its help names: the lines a rule
// for the whole command line is tried on.
func everyCommandLine(t *testing.T) [][]string {
	t.Helper()
	handler := dispatchHandlers(t)
	real := realSubcommands(t)
	// One spelling of each command: `forms` and `form` are one function.
	var asks [][]string
	asked, tried := map[string]bool{}, map[string]bool{}
	for _, c := range dispatchedCommands(t) {
		if strings.HasPrefix(c, "__") || handler[c] == "" || asked[handler[c]] {
			continue // the re-executed shims, and help and version, answered inline
		}
		asked[handler[c]] = true
		asks, tried[c] = append(asks, []string{c}), true
		for _, g := range real[c] {
			asks, tried[c+" "+g[0]] = append(asks, []string{c, g[0]}), true
		}
	}
	// And the subcommands the help names, for the commands whose switch is
	// in a function the dispatch does not call directly, as blog's is.
	for _, m := range regexp.MustCompile(`(?m)^  quilzo (\S+) ([a-z][a-z0-9-]*)(?: |$)`).FindAllStringSubmatch(usageText, -1) {
		if c, sub := m[1], m[2]; tried[c] && !tried[c+" "+sub] {
			asks, tried[c+" "+sub] = append(asks, []string{c, sub}), true
		}
	}
	// And a subcommand's own subcommands, which only the help names: `geo
	// network remove` is the third word of an alternative on geo's line, and
	// it dropped a second prefix while every line above refused.
	deeper := 0
	for _, m := range regexp.MustCompile(`(?m)^  quilzo (\S+) (.+?)(?:   .*)?$`).FindAllStringSubmatch(usageText, -1) {
		c := m[1]
		if !tried[c] {
			continue
		}
		for _, alternative := range strings.Split(m[2], " | ") {
			line := []string{c}
			for _, word := range strings.Fields(alternative) {
				if !helpSubcommand.MatchString(word) {
					break
				}
				line = append(line, word)
			}
			if name := strings.Join(line, " "); len(line) > 2 && !tried[name] {
				asks, tried[name] = append(asks, line), true
				deeper++
			}
		}
	}
	if len(asks) < 400 || deeper < 10 {
		t.Fatalf("only %d commands to try, %d of them three words deep; the command list was not read", len(asks), deeper)
	}
	return asks
}

// A word after a name the command does take is refused too, and a flag
// after it is read.
//
// These get past the test above, which gives a command words that are not
// names: the first is refused for what it is, and nothing is learnt of the
// rest. `publish COMMIT --no-a11y-check` stopped parsing at the commit and
// ran the check it was told to skip, `scim token now --revoke` made the
// identity provider a new token when asked to take its token away,
// `fediverse block a.example b.example` refused one instance and said
// nothing of the other, `auth dny dana publisher` printed the commands
// there are and exited 0, and `audit pages` reported no template with
// escaping off, of a directory that was not there.
func TestAWordAfterANameIsRefused(t *testing.T) {
	root, token := accessStore(t)
	addPage(t, root, token, "index", "v1")
	if _, e, code := cliRun(t, root, token, "provenance", "set", "index", "--source", "humanEdits", "--author", "owner"); code != 0 {
		t.Fatalf("provenance: %s", e)
	}
	o, _, _ := cliRun(t, root, token, "log", "--json")
	var hist struct{ Commits []struct{ ID string } }
	if err := json.Unmarshal([]byte(o), &hist); err != nil || len(hist.Commits) == 0 {
		t.Fatalf("log --json: %v\n%s", err, firstLines(o, 4))
	}
	commit := hist.Commits[0].ID

	for _, line := range [][]string{
		{"publish", commit, "extra"},
		{"render", "index", "page.html", "extra"},
		{"log", "5"},
		{"agents", "today"},
		{"scim", "token", "now", "--revoke"},
		{"fediverse", "block", "a.example", "b.example"},
		{"auth", "dny", "dana", "publisher"},
		{"audit", "pages"},
		{"spend", "lst"},
		{"compliance", "sbom", "a.json", "b.json"},
		{"theme", "show", "extra"},
		{"version", "now"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code == 0 {
			t.Errorf("`quilzo %s` exited 0: %s", strings.Join(line, " "), firstLines(e, 3))
		}
	}
	if o, _, _ := cliRun(t, root, token, "log", "--ref", "live", "--json"); strings.Contains(o, commit) {
		t.Errorf("the refused publish went live: %s", firstLines(o, 6))
	}
	if _, err := os.Stat(scimTokenPath(root)); err == nil {
		t.Error("`quilzo scim token now --revoke` made a provisioning token")
	}
	if o, _, _ := cliRun(t, root, token, "fediverse", "blocked", "--json"); strings.Contains(o, "a.example") {
		t.Errorf("the refused block was made of its first word: %s", firstLines(o, 6))
	}

	// The flag after the commit is read, and --revoke wherever it stands.
	if _, e, code := cliRun(t, root, token, "publish", commit, "--no-a11y-check"); code != 0 {
		t.Errorf("`quilzo publish COMMIT --no-a11y-check`: %s", firstLines(e, 4))
	}
	if _, e, code := cliRun(t, root, token, "scim", "token", "--days", "3", "--revoke"); code != 0 {
		t.Errorf("`quilzo scim token --days 3 --revoke`: %s", firstLines(e, 3))
	}
}

// A word after the names a command reads by hand is refused too.
//
// These read their names by index, args[0] and args[1], and looked at
// nothing after them. The test of every command gives each one words that
// are not names, so the first is refused for what it is and the rest are
// never reached; with the names right, the word after them was dropped.
// `auditlog verify-head head.json keys.json`, the --keys forgotten, checked
// the head against this machine's own keys and said it was verified. `peer
// add stage https://stage.example draft` paired with what is live there, not
// the draft. `saml remove okta azure` took one provider away and said
// nothing of the other, and `auth recover --reason locked out` went on with
// the reason "locked".
func TestAWordAfterNamesReadByHandIsRefused(t *testing.T) {
	root, token := accessStore(t)
	addPage(t, root, token, "index", "v1")
	dir := t.TempDir()
	for _, line := range [][]string{
		{"agent", "new", "bot", "--kind", "retrieval"},
		{"note", "add", "index", "the price is wrong"},
		{"peer", "add", "mirror", "https://mirror.example"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Fatalf("`quilzo %s`: %s", strings.Join(line, " "), firstLines(e, 3))
		}
	}
	o, _, _ := cliRun(t, root, token, "note", "list", "--json")
	var pages []struct{ Notes []struct{ ID string } }
	if err := json.Unmarshal([]byte(o), &pages); err != nil || len(pages) != 1 || len(pages[0].Notes) != 1 {
		t.Fatalf("note list --json: %v\n%s", err, firstLines(o, 4))
	}
	note := pages[0].Notes[0].ID
	written := func(name string, args ...string) string {
		t.Helper()
		o, e, code := cliRun(t, root, token, args...)
		if code != 0 {
			t.Fatalf("`quilzo %s`: %s", strings.Join(args, " "), firstLines(e, 3))
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(o), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	head := written("head.json", "auditlog", "head", "--json")
	bookings := written("bookings.json", "booking", "example")
	logs := filepath.Join(dir, "audit")
	if err := os.Mkdir(logs, 0o750); err != nil {
		t.Fatal(err)
	}

	for _, line := range [][]string{
		{"agent", "show", "bot", "extra"},
		{"auditlog", "dir", logs, "extra"},
		{"auditlog", "verify-head", head, filepath.Join(dir, "keys.json")},
		{"booking", "setup", bookings, "extra"},
		{"note", "resolve", "index", note, "extra"},
		{"note", "remove", "index", note, "extra"},
		{"peer", "add", "stage", "https://stage.example", "draft"},
		{"peer", "remove", "mirror", "extra"},
		{"peer", "pull", "mirror", "extra"},
		{"peer", "adopt", "mirror", "extra"},
		{"saml", "show", "okta", "extra"},
		{"saml", "metadata", "okta", "extra"},
		{"saml", "remove", "okta", "azure"},
		{"type", "stub", "article", "extra"},
		{"auth", "recover", "--principal", "owner", "--reason", "locked", "out", "--i-have-filesystem-access"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code != 2 || !strings.Contains(e, "does not take") {
			t.Errorf("`quilzo %s` exited %d, want 2 and the word it does not take: %s", strings.Join(line[:2], " ")+" …", code, firstLines(e, 3))
		}
	}
	// And none of them was done with the words that came first.
	if o, _, _ := cliRun(t, root, token, "note", "list", "--json"); !strings.Contains(o, note) {
		t.Errorf("a refused line resolved or removed the note: %s", firstLines(o, 6))
	}
	if o, _, _ := cliRun(t, root, token, "peer", "list", "--json"); !strings.Contains(o, "mirror") || strings.Contains(o, "stage") {
		t.Errorf("a refused line changed the peers: %s", firstLines(o, 8))
	}
	if o, _, _ := cliRun(t, root, token, "auditlog", "dir", "--json"); !strings.Contains(o, `"in_store": true`) {
		t.Errorf("the refused line moved the audit log: %s", firstLines(o, 4))
	}
	if o, _, _ := cliRun(t, root, token, "booking", "setup", "--json"); strings.TrimSpace(o) != "null" {
		t.Errorf("the refused line set bookings up: %s", firstLines(o, 4))
	}

	// The lines as the help writes them still run.
	for _, line := range [][]string{
		{"agent", "show", "bot"},
		{"auditlog", "verify-head", head},
		{"auditlog", "verify-head", head, "--keys", filepath.Join(root, "head.pub.json")},
		{"peer", "add", "stage", "https://stage.example", "--ref", "draft"},
		{"peer", "remove", "stage"},
		{"note", "resolve", "index", note},
		{"booking", "setup", bookings},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line[:2], " ")+" …", code, firstLines(e, 3))
		}
	}
}

// A named network is taken away or added whole, or not at all.
//
// `geo network` reads its words by hand, three deep, where the helpers and
// the test of every command did not reach. `geo network remove 10.0.0.0/8
// 192.168.0.0/16` took the first away, said nothing of the second and exited
// 0, and the office that was meant to stop being trusted still was. `geo
// network add PREFIX NAME --kind`, with the value forgotten, added the
// network with no kind at all, and a word after the last value was dropped.
func TestGeoNetworkRefusesAWordItDoesNotTake(t *testing.T) {
	root, token := accessStore(t)
	for _, line := range [][]string{
		{"geo", "network", "add", "10.0.0.0/8", "office", "--kind", "office"},
		{"geo", "network", "add", "192.168.0.0/16", "tunnel", "--kind", "vpn"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Fatalf("`quilzo %s`: %s", strings.Join(line, " "), firstLines(e, 3))
		}
	}
	for _, line := range [][]string{
		{"geo", "network", "remove", "10.0.0.0/8", "192.168.0.0/16"},
		{"geo", "network", "add", "10.2.0.0/16", "lab", "--kind"},
		{"geo", "network", "add", "10.3.0.0/16", "annex", "--kind", "office", "now"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code != 2 || !strings.Contains(e, "usage") {
			t.Errorf("`quilzo %s` exited %d, want 2 and its usage: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	o, _, _ := cliRun(t, root, token, "geo", "status", "--json")
	for _, prefix := range []string{"10.0.0.0/8", "192.168.0.0/16"} {
		if !strings.Contains(o, prefix) {
			t.Errorf("the refused removal took %s away: %s", prefix, firstLines(o, 8))
		}
	}
	for _, prefix := range []string{"10.2.0.0/16", "10.3.0.0/16"} {
		if strings.Contains(o, prefix) {
			t.Errorf("the refused line added %s: %s", prefix, firstLines(o, 8))
		}
	}
	// One prefix is still taken away.
	if _, e, code := cliRun(t, root, token, "geo", "network", "remove", "10.0.0.0/8"); code != 0 {
		t.Fatalf("`quilzo geo network remove 10.0.0.0/8`: %s", firstLines(e, 3))
	}
	if o, _, _ := cliRun(t, root, token, "geo", "status", "--json"); strings.Contains(o, "10.0.0.0/8") {
		t.Errorf("the network was not taken away: %s", firstLines(o, 8))
	}
}

// A word after a subcommand the list of every command does not find is
// refused too.
//
// That list reads the switch of the function the dispatch calls, and the
// subcommands the help spells out. A subcommand reached by an `if`, by a
// switch a function further down, or written in brackets in the help is in
// neither, and these went on dropping their words while every line the list
// held refused. `access review close q3` closed whichever review was open,
// `webhook test ID` sent the test to every endpoint and not to the one,
// `pending list mine` listed everybody's, and `siem stream send now`, `pay
// sync all` and `booking pause friday` did what they do with the word
// unread.
func TestAWordAfterASubcommandTheListMissesIsRefused(t *testing.T) {
	root, token := accessStore(t)
	if _, e, code := cliRun(t, root, token, "agent", "new", "bot", "--kind", "retrieval"); code != 0 {
		t.Fatalf("agent new: %s", firstLines(e, 3))
	}
	for _, line := range [][]string{
		{"access", "review", "start", "extra"},
		{"access", "review", "items", "extra"},
		{"access", "review", "close", "extra"},
		{"agent", "credential", "keys", "extra"},
		{"agent", "credential", "list", "bot", "extra"},
		{"agent", "template", "list", "extra"},
		{"agent", "trigger", "bot", "list", "extra"},
		{"booking", "pause", "extra"},
		{"booking", "resume", "extra"},
		{"gateway", "providers", "anthropic", "extra"},
		{"network", "show", "extra"},
		{"pay", "sync", "extra"},
		{"pending", "list", "extra"},
		{"shield", "decoy", "list", "extra"},
		{"shield", "playbook", "list", "extra"},
		{"shield", "trust", "list", "extra"},
		{"siem", "stream", "key", "extra"},
		{"siem", "stream", "send", "extra"},
		{"siem", "stream", "status", "extra"},
		{"theme", "layer", "show", "extra"},
		{"theme", "layer", "unset", "extra"},
		{"type", "example", "article", "extra"},
		{"webhook", "test", "extra"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code != 2 || !strings.Contains(e, "does not take") {
			t.Errorf("`quilzo %s` exited %d, want 2 and the word it does not take: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	// One video has a caption track taken off it, and a second was not
	// looked at.
	if _, e, _ := cliRun(t, root, token, "media", "captions", "v1", "v2", "--remove", "t1"); !strings.Contains(e, "usage: quilzo media captions VIDEO --remove TRACK") {
		t.Errorf("`quilzo media captions v1 v2 --remove t1` did not refuse the second video: %s", firstLines(e, 3))
	}
	// Without the word they answer as they did.
	for _, line := range [][]string{
		{"agent", "credential", "list", "bot"},
		{"agent", "template", "list"},
		{"agent", "trigger", "bot"},
		{"agent", "trigger", "bot", "list"},
		{"gateway", "providers", "anthropic"},
		{"network"},
		{"network", "show"},
		{"pending", "list"},
		{"shield", "decoy", "list"},
		{"shield", "playbook", "list"},
		{"shield", "trust", "list"},
		{"siem", "stream", "status"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
}

// A flag a command does not take is refused the way a word is.
//
// The commands that take no flags hand their words to a flag set with none
// in it, and the flag package answered for them: `verify --all` said "flag
// provided but not defined: -all", then "Usage of arguments:" with nothing
// under it, then the error again, and exited 1, which is a command that ran
// and failed. It is the command's own usage and exit 2, as for a word.
func TestAFlagACommandDoesNotTakeIsRefusedWithItsUsage(t *testing.T) {
	root, token := accessStore(t)
	for _, line := range [][]string{
		{"verify", "--all"},
		{"diff", "-p"},
		{"auth", "list", "--all"},
		{"config", "show", "--key", "site.name"},
		{"token", "list", "-x"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code != 2 || !strings.Contains(e, "does not take") || !strings.Contains(e, "  quilzo "+line[0]) {
			t.Errorf("`quilzo %s` exited %d, want 2 and its usage: %s", strings.Join(line, " "), code, firstLines(e, 4))
		}
		if strings.Contains(e, "Usage of arguments") || strings.Count(e, "not defined") > 0 {
			t.Errorf("`quilzo %s` was answered by the flag package: %s", strings.Join(line, " "), firstLines(e, 4))
		}
	}
	// What follows "--" is not a flag, and is refused as the word it is.
	if _, e, code := cliRun(t, root, token, "verify", "--", "--all"); code != 2 || !strings.Contains(e, "does not take") {
		t.Errorf("`quilzo verify -- --all` exited %d: %s", code, firstLines(e, 3))
	}
}

// A protection that is about no one thing takes no word.
//
// The shield's commands gather every word after their flags as the target,
// and lockdown and freeze, which have none, never looked at what was
// gathered. `shield freeze 6h --reason "…"`, the --for forgotten, froze
// publishing for the hour that is the default and said so in a line nobody
// reads twice during an incident: the protection ended five hours before it
// was meant to. The test of every command passed, since six words with no
// --reason are refused for the reason.
func TestShieldLockdownAndFreezeTakeNoWord(t *testing.T) {
	root, token := accessStore(t)
	for _, kind := range []string{"freeze", "lockdown"} {
		_, e, code := cliRun(t, root, token, "shield", kind, "6h", "--reason", "an incident")
		if code != 2 || !strings.Contains(e, "does not take") {
			t.Errorf("`quilzo shield %s 6h --reason …` exited %d, want 2 and the word it does not take: %s", kind, code, firstLines(e, 3))
		}
	}
	if o, _, _ := cliRun(t, root, token, "shield", "list", "--json"); strings.Contains(o, "sh-") {
		t.Errorf("a refused line put a protection in force: %s", firstLines(o, 8))
	}
	// With --for it is taken for as long as was asked.
	o, e, code := cliRun(t, root, token, "shield", "freeze", "--for", "6h", "--reason", "an incident")
	if code != 0 || !strings.Contains(o, "6 hours") {
		t.Errorf("`quilzo shield freeze --for 6h --reason …` exited %d: %s", code, firstLines(o+e, 3))
	}
}

// addPage drafts a page with the command line, as somebody would.
func addPage(t *testing.T, root, token, name, title string) {
	t.Helper()
	// A file of its own name, since a page's may hold a slash.
	page := filepath.Join(t.TempDir(), "page.json")
	if err := os.WriteFile(page, []byte(`{"title":"`+title+`","body":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, e, code := cliRun(t, root, token, "add", name+"="+page, "-m", title); code != 0 {
		t.Fatalf("add: %s", e)
	}
}

// `rollback 2` rolled the live site back one publication, not two.
//
// The 2 was a word rollback does not take, and it was dropped: what the
// public is served changed on a misread command, exit 0. It is refused, and
// --steps is how the number is given.
func TestRollbackRefusesANumberAsAWord(t *testing.T) {
	root, token := accessStore(t)
	for _, v := range []string{"v1", "v2", "v3"} {
		addPage(t, root, token, "index", v)
		if _, e, code := cliRun(t, root, token, "provenance", "set", "index", "--source", "humanEdits", "--author", "owner"); code != 0 {
			t.Fatalf("provenance: %s", e)
		}
		if _, e, code := cliRun(t, root, token, "publish", "--no-a11y-check"); code != 0 {
			t.Fatalf("publish %s: %s", v, e)
		}
	}
	live := func() string {
		o, _, _ := cliRun(t, root, token, "log", "--ref", "live", "--json")
		return o
	}
	before := live()
	_, e, code := cliRun(t, root, token, "rollback", "2")
	if code == 0 || !strings.Contains(e, "usage") {
		t.Errorf("`quilzo rollback 2` exited %d: %s", code, firstLines(e, 3))
	}
	if after := live(); after != before {
		t.Errorf("`quilzo rollback 2` moved the live site:\nbefore %s\nafter %s", firstLines(before, 6), firstLines(after, 6))
	}
	if _, e, code := cliRun(t, root, token, "rollback", "--steps", "2"); code != 0 {
		t.Errorf("`quilzo rollback --steps 2`: %s", firstLines(e, 3))
	}
}

// A mistyped word after `site` started the public server.
//
// `site fil` meant `site fill`; the word matched no subcommand, fell through
// to the server's flags, which ignored it, and the terminal hung on a site
// served to the network. Every other command group names its subcommands
// for a word it does not know, and this one does too now.
func TestSiteRefusesAWordItDoesNotKnow(t *testing.T) {
	root, token := accessStore(t)
	tpl := t.TempDir()
	if err := os.WriteFile(filepath.Join(tpl, "page.html"), []byte("<p>{{.Title}}</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, line := range [][]string{
		{"site", "fil"},
		{"site", "--addr", "127.0.0.1:0", "--templates", tpl, "report"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code == 0 || !strings.Contains(e, "fill") {
			t.Errorf("`quilzo %s` exited %d without naming the site commands: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
}

// Flags may come before the names a command takes, as they may after.
//
// leadingArgs gathered names only up to the first flag, so `auth grant --on
// /news fay publisher` found no names and answered with its usage, while
// `agent new --kind operator b2` took the same order. One rule for the whole
// command line, in the helper they share.
func TestFlagsMayComeBeforeTheNames(t *testing.T) {
	root, token := accessStore(t)
	for _, line := range [][]string{
		{"auth", "grant", "--on", "/news", "fay", "publisher"},
		{"auth", "grant", "gil", "--on", "/blog", "author"},
		{"token", "issue", "--principal", "owner", "--role", "reader", "--ttl", "1h", "ci"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	if got := bindingsOf(t, root, "fay"); !slices.Equal(got, []string{"publisher /news"}) {
		t.Errorf("fay holds %v, want [publisher /news]", got)
	}
	if got := bindingsOf(t, root, "gil"); !slices.Equal(got, []string{"author /blog"}) {
		t.Errorf("gil holds %v, want [author /blog]", got)
	}
}

// The two commands that took their name off the front by hand take it after
// their flags as well.
//
// `menu add --label Home --target index foot` is one of the lines the report
// gave, and it went on answering "one menu name, and the flags after it"
// once every command built on leadingArgs took the order: menu add and
// rights set read their first word for themselves, so the helper never saw
// them. A word past the name is refused as it is everywhere else.
func TestFlagsMayComeBeforeTheNameReadByHand(t *testing.T) {
	root, token := accessStore(t)
	addPage(t, root, token, "index", "v1")
	id := strings.Repeat("ab", 32)
	for _, line := range [][]string{
		{"menu", "add", "--label", "Home", "--target", "index", "foot"},
		{"menu", "add", "foot", "--label", "Start", "--target", "index", "--order", "2"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 0 {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	if o, _, _ := cliRun(t, root, token, "menu", "list", "--json"); !strings.Contains(o, "Home") || !strings.Contains(o, "Start") {
		t.Errorf("the menu does not hold both entries: %s", firstLines(o, 20))
	}
	// No file has this id, and in either order that is the answer.
	for _, line := range [][]string{
		{"rights", "set", "--licence", "CC0", "--holder", "Ada", id},
		{"rights", "set", id, "--licence", "CC0", "--holder", "Ada"},
	} {
		if _, e, code := cliRun(t, root, token, line...); code != 1 || !strings.Contains(e, "there is no file") {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line[:3], " ")+" …", code, firstLines(e, 3))
		}
	}
	for _, line := range [][]string{
		{"menu", "add", "foot", "--label", "Our", "shop", "--target", "index"},
		{"menu", "add", "foot", "side", "--label", "Shop", "--target", "index"},
		{"menu", "remove", "foot", "m1", "m2"},
		{"rights", "set", id, strings.Repeat("cd", 32), "--licence", "CC0"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code != 2 || !strings.Contains(e, "does not take") {
			t.Errorf("`quilzo %s` exited %d, want 2 and the word it does not take: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	if o, _, _ := cliRun(t, root, token, "menu", "list", "--json"); strings.Contains(o, "Our") || strings.Contains(o, "Shop") {
		t.Errorf("a refused line added to the menu: %s", firstLines(o, 12))
	}
}

// The refusal of a path written after `auth explain` says where a path goes.
//
// `auth explain dana publish /blog` answered about the whole site and said
// nothing of /blog. It is refused now, with the help's line for the command,
// and that line was "WHO [ACTION]": whoever typed the path was told it is not
// taken and not that --on takes it.
func TestAuthExplainSaysWhereThePathGoes(t *testing.T) {
	root, token := accessStore(t)
	_, e, code := cliRun(t, root, token, "auth", "explain", "dana", "publish", "/blog")
	if code != 2 || !strings.Contains(e, "--on PATH") {
		t.Errorf("`quilzo auth explain dana publish /blog` exited %d and did not name --on PATH: %s", code, firstLines(e, 3))
	}
	// Nobody has given dana anything, which is the answer about /blog and
	// exits 1 as a refusal does.
	o, e, code := cliRun(t, root, token, "auth", "explain", "dana", "publish", "--on", "/blog")
	if code == 2 || !strings.Contains(o+e, "dana publish on /blog") {
		t.Errorf("`quilzo auth explain dana publish --on /blog` exited %d: %s", code, firstLines(o+e, 3))
	}
}

// A command that takes as many names as it is given takes them.
//
// `research add NAME FILE…` gathers every leading word and was told it took
// one name, so with a project and a file in hand it went to refuse the
// second of no words after the flags and the program stopped on an index
// out of range: `quilzo research add proj notes.txt`, the command the line
// before it prints, was a panic. `research claim NAME VALUE… --run RUN` was
// too.
func TestACommandThatTakesManyNamesTakesThem(t *testing.T) {
	root, token := accessStore(t)
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, b, c := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt"), filepath.Join(dir, "c.txt")
	if _, e, code := cliRun(t, root, token, "research", "new", "proj", "--question", "does it hold"); code != 0 {
		t.Fatalf("research new: %s", firstLines(e, 3))
	}
	for _, line := range [][]string{
		{"research", "add", "proj", a},
		{"research", "add", "proj", a, b, "--to", "data"},
		{"research", "add", "proj", "--to", "more", c},
	} {
		o, e, code := cliRun(t, root, token, line...)
		if code != 0 || !strings.Contains(o, "added") {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line[:3], " ")+" …", code, firstLines(e, 3))
		}
	}
	// No such run, which is an answer; the panic was not.
	_, e, code := cliRun(t, root, token, "research", "claim", "proj", "mean", "median", "--run", "r1")
	if code != 1 || strings.Contains(e, "panic") {
		t.Errorf("`quilzo research claim proj mean median --run r1` exited %d: %s", code, firstLines(e, 3))
	}
}

// A "--" that is a flag's value is the value, and the flags go on after it.
//
// The loop took a "--" before the word it stopped at for the end of the
// flags, whichever it was. In `auth grant --note -- dana publisher --on
// /legal` the note is "--", and every word after it was taken for a name, the
// --on and its path among them: a flag read as a name, and the line refused
// for a word it does take.
func TestADoubleDashThatIsAValueDoesNotEndTheFlags(t *testing.T) {
	flags := func() (*flag.FlagSet, *string, *string, *bool) {
		fs := flag.NewFlagSet("grant", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		return fs, fs.String("note", "", ""), fs.String("on", "/", ""), fs.Bool("deny", false, "")
	}
	fs, note, on, deny := flags()
	var pos []string
	if err := parseFlags(fs, []string{"--note", "--", "dana", "publisher", "--on", "/legal", "--deny"}, &pos, 2); err != nil {
		t.Fatal(err)
	}
	if *note != "--" || *on != "/legal" || !*deny || !slices.Equal(pos, []string{"dana", "publisher"}) {
		t.Errorf("read note %q, on %q, deny %v and the names %q", *note, *on, *deny, pos)
	}
	// The "--" that does end the flags still does, after a flag that takes
	// no value and after one whose value is beside it.
	for _, line := range [][]string{
		{"dana", "--deny", "--", "--on"},
		{"dana", "--note=x", "--", "--on"},
		{"--note", "--", "dana", "--", "--on"},
	} {
		fs, _, on, _ := flags()
		pos = nil
		if err := parseFlags(fs, line, &pos, 2); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if *on != "/" || !slices.Equal(pos, []string{"dana", "--on"}) {
			t.Errorf("%q: read on %q and the names %q", line, *on, pos)
		}
	}
}

// A flag before the name a command is about does not get it past a deny.
//
// Taking flags before the names opened this. The check on a page, a
// collection of records or an agent is made before the command runs, by a
// table that says which word names it, and it read the words up to the first
// flag. With the flag first it found no name and asked about the whole site,
// which a deny on /legal does not cover: `lock --note x legal/terms` locked
// a page its caller was denied, and `note add`, `checked set` and
// `provenance set` wrote to one. So the words after a flag are each asked
// about too.
func TestAFlagFirstDoesNotGetPastADeny(t *testing.T) {
	root, owner := accessStore(t)
	addPage(t, root, owner, "legal/terms", "v1")
	addPage(t, root, owner, "index", "v1")
	for _, line := range [][]string{
		{"records", "add", "secret", "name=alpha"},
		{"agent", "new", "bot", "--kind", "retrieval"},
		{"auth", "grant", "dana", "author"},
		{"auth", "deny", "dana", "author", "--on", "/legal"},
		{"auth", "deny", "dana", "author", "--on", "/@data/secret"},
		{"auth", "deny", "dana", "run-agents", "--on", "/@agents/bot"},
	} {
		if _, e, code := cliRun(t, root, owner, line...); code != 0 {
			t.Fatalf("`quilzo %s`: %s", strings.Join(line, " "), firstLines(e, 3))
		}
	}
	o, e, code := cliRun(t, root, owner, "token", "issue", "danas", "--principal", "dana", "--role", "author", "--json")
	var tok struct{ Token string }
	if err := json.Unmarshal([]byte(o), &tok); code != 0 || err != nil || tok.Token == "" {
		t.Fatalf("token issue for dana: %v %s", err, firstLines(e, 3))
	}
	dana := tok.Token

	for _, line := range [][]string{
		{"lock", "--note", "x", "legal/terms"},
		{"note", "add", "--field", "title", "legal/terms", "flag first"},
		{"checked", "set", "--note", "ok", "legal/terms"},
		{"provenance", "set", "--source", "humanEdits", "--author", "dana", "legal/terms"},
		{"records", "add", "--id", "0123456789abcdef0123456789abcdef", "secret", "name=gamma"},
		{"agent", "run", "--", "bot"},
	} {
		_, e, code := cliRun(t, root, dana, line...)
		if code == 0 || !strings.Contains(e, "denied") {
			t.Errorf("`quilzo %s` by somebody denied it exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}
	for what, line := range map[string][]string{
		"legal/terms": {"lock", "list", "--json"},
		"flag first":  {"note", "list", "--json"},
		"gamma":       {"records", "list", "secret", "--json"},
	} {
		if o, _, _ := cliRun(t, root, owner, line...); strings.Contains(o, what) {
			t.Errorf("a denied command left %q in `quilzo %s`: %s", what, strings.Join(line, " "), firstLines(o, 6))
		}
	}
	// Somebody nothing denies there still writes flags first, and so does
	// dana on a page she may edit.
	if _, e, code := cliRun(t, root, owner, "lock", "--note", "x", "legal/terms"); code != 0 {
		t.Errorf("the owner's `quilzo lock --note x legal/terms`: %s", firstLines(e, 3))
	}
	if _, e, code := cliRun(t, root, dana, "lock", "--note", "x", "index"); code != 0 {
		t.Errorf("dana's `quilzo lock --note x index`: %s", firstLines(e, 3))
	}
}

// A --root that holds no store is refused, and nothing is made there.
//
// open made a store wherever it was pointed, so a nightly backup of an
// unmounted volume wrote a backup of nothing and said "backed up and
// checked", and `verify` of a mistyped path said "0 object(s) intact".
// Only init makes a store.
func TestARootThatIsNotAStoreIsRefused(t *testing.T) {
	key := filepath.Join(t.TempDir(), "bk.key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("k"), 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(backupKeyFileEnv, key)
	for _, line := range [][]string{
		{"verify"},
		{"diff"},
		{"auditlog", "verify"},
		{"backup", "create", filepath.Join(t.TempDir(), "b.qzb")},
		{"posture", "scan"},
		{"auth", "list"},
	} {
		root := filepath.Join(t.TempDir(), "qulizo")
		_, e, code := cliRun(t, root, "", line...)
		if code != 4 {
			t.Errorf("`quilzo --root qulizo %s` exited %d, want 4 (not found): %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
		if !strings.Contains(e, "init") {
			t.Errorf("`quilzo --root qulizo %s` did not say how a store is made: %s", strings.Join(line, " "), firstLines(e, 3))
		}
		if _, err := os.Stat(root); err == nil {
			t.Errorf("`quilzo --root qulizo %s` made the directory", strings.Join(line, " "))
		}
	}
	// A directory that is there and holds no store, as an empty mount point
	// is, is refused the same way.
	empty := t.TempDir()
	if _, _, code := cliRun(t, empty, "", "verify"); code != 4 {
		t.Errorf("verify of an empty directory exited %d, want 4", code)
	}
	if _, err := os.Stat(filepath.Join(empty, "objects")); err == nil {
		t.Error("verify of an empty directory made a store in it")
	}
	// And init still makes one, and the commands then run.
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, root, "", "verify"); code != 0 {
		t.Fatalf("verify after init: %s", e)
	}
}

// A root that cannot be looked into is said to be that, and not to hold no
// store.
//
// The refusal asked only whether objects/ could be found, so a store its
// caller may not read answered as an empty directory does: somebody who left
// off `sudo -u quilzo` was told "no store at /srv/quilzo/.quilzo; quilzo
// --root /srv/quilzo/.quilzo init makes one", of a store that was there. So
// did a --root that runs through a file.
func TestARootThatCannotBeLookedIntoIsNotSaidToBeEmpty(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{"through a file": filepath.Join(file, "store")}
	// An account that is not root is stopped by a directory's mode; root is
	// not, so there the file stands for both.
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.MkdirAll(filepath.Join(locked, "objects"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		roots["another account's"] = locked
	}
	for what, root := range roots {
		err := needStore(root)
		if err == nil || errors.Is(err, errNoStore) || strings.Contains(err.Error(), "init makes one") {
			t.Errorf("a root %s: %v", what, err)
		}
	}
	// One with nothing at it is still no store, and says how one is made.
	if err := needStore(filepath.Join(dir, "qulizo")); !errors.Is(err, errNoStore) || !strings.Contains(err.Error(), "init makes one") {
		t.Errorf("a root with nothing at it: %v", err)
	}
	// On the command line it is a failure, 1, where no store is "not found".
	_, e, code := cliRun(t, roots["through a file"], "", "token", "list")
	if code != 1 || strings.Contains(e, "init makes one") {
		t.Errorf("`quilzo token list` of a root through a file exited %d: %s", code, firstLines(e, 3))
	}
}

// Only init runs on a --root that holds no store, and nothing is made there.
//
// open refuses such a root, and the commands that open a store went with it.
// The ones that read a store's files for themselves did not, and there are
// more of those: `token list` of a mistyped --root said "no tokens", `secret
// list` that no credentials are kept, `scan` "0 finding(s)" and `vault
// status` that the objects are stored in the clear, each exit 0, as `verify`
// had said "0 object(s) intact". `member invite` made the directory and
// wrote an invitation into it, and `studio` started its server there. The
// test of the six lines the report named passed with all of them.
//
// So every command the program dispatches, and every subcommand, is run on a
// root with nothing at it, and has to refuse with how a store is made and
// make nothing. The ones that are not about a store are listed (storeless),
// and the list is held to commands there are.
func TestOnlyInitRunsOnARootThatIsNotAStore(t *testing.T) {
	tried := map[string]bool{}
	for _, a := range everyCommandLine(t) {
		line := strings.Join(a, " ")
		tried[line] = true
		if runsWithoutAStore(a[0], a[1:]) {
			continue
		}
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			root := filepath.Join(t.TempDir(), "qulizo")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"quilzo-main", "--root", root}, a...)...)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=", "NO_COLOR=1")
			var said bytes.Buffer
			cmd.Stdout, cmd.Stderr = &said, &said
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("`quilzo --root qulizo %s` did not refuse and went on running: %s", line, firstLines(said.String(), 3))
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 4 || !strings.Contains(said.String(), "init makes one") {
				t.Errorf("`quilzo --root qulizo %s` did not refuse the root (%v):\n%s", line, err, firstLines(said.String(), 3))
			}
			if _, err := os.Stat(root); err == nil {
				t.Errorf("`quilzo --root qulizo %s` made the directory", line)
			}
		})
	}
	// A command listed as not about a store is one there is, under the
	// spelling the help has: a line that names nothing lets nothing through,
	// and reads as though it did.
	for key := range storeless {
		if !tried[key] {
			t.Errorf("storeless lists %q, which is not a command there is", key)
		}
	}
	// init is not among the lines tried, being the one that is to make a
	// store there; it is among the commands dispatched.
	dispatched := dispatchedCommands(t)
	for c := range storelessWhole {
		if !slices.Contains(dispatched, c) {
			t.Errorf("storelessWhole lists %q, which is not a command there is", c)
		}
	}
}

// What is not about a store runs where there is none.
//
// The release is built this way: the bill of materials, the algorithms and
// the count of third-party components are asked of the binary in a checkout
// with no store in it, and a store that is lost is restored from its backup
// by a command whose --root has nothing at it. Refusing every command there
// would have stopped the release and the restore.
func TestWhatIsNotAboutAStoreRunsWithoutOne(t *testing.T) {
	key := filepath.Join(t.TempDir(), "bk.key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("k"), 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(backupKeyFileEnv, key)
	// A store, backed up, for the two that read a backup.
	store := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, store, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	addPage(t, store, "", "index", "v1")
	dir := t.TempDir()
	file := filepath.Join(dir, "b.qzb")
	if _, e, code := cliRun(t, store, "", "backup", "create", file); code != 0 {
		t.Fatalf("backup create: %s", firstLines(e, 3))
	}
	restored := filepath.Join(dir, "restored")

	for _, line := range [][]string{
		{"version"},
		{"help"},
		{"compliance", "sbom", filepath.Join(dir, "sbom.json")},
		{"compliance", "crypto", "--json"},
		{"--json", "compliance", "summary"},
		{"backup", "key"},
		{"backup", "verify", file},
		{"backup", "restore", file, "--into", restored},
		{"token", "keygen", filepath.Join(dir, "dpop.jwk")},
		{"auth", "roles"},
		{"posture", "rules"},
		{"template", "list"},
		{"templates", "layouts"},
		{"sframe", "suites"},
		{"theme", "styles"},
	} {
		root := filepath.Join(t.TempDir(), "qulizo")
		_, e, code := cliRun(t, root, "", line...)
		if code != 0 {
			t.Errorf("`quilzo --root qulizo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
		if _, err := os.Stat(root); err == nil {
			t.Errorf("`quilzo --root qulizo %s` made the directory", strings.Join(line, " "))
		}
	}
	if !isStore(filepath.Join(restored, "store")) {
		t.Error("the backup was not restored into a store")
	}
	// `auditlog dir` is not among them, though the rest of auditlog asks for
	// itself: it made the root, began a log and a key there, and said the
	// log had moved.
	typo, logs := filepath.Join(t.TempDir(), "qulizo"), t.TempDir()
	if _, e, code := cliRun(t, typo, "", "auditlog", "dir", logs); code != 4 || !strings.Contains(e, "init makes one") {
		t.Errorf("`quilzo --root qulizo auditlog dir DIR` exited %d: %s", code, firstLines(e, 3))
	}
	if _, err := os.Stat(typo); err == nil {
		t.Error("`quilzo --root qulizo auditlog dir DIR` made the directory")
	}
	if entries, _ := os.ReadDir(logs); len(entries) != 0 {
		t.Errorf("`quilzo --root qulizo auditlog dir DIR` wrote %s into DIR", entries[0].Name())
	}
	// A command nobody has is said to be that, and not to want a store.
	_, e, code := cliRun(t, filepath.Join(t.TempDir(), "qulizo"), "", "tokens")
	if code == 0 || strings.Contains(e, "init makes one") {
		t.Errorf("`quilzo --root qulizo tokens` exited %d: %s", code, firstLines(e, 3))
	}
}

// Everything after "--" belongs to the program a command runs.
//
// The global pass took --root, --token and --json from anywhere on the line,
// so `agent program bot -- tool --root /data` looked for the agent in /data,
// and a program's own `--token X` became the caller's credential and was
// gone from the program's command line.
func TestGlobalFlagsStopAtTheDoubleDash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, root, "", "agent", "new", "bot", "--kind", "operator"); code != 0 {
		t.Fatalf("agent new: %s", e)
	}
	want := []string{"/bin/sh", "--root", "/tmp/elsewhere", "--token", "abc123", "--json", "--verbose"}
	if _, e, code := cliRun(t, root, "", append([]string{"agent", "program", "bot", "--"}, want...)...); code != 0 {
		t.Fatalf("agent program: %s", firstLines(e, 3))
	}
	set, err := loadAgents(root)
	if err != nil {
		t.Fatal(err)
	}
	m := set.Agents["bot"]
	if m.Program == nil || !slices.Equal(m.Program.Command, want) {
		t.Fatalf("the program was declared as %v, want %v", m.Program, want)
	}
}
