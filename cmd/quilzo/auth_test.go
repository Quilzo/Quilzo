// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
)

// A job is granted, works on its area's commands only, and is revoked whole.
func TestAJobIsGrantedFromTheCommandLineAndKeepsToItsArea(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	if err := cmdAuth(root, []string{"grant", "sam", "analyst", "--for", "30d"}); err != nil {
		t.Fatal(err)
	}
	p, _ := loadPolicy(root)
	if !p.Evaluate("sam", auth.ActGrant, auth.AreaSecurity).Allowed ||
		p.Evaluate("sam", auth.ActView, "/").Allowed {
		t.Fatalf("the analyst job did not grant its area alone: %+v", p.Bindings)
	}
	for _, b := range p.Bindings {
		if b.Principal == "sam" && (b.Expires == 0 || b.Expires > time.Now().Add(31*24*time.Hour).Unix()) {
			t.Errorf("--for 30d gave %+v", b)
		}
	}
	if err := cmdAuth(root, []string{"grant", "sam", "analyst", "--on", "/blog"}); err == nil {
		t.Error("a job was granted on a part of the site")
	}

	// As sam: the area's commands run, and nothing outside them.
	issueFor := func(who string) string {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue("t", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		_ = saveJSON(tokensPath(root), ts)
		return secret
	}
	t.Setenv("QUILZO_TOKEN", issueFor("sam"))
	if err := authoriseCommand(root, "shield", []string{"status"}); err != nil {
		t.Errorf("an analyst cannot read the shield: %v", err)
	}
	for _, c := range [][]string{{"publish"}, {"auth", "grant", "x", "admin"}, {"add", "x=y.json"}, {"inbox"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("an analyst may run %v", c)
		}
	}

	t.Setenv("QUILZO_TOKEN", "")
	if err := cmdAuth(root, []string{"revoke", "sam", "analyst"}); err != nil {
		t.Fatal(err)
	}
	p, _ = loadPolicy(root)
	if p.Evaluate("sam", auth.ActView, auth.AreaSecurity).Allowed {
		t.Error("revoking the job left part of it")
	}
}

// The auditor job is only granted with an end, and its holder reads the log
// and the posture from a terminal and runs nothing that changes them.
func TestAnAuditorReadsFromTheCommandLineAndChangesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "kim", "auditor"}); err == nil {
		t.Fatal("an auditor was granted with no end")
	}
	if err := cmdAuth(root, []string{"grant", "kim", "auditor", "--for", "30d"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "rae", "reader"}); err != nil {
		t.Fatal(err)
	}
	issueFor := func(who string) string {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue("t", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		_ = saveJSON(tokensPath(root), ts)
		return secret
	}
	reads := [][]string{{"auditlog", "show"}, {"auditlog", "verify"}, {"posture", "rules"}, {"posture", "frameworks"}, {"compliance", "summary"}}
	t.Setenv("QUILZO_TOKEN", issueFor("kim"))
	for _, c := range reads {
		if err := authoriseCommand(root, c[0], c[1:]); err != nil {
			t.Errorf("an auditor cannot run %v: %v", c, err)
		}
	}
	for _, c := range [][]string{{"auditlog", "anchor"}, {"posture", "suppress", "x"}, {"finding", "list"}, {"publish"}, {"auth", "grant", "x", "reader"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("an auditor may run %v", c)
		}
	}
	// A reader over the site used to run these: the admin would not show
	// them the log, and the terminal did.
	t.Setenv("QUILZO_TOKEN", issueFor("rae"))
	for _, c := range reads {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("a reader over the site may run %v", c)
		}
	}
}

// What a grant lets somebody do is said from the policy as it is written,
// not from the copy read before the change: it said "nothing" for every
// grant, an administrator's included.
func TestAGrantSaysWhatItLetsThemDo(t *testing.T) {
	root := connectStore(t)
	_, read := captureStdout(t)
	err := cmdAuth(root, []string{"grant", "dana", "author", "--on", "/blog"})
	out := read()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "can now: nothing") || !strings.Contains(out, "edit-draft") {
		t.Fatalf("the consequence is not what was granted:\n%s", out)
	}
}

// A fresh install's first credential: the first token, for the
// administrator the policy names alone, is issued without a second
// administrator nobody could be; the next one is not issued without a
// token at all.
func TestTheOnlyAdministratorGetsTheirFirstToken(t *testing.T) {
	root := connectStore(t)
	t.Setenv("QUILZO_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := authoriseCommand(root, "token", []string{"issue", "laptop", "--principal", "dana"}); err != nil {
		t.Fatalf("the first token was refused: %v", err)
	}
	if err := tokenIssue(root, []string{"laptop", "--principal", "dana"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	if len(ts.Tokens) != 1 || ts.Tokens[0].Role != auth.RoleAdmin {
		t.Fatalf("no administrator's token was issued: %+v", ts.Tokens)
	}
	if pend, _ := dualStore(root).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("it waits for a second administrator: %+v", pend)
	}
	if err := authoriseCommand(root, "token", []string{"issue", "again", "--principal", "dana"}); err == nil {
		t.Fatal("a second token was issued with no token presented")
	}
	evs, _ := audit.Read(auditPath(root))
	boot := false
	for _, e := range evs {
		if e.Action == "dual.approved" && e.Detail["bootstrap"] == "true" {
			boot = true
		}
	}
	if !boot {
		t.Error("the record does not say the first token was the bootstrap")
	}
}

// Each place that says how to run an auth subcommand names the arguments
// the command needs.
//
// `quilzo help` said `quilzo auth revoke WHO [--on PATH]`, and the command
// needs a principal and a role: a store set up by following the help failed
// at its first revoke, with a usage line the help had never shown. `quilzo
// auth`'s own list said explain needs an action, which it does not. So the
// count of required arguments in both lists is checked against the usage
// each command answers with when it is given none, which is what the
// command itself reads.
func TestEveryAuthSynopsisNamesTheArgumentsTheCommandNeeds(t *testing.T) {
	root := connectStore(t)
	help := helpText(t)
	_, read := captureStdout(t)
	_ = authUsage()
	own := read()

	for _, sub := range []string{"grant", "deny", "revoke", "explain", "enrol", "unlock"} {
		err := cmdAuth(root, []string{sub})
		if err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("`quilzo auth %s` with nothing else did not answer its usage: %v", sub, err)
		}
		codes := synopses(err.Error(), "quilzo auth "+sub)
		if len(codes) == 0 {
			t.Fatalf("the usage of auth %s does not name it: %v", sub, err)
		}
		need := requiredArgs(codes[0])
		if len(synopses(help, "quilzo auth "+sub)) == 0 || len(synopses(own, sub)) == 0 {
			t.Fatalf("auth %s is missing from one of the lists, so nothing was compared", sub)
		}
		for _, line := range synopses(help, "quilzo auth "+sub) {
			if n := requiredArgs(line); n >= 0 && n != need {
				t.Errorf("`quilzo help` says `quilzo auth %s%s`, which is %d argument(s); "+
					"the command needs %d: %s", sub, line, n, need, err)
			}
		}
		for _, line := range synopses(own, sub) {
			if n := requiredArgs(line); n >= 0 && n != need {
				t.Errorf("`quilzo auth` says `%s%s`, which is %d argument(s); "+
					"the command needs %d: %s", sub, line, n, need, err)
			}
		}
	}
}

// synopses finds every place text names the command at the start of a line
// or of a usage, and returns what follows it up to the description or the
// next alternative.
func synopses(text, command string) []string {
	var out []string
	pat := regexp.MustCompile(`(?m)(?:^\s*|usage: |or: |\| )` + regexp.QuoteMeta(command) +
		`((?:[ \t][^\n]*)?)$`)
	end := regexp.MustCompile(`\s{2,}| \| `)
	for _, m := range pat.FindAllStringSubmatch(text, -1) {
		rest := m[1]
		if i := end.FindStringIndex(strings.TrimLeft(rest, " \t")); i != nil {
			rest = strings.TrimLeft(rest, " \t")[:i[0]]
		}
		out = append(out, " "+strings.TrimSpace(rest))
	}
	return out
}

// requiredArgs counts the placeholders a synopsis requires, stopping at the
// first optional part or flag. It is -1 for a line that says "as above".
func requiredArgs(synopsis string) int {
	placeholder := regexp.MustCompile(`^(<[^>]+>|[A-Z][A-Z0-9_/|]*)$`)
	n := 0
	for _, word := range strings.Fields(synopsis) {
		switch {
		case word == "...":
			return -1
		case placeholder.MatchString(word):
			n++
		default:
			return n
		}
	}
	return n
}

// Every row of `quilzo auth list` keeps to the columns of its header.
//
// The widths were fixed at 18, 10, 16 and 14, and a principal is often an
// email address: claimsadmin@qz.test is 19 characters, and its row pushed
// every column after it one place right of the header and of the rows
// around it. "unrecorded" was padded with its colour codes counted as
// width, so on a terminal what followed it stood four places left of the
// same thing on a recorded row.
func TestAuthListKeepsEveryRowInItsColumns(t *testing.T) {
	root := connectStore(t)
	pol := &auth.Policy{}
	// Listed by somebody who may grant, who is shown everybody's rows; a
	// reader is shown only their own (TestAReaderListsTheirOwnGrantsAndTokens).
	isolateToken(t)
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.Issue("boss-laptop", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	for _, b := range []auth.Binding{
		{Principal: "boss", Role: auth.RoleAdmin, Resource: "/", GrantedBy: "cli"},
		{Principal: "claimsadmin@qz.test", Role: auth.RoleAdmin, Resource: "/", GrantedBy: "cli", Deny: true},
		{Principal: "bo", Role: auth.RoleReader, Resource: "/a-rather-long/section/path", Deny: true},
		{Principal: "a-principal-of-forty-characters@qz.test", Role: auth.RolePublisher,
			Resource: "/", GrantedBy: "an-administrator-with-a-long-name", Deny: true},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	// The table, as a terminal shows it: connectStore asks for JSON.
	savedDim, savedRed, savedReset := dim, red, reset
	dim, red, reset = "\x1b[2m", "\x1b[31m", "\x1b[0m"
	t.Cleanup(func() { dim, red, reset = savedDim, savedRed, savedReset })

	_, read := captureStdout(t)
	w = out.New(false)
	err = authList(root)
	printed := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(read(), "")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(printed, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected a header, a rule and four rows:\n%s", printed)
	}
	header := lines[0]
	for _, col := range []string{"role", "resource", "granted by"} {
		at := strings.Index(header, col)
		for _, row := range lines[2:] {
			if at > len(row) || row[at-1] != ' ' || row[at] == ' ' {
				t.Errorf("the %q column starts at %d in the header and not in this row:\n%s\n%s",
					col, at, header, row)
			}
		}
	}
	deny := -1
	for _, row := range lines[2:] {
		at := strings.Index(row, "DENY")
		if deny == -1 {
			deny = at
		}
		if at != deny {
			t.Errorf("DENY stands at %d in one row and %d in another:\n%s", deny, at, printed)
		}
	}
}

// The token list keeps its columns the same way, for a token whose name is
// longer than the sixteen characters the column used to be.
func TestTokenListKeepsEveryRowInItsColumns(t *testing.T) {
	root := connectStore(t)
	ts, _ := loadTokens(root)
	for _, name := range []string{"ci-deploy-production", "laptop"} {
		if _, _, err := ts.Issue(name, "dana", auth.RoleReader, "/", time.Hour, auth.RoleAdmin); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	_, read := captureStdout(t)
	w = out.New(false)
	err := tokenList(root)
	printed := read()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(printed, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected a header and two rows:\n%s", printed)
	}
	at := strings.Index(lines[0], "role")
	for _, row := range lines[1:] {
		if !strings.HasPrefix(row[at:], "reader") {
			t.Errorf("the role column starts at %d in the header and not in this row:\n%s\n%s",
				at, lines[0], row)
		}
	}
}

// The stale tokens keep their columns too: the list of tokens nobody uses
// put each name in a fixed sixteen places, as the token list did, and
// "ci-deploy-production" pushed its "never used" out of line with the rest.
func TestTokenStaleKeepsEveryRowInItsColumns(t *testing.T) {
	root := connectStore(t)
	ts, _ := loadTokens(root)
	for _, name := range []string{"ci-deploy-production", "laptop"} {
		if _, _, err := ts.Issue(name, "dana", auth.RoleReader, "/", time.Hour, auth.RoleAdmin); err != nil {
			t.Fatal(err)
		}
	}
	for i := range ts.Tokens {
		ts.Tokens[i].CreatedAt = time.Now().Add(-48 * time.Hour).Unix()
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	_, read := captureStdout(t)
	w = out.New(false)
	err := tokenStale(root, []string{"--idle", "24h"})
	printed := read()
	if err != nil {
		t.Fatal(err)
	}
	var at []int
	for _, row := range strings.Split(printed, "\n") {
		if i := strings.Index(row, "never used"); i >= 0 {
			at = append(at, i)
		}
	}
	if len(at) != 2 {
		t.Fatalf("expected two stale tokens:\n%s", printed)
	}
	if at[0] != at[1] {
		t.Errorf("\"never used\" stands at %d in one row and %d in the other:\n%s", at[0], at[1], printed)
	}
}
