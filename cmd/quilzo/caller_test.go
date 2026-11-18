// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// A rejected token is named by where it came from, and an old token file
// shadowing QUILZO_TOKEN says so: the file is read first on purpose, and
// the refusal is where a person learns it.
func TestARejectedTokenSaysWhereItCameFrom(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".quilzo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".quilzo", "token"),
		[]byte("qz_"+strings.Repeat("a", 52)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "qz_"+strings.Repeat("b", 52))
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	c := resolveCaller(root, "")
	if c.Verified {
		t.Fatal("an unknown token verified")
	}
	if !strings.Contains(c.Why, filepath.Join(home, ".quilzo", "token")) || !strings.Contains(c.Why, "QUILZO_TOKEN is set too") {
		t.Fatalf("the refusal does not say which token was tried: %q", c.Why)
	}
	if c := resolveCaller(root, "qz_"+strings.Repeat("c", 52)); !strings.Contains(c.Why, "from --token") {
		t.Fatalf("an explicit token is not named as one: %q", c.Why)
	}
}

// A risk accepted on a store nobody has been granted anything in names the
// operating-system account that accepted it, said to be not verified, as
// nothing checked it.
//
// `quilzo config set mcp.remote true --accept-risk ...` run where $USER,
// $USERNAME and $LOGNAME are empty, as under a service manager or in a
// container, was accepted by "unknown-operator": the posture scan and
// `config show` named nobody, though the program knew whose account it ran
// as. And a name taken from $USER was shown as plainly as one a token
// proved.
func TestAnAcceptanceNamesWhoAcceptedIt(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Username == "" {
		t.Skipf("this system does not say whose account this is: %v", err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = ""
	for _, tc := range []struct{ user, want string }{
		{"", me.Username + " (not verified)"},
		{"kit", "kit (not verified)"},
	} {
		for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
			t.Setenv(k, "")
		}
		t.Setenv("USER", tc.user)
		root := t.TempDir()
		if err := cmdInit(root); err != nil {
			t.Fatal(err)
		}
		if err := cmdConfig(root, []string{"set", "mcp.remote", "true", "--accept-risk", "agents reach it"}); err != nil {
			t.Fatal(err)
		}
		w := mustConfig(root).Weakened()
		if len(w) != 1 || w[0].Accepted == nil {
			t.Fatalf("USER=%q: mcp.remote is not reported as accepted: %d weakened", tc.user, len(w))
		}
		if by := w[0].Accepted.By; by != tc.want {
			t.Errorf("USER=%q: accepted by %q, not %q", tc.user, by, tc.want)
		}
		got, err := humanOutput(t, func() error { return cmdConfig(root, []string{"show"}) })
		if err != nil || !strings.Contains(got, "accepted by "+tc.want) {
			t.Errorf("USER=%q: config show does not name %q: %v\n%s", tc.user, tc.want, err, got)
		}
	}
}

// An account the system has no name for is named by its number, as the
// refusal to start a server names it (storeowner_unix.go), and is still
// said to be not verified.
//
// A container started with a user id its image has no entry for, as
// `docker run --user 1000` and every OpenShift pod are, has no $USER and
// no name to look up, and a risk accepted there was accepted by
// "unknown-operator" though the id was right there.
func TestAnAccountWithNoNameIsNamedByItsNumber(t *testing.T) {
	uid := os.Geteuid()
	if uid < 0 {
		t.Skip("this system has no user ids")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = ""
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		t.Setenv(k, "")
	}
	t.Cleanup(func(old func() (*user.User, error)) func() {
		return func() { currentAccount = old }
	}(currentAccount))
	currentAccount = func() (*user.User, error) {
		return nil, user.UnknownUserIdError(uid)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "mcp.remote", "true", "--accept-risk", "agents reach it"}); err != nil {
		t.Fatal(err)
	}
	want := "uid " + strconv.Itoa(uid) + " (not verified)"
	w := mustConfig(root).Weakened()
	if len(w) != 1 || w[0].Accepted == nil {
		t.Fatalf("mcp.remote is not reported as accepted: %d weakened", len(w))
	}
	if by := w[0].Accepted.By; by != want {
		t.Errorf("an account with no name: accepted by %q, not %q", by, want)
	}
}

// Whether a token is a person's or a program's is what its issue recorded,
// never a guess from its name.
//
// It was the name: a token called "cli", or one with an @ in it, was a
// person's, and every other token a program's. So the first administrator's
// token, issued as deploy/README.md says (`token issue first --principal
// ada`), and the session exchanged from it, could not start an access
// review ("ada is a program's credential, not a person"), while an
// administrator's token issued for a CI job and named cli could.
func TestWhetherATokenIsAPersonsIsRecordedAtIssue(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = ""
	root := connectStore(t)
	if err := cmdAuth(root, []string{"grant", "ada", "admin"}); err != nil {
		t.Fatal(err)
	}
	issue := func(args ...string) string {
		t.Helper()
		doc, err := jsonAnswer(t, func() error { return cmdToken(root, append([]string{"issue"}, args...)) })
		secret, _ := doc["token"].(string)
		if err != nil || secret == "" {
			t.Fatalf("token issue %v: %v %v", args, err, doc)
		}
		return secret
	}

	// The store's first token, for its only administrator, is theirs.
	flagToken = issue("first", "--principal", "ada")
	if c := resolveCaller(root, ""); c.Kind != audit.KindHuman || !c.Verified {
		t.Fatalf("the first administrator's own first token is not a person's: %+v", c)
	}
	doc, err := jsonAnswer(t, func() error { return cmdToken(root, []string{"exchange"}) })
	session, _ := doc["token"].(string)
	if err != nil || session == "" {
		t.Fatalf("exchange: %v %v", err, doc)
	}
	if c := resolveCaller(root, session); c.Kind != audit.KindHuman {
		t.Errorf("a session exchanged from a person's token is not a person's: %+v", c)
	}

	// Named cli and issued for a program, it is a program's, and the
	// refusal names the token, not the person it acts as.
	ci := issue("cli", "--principal", "ada", "--role", "admin")
	if c := resolveCaller(root, ci); c.Kind != audit.KindService {
		t.Fatalf("a token issued for a program is a person's because it is named cli: %+v", c)
	}
	_, err = reviewStart(root, resolveCaller(root, ci))
	if err == nil || !strings.Contains(err.Error(), "the token cli") || strings.Contains(err.Error(), "ada is a program") {
		t.Errorf("a program's token started a review, or the refusal does not name the token: %v", err)
	}
	if _, err := reviewStart(root, resolveCaller(root, session)); err != nil {
		t.Fatalf("the first administrator cannot start a review with the session from their own token: %v", err)
	}

	// And issued as somebody's own, whatever it is called, it is theirs.
	if c := resolveCaller(root, issue("laptop", "--principal", "ada", "--person")); c.Kind != audit.KindHuman {
		t.Errorf("a token issued --person is not a person's: %+v", c)
	}
}
