package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Every command the dispatcher can reach must declare what it needs.
//
// This is the test that would have caught the bug. `publish` called authorise
// and nineteen other commands did not, so with a policy configured and no
// token presented, `auth grant mallory admin` and `token issue --role admin`
// both succeeded — the access-control model bypassed by anyone able to run the
// binary.
//
// It is deliberately a source walk rather than a list. A list would need
// updating by the same person who forgot to add the check, which is no
// guarantee at all. Parsing the switch means a command that exists is a
// command this test knows about, whether or not anybody remembered it.
func TestEveryDispatchedCommandDeclaresItsPrivilege(t *testing.T) {
	cases := dispatchedCommands(t)
	if len(cases) < 30 {
		t.Fatalf("found only %d commands in the dispatch switch; the parse is "+
			"probably wrong, and a test that finds nothing passes", len(cases))
	}
	for _, c := range cases {
		n, ok := commandNeeds[c]
		if !ok {
			t.Errorf("%q is dispatched but declares no privilege. Add it to "+
				"commandNeeds, with an action or with a reason it needs none.", c)
			continue
		}
		if n.action == "" && strings.TrimSpace(n.why) == "" {
			t.Errorf("%q requires no authority and does not say why. The "+
				"reason is the review: writing it down is what makes somebody "+
				"notice when it is wrong.", c)
		}
		if n.action != "" {
			if _, known := auth.Needs(n.action); !known {
				t.Errorf("%q needs action %q, which is not an action the "+
					"policy knows how to evaluate — so the check always "+
					"passes", c, n.action)
			}
		}
	}
}

// And the reverse: an entry for a command that no longer exists is dead weight
// that makes the table look more complete than it is.
func TestThePrivilegeTableHasNoEntriesForCommandsThatDoNotExist(t *testing.T) {
	live := map[string]bool{}
	for _, c := range dispatchedCommands(t) {
		live[c] = true
	}
	for key := range commandNeeds {
		base, _, isSub := strings.Cut(key, " ")
		if isSub {
			if !live[base] {
				t.Errorf("commandNeeds has %q but %q is not dispatched", key, base)
			}
			continue
		}
		if !live[key] {
			t.Errorf("commandNeeds has %q, which is not a command", key)
		}
	}
}

// A specific key must narrow its parent, never widen it.
//
// The two look equivalent and are not. An unlisted subcommand falls through to
// the parent, so a permissive parent with a strict child means the next
// subcommand somebody adds arrives unguarded — and it is the mutating ones
// that get added. A strict parent with permissive children means a new
// subcommand arrives over-guarded, which surfaces as a bug report rather than
// as a breach.
//
// This found `posture`, which defaulted to view with `posture suppress`
// needing grant. Accepting a security risk on the organisation's behalf was
// one forgotten table row away from being readable by anyone.
func TestReadOnlySubcommandsAreMoreNarrowThanTheirParents(t *testing.T) {
	rank := map[auth.Action]int{
		auth.ActView: 1, auth.ActEditDraft: 2, auth.ActPublish: 3,
		auth.ActRollback: 3, auth.ActGrant: 4, auth.ActToken: 4,
	}
	for key, n := range commandNeeds {
		base, _, isSub := strings.Cut(key, " ")
		if !isSub || n.action == "" {
			continue
		}
		parent, ok := commandNeeds[base]
		if !ok || parent.action == "" {
			continue
		}
		if rank[n.action] > rank[parent.action] {
			t.Errorf("%q needs %s but its parent %q needs only %s, so the "+
				"specific key widens access instead of narrowing it",
				key, n.action, base, parent.action)
		}
	}
}

// dispatchedCommands reads the case labels out of main's command switch.
func dispatchedCommands(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(".", "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatal(err)
	}

	var out []string
	ast.Inspect(f, func(node ast.Node) bool {
		sw, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		ident, ok := sw.Tag.(*ast.Ident)
		if !ok || ident.Name != "cmd" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cl, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range cl.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				out = append(out, strings.Trim(lit.Value, `"`))
			}
		}
		return true
	})
	return out
}

// -- and that the table is actually consulted --------------------------------

// The source walk above proves every command declares something. It does not
// prove the declaration is enforced, and a table nobody reads is a comment.
func TestPrivilegedCommandsAreRefusedWithoutAToken(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	// One binding, which is what turns enforcement on.
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "alice", Role: auth.RoleAdmin, Resource: "/",
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")

	for _, tc := range []struct {
		cmd  string
		args []string
	}{
		{"auth", []string{"grant", "mallory", "admin"}},
		{"auth", []string{"revoke", "alice", "admin"}},
		{"token", []string{"issue", "evil", "--principal", "mallory", "--role", "admin"}},
		{"publish", nil},
		{"rollback", nil},
		{"add", []string{"x=y.json"}},
		{"schedule", []string{"add", "1h"}},
		{"posture", []string{"suppress", "access.no-policy", "--reason", "x"}},
		{"type", []string{"add", "t.json"}},
		{"webhook", []string{"add", "https://x.example"}},
	} {
		err := authoriseCommand(root, tc.cmd, tc.args)
		if err == nil {
			t.Errorf("%s %v was allowed with no token presented",
				tc.cmd, tc.args)
		}
	}
}

// Reading is refused too, so a store with access control does not hand its
// contents to anybody with a shell on the machine.
func TestReadsAreAlsoRefusedWithoutAToken(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	for _, cmd := range []string{"log", "diff", "verify", "export", "siem"} {
		if err := authoriseCommand(root, cmd, nil); err == nil {
			t.Errorf("%s read the store with no token", cmd)
		}
	}
}

// The bootstrap, and the reason it exists: without it the first grant bricks
// the store. `auth grant alice admin` creates the policy, and from that moment
// `token issue` needs manage-tokens, which needs a token, which cannot be
// issued. The operator's only recovery was editing JSON by hand.
func TestTheFirstTokenCanBeIssuedAfterTheFirstGrant(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")

	if err := authoriseCommand(root, "token",
		[]string{"issue", "laptop", "--principal", "alice", "--role", "admin"}); err != nil {
		t.Fatalf("the first token could not be issued, so the store is "+
			"locked: %v", err)
	}
}

// And it closes the moment a token exists, rather than staying open as a mode
// somebody has to remember to turn off.
func TestTheBootstrapClosesOnceATokenExists(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	if _, _, err := ts.Issue("first", "alice", auth.RoleAdmin, "/",
		time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")

	if err := authoriseCommand(root, "token",
		[]string{"issue", "second", "--principal", "alice", "--role", "admin"}); err == nil {
		t.Error("a second token was issued with no authentication; the " +
			"bootstrap did not close")
	}
}

// It must not become an escalation path either: issuing to a principal the
// policy has never heard of would let anybody invent an admin.
func TestTheBootstrapOnlyIssuesToAPrincipalThePolicyKnows(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")

	if err := authoriseCommand(root, "token",
		[]string{"issue", "evil", "--principal", "mallory", "--role", "admin"}); err == nil {
		t.Error("the bootstrap issued a token to a principal with no binding, " +
			"which is an admin account invented from nothing")
	}
}

// A store nobody has configured must stay usable without ceremony. Requiring a
// token before anybody has been granted anything would make `quilzo init`
// followed by `quilzo add` fail, which is the first thing anyone does.
func TestAnUnconfiguredStoreNeedsNoToken(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	for _, cmd := range []string{"add", "publish", "log", "auth", "token"} {
		if err := authoriseCommand(root, cmd, nil); err != nil {
			t.Errorf("%s needed a token on a store with no policy: %v", cmd, err)
		}
	}
}

// Asking a command how to use it must not require the authority to run it.
func TestHelpNeedsNoAuthority(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	if err := authoriseCommand(root, "publish", []string{"--help"}); err != nil {
		t.Errorf("publish --help was refused: %v", err)
	}
}

// A typo must not tell a user to edit a Go source file.
//
// Every unknown command took the developer's message for as long as this check
// has existed — "add it to commandNeeds in cmd/quilzo/privilege.go" — because
// "somebody added a command and forgot the table" and "somebody mistyped" were
// never distinguished. The first is a real condition worth a loud message; the
// second is the overwhelmingly common one.
//
// The developer case is prevented rather than reported: the test above walks
// the dispatch switch and fails when a command is missing from the table, so
// by the time this runs, an unrecognised name can only be a typo.
func TestATypoGetsAHumanMessage(t *testing.T) {
	for _, typo := range []string{"wibble", "aprove", "pubish", "recrods"} {
		err := unknownCommand(typo)
		if err == nil {
			t.Fatalf("%q was accepted", typo)
		}
		msg := err.Error()
		if strings.Contains(msg, "commandNeeds") ||
			strings.Contains(msg, ".go") {
			t.Errorf("%q told a user to edit source: %s", typo, msg)
		}
		if !strings.Contains(msg, "quilzo help") {
			t.Errorf("%q does not say how to find the real commands: %s",
				typo, msg)
		}
	}
}

// A near-miss suggests the command it is near.
func TestANearMissSuggestsTheRealCommand(t *testing.T) {
	for typo, want := range map[string]string{
		"pubish":  "publish",
		"recrods": "records",
		"revew":   "review",
		"medai":   "media",
	} {
		msg := unknownCommand(typo).Error()
		if !strings.Contains(msg, want) {
			t.Errorf("%q did not suggest %q: %s", typo, want, msg)
		}
	}
}
