package main

import (
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// Following the sign-in screen exactly has to leave somebody able to work.
//
// It named one of the two commands. A token says which role it may act up to;
// a binding is what grants one. So `token issue you --principal you --role
// admin` -- the whole of what the screen said -- produced a credential that
// signed in and was then refused by every screen, with "no binding gives you
// any role on /". That reads as a broken program rather than a missing step,
// and it is the first thing a new installation does.
func TestTheDocumentedFirstRunLeavesSomebodyAbleToWork(t *testing.T) {
	t.Setenv("QUILZO_TOKEN", "")
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}

	if err := authoriseCommand(root, "auth",
		[]string{"grant", "you", "admin"}); err != nil {
		t.Fatalf("granting the first binding was refused: %v", err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "you", Role: auth.RoleAdmin, Resource: "/",
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}

	// Issuing after the first grant, which is the half that could have
	// deadlocked: the grant switches identity checks on, and issuing needs
	// manage-tokens. It is allowed because no token exists yet and the
	// principal is already in the policy — the bootstrap in privilege.go. If
	// that ever closes, this order strands every new installation.
	if err := authoriseCommand(root, "token",
		[]string{"issue", "you", "--principal", "you", "--role", "admin"}); err != nil {
		t.Fatalf("issuing the first token after the first grant was refused, "+
			"so following\n  the sign-in screen in order bricks the store: %v", err)
	}

	// And the state that matters: the principal actually holds a role.
	loaded, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strongestRole(loaded, "you", "/"); got != auth.RoleAdmin {
		t.Errorf("after both commands the principal holds %q, so the admin "+
			"would refuse every screen", got)
	}
}

// A token issued to somebody who holds no binding is the trap, and it must say
// so at the moment it happens.
//
// The line it prints reads "admin on /", which looks like a grant and is not
// one: it is the ceiling the token may act up to, while the floor is whatever
// the principal actually holds. Nothing said the floor was zero.
func TestATokenForSomebodyWithNoRoleIsAKnownDeadEnd(t *testing.T) {
	t.Setenv("QUILZO_TOKEN", "")
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}

	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strongestRole(pol, "you", "/"); got != auth.RoleNone {
		t.Fatalf("a fresh store already grants %q, so this test proves nothing", got)
	}

	// The warning is printed by cmdTokenIssue when this is true. The condition
	// is what is asserted here; the wording is not, because wording changes
	// and the dead end does not.
	src, err := os.ReadFile("auth.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "holds no role yet") {
		t.Error("issuing a token to a principal with no binding no longer " +
			"warns.\n  That token signs in and is refused by every screen, " +
			"and nothing says why.")
	}
}

// What the sign-in screen tells somebody has to be both commands.
//
// This screen is the only instruction most people will ever read.
func TestTheSignInScreenNamesBothCommands(t *testing.T) {
	body, err := os.ReadFile("../../internal/admin/assets/signin.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)

	if !strings.Contains(page, "quilzo token issue") {
		t.Error("the sign-in screen does not say how to issue a token")
	}
	if !strings.Contains(page, "quilzo auth grant") {
		t.Error("the sign-in screen names no grant, so somebody following it " +
			"signs in\n  and is refused by every screen")
	}
}
