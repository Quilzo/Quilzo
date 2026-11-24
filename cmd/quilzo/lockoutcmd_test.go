// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/lockout"
	"github.com/quilzo/quilzo/internal/out"
)

// The operator lets a locked-out administrator in again from the command
// line, which is how a store whose only administrator is locked out gets
// them back; somebody without the right to grant cannot.
func TestAuthUnlockLetsALockedOutAccountIn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	for _, g := range [][]string{{"grant", "boss", "admin"}, {"grant", "pat", "author"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	for i := 0; i < lockout.Ceiling; i++ {
		if _, _, err := lockoutStore(root).Fail("boss", "192.0.2.10", now); err != nil {
			t.Fatal(err)
		}
	}
	ts, _ := loadTokens(root)
	pat, _, err := ts.Issue("p", "pat", auth.RoleAuthor, "/", time.Hour, auth.RoleAuthor)
	if err != nil {
		t.Fatal(err)
	}
	boss, _, err := ts.Issue("b", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", pat)
	if err := cmdAuth(root, []string{"unlock", "boss"}); err == nil {
		t.Error("an author unlocked an administrator")
	}
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuth(root, []string{"unlock", "boss"}); err != nil {
		t.Fatal(err)
	}
	if held, _ := lockoutStore(root).Held(now); len(held) != 0 {
		t.Fatalf("still held: %+v", held)
	}
	body, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(body), "account.unlocked") {
		t.Error("the unlock was not recorded")
	}
}

// lockedOutStore is a store with two administrators, dana and lee, and a
// token for each, where dana is locked out.
func lockedOutStore(t *testing.T) (root, dana, lee string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root, dana, lee = twoAdmins(t)
	for i := 0; i < lockout.Ceiling; i++ {
		if _, _, err := lockoutStore(root).Fail("dana", "192.0.2.10", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return root, dana, lee
}

// Nobody unlocks themselves while another administrator is there to ask.
//
// The Sign-ins screen refuses it: "Somebody else has to unlock you: that
// is the point of a lockout." The command line asked only whether the
// caller may grant access, so a locked-out administrator, or whoever held
// their token, ran `quilzo auth unlock` on their own name and was let in
// again from everywhere, with a second administrator a message away. The
// command is how a store's only administrator gets back, and is still
// that.
func TestNobodyUnlocksThemselvesWhileAnotherAdministratorCan(t *testing.T) {
	root, dana, lee := lockedOutStore(t)
	unlock := func(token, name string) error {
		return as(t, token, func() error { return cmdAuth(root, []string{"unlock", name}) })
	}
	err := unlock(dana, "dana")
	if err == nil || exitCode(err) != out.ExitBlocked || !strings.Contains(err.Error(), "omebody else has to unlock you") {
		t.Fatalf("a locked-out administrator unlocking themselves, with another there: %v", err)
	}
	// However their name is written.
	if err := unlock(dana, "Dana"); err == nil {
		t.Fatal("unlocked themselves under another spelling of their name")
	}
	if held, _ := lockoutStore(root).Held(time.Now()); len(held) != 1 {
		t.Fatalf("no longer held: %+v", held)
	}
	refused := auditFor(t, root, "account.unlocked")
	if len(refused) != 2 || refused[0].Outcome != audit.Denied {
		t.Fatalf("the refusals are not in the log: %+v", refused)
	}
	// The other administrator unlocks them, as on the screen.
	if err := unlock(lee, "dana"); err != nil {
		t.Fatal(err)
	}
	if held, _ := lockoutStore(root).Held(time.Now()); len(held) != 0 {
		t.Fatalf("still held: %+v", held)
	}
	done := auditFor(t, root, "account.unlocked")
	if last := done[len(done)-1]; last.Outcome != audit.Success || last.Detail["alone"] != "" {
		t.Fatalf("the unlock by another administrator: %+v", last)
	}
	// Somebody who is not locked out is told that, as before, and refused
	// nothing.
	if err := unlock(dana, "dana"); err != nil || len(auditFor(t, root, "account.unlocked")) != len(done) {
		t.Fatalf("asking about an account that is not held: %v", err)
	}
}

// The only administrator there is unlocks themselves, and the record says
// it was done alone; not for a day after another administrator stopped
// being one, as with everything else one administrator does alone.
func TestTheOnlyAdministratorUnlocksThemselvesAndTheRecordSaysSo(t *testing.T) {
	root, dana, _ := lockedOutStore(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.RevokeNamed("lee", "admin", "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	unlock := func() error {
		return as(t, dana, func() error { return cmdAuth(root, []string{"unlock", "dana"}) })
	}
	err := unlock()
	if err == nil || exitCode(err) != out.ExitBlocked || !strings.Contains(err.Error(), "a day after another") {
		t.Fatalf("the only administrator, a moment after the other left: %v", err)
	}
	if got := auditFor(t, root, "dual.alone-refused"); len(got) != 1 {
		t.Fatalf("the refusal to act alone is not in the log: %+v", got)
	}
	if held, _ := lockoutStore(root).Held(time.Now()); len(held) != 1 {
		t.Fatalf("no longer held: %+v", held)
	}
	// A day on, with nobody else to ask, they are who unlocks them.
	if err := os.Remove(dualStore(root).Path); err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if held, _ := lockoutStore(root).Held(time.Now()); len(held) != 0 {
		t.Fatalf("still held: %+v", held)
	}
	done := auditFor(t, root, "account.unlocked")
	if last := done[len(done)-1]; last.Outcome != audit.Success || last.Detail["alone"] != "true" {
		t.Fatalf("the record does not say it was done alone: %+v", last)
	}
}

// Nobody unlocks themselves by writing their name so the lockout record
// takes it for theirs and the check before it does not.
//
// The record finds an account by its name in any case, strings.EqualFold,
// to which the long s, ſ (U+017F), is an s; the check that the lockout
// was not the caller's own compared the name as typed with
// auth.SamePerson, to which it is not. Locked out, ross ran
// `quilzo auth unlock roſs` and was let in again from everywhere, with
// dana and lee a message away.
func TestNobodyUnlocksThemselvesUnderAFoldedSpellingOfTheirName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root, _, lee := twoAdmins(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "ross", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	ross, _, err := ts.Issue("ross", "ross", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < lockout.Ceiling; i++ {
		if _, _, err := lockoutStore(root).Fail("ross", "192.0.2.10", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	unlock := func(token, name string) error {
		return as(t, token, func() error { return cmdAuth(root, []string{"unlock", name}) })
	}
	for _, name := range []string{"ro\u017fs", "RO\u017fS", "Ro\u017f\u017f"} {
		if err := unlock(ross, name); err == nil || exitCode(err) != out.ExitBlocked {
			t.Errorf("ross unlocked himself as %q: %v", name, err)
		}
	}
	if held, _ := lockoutStore(root).Held(time.Now()); len(held) != 1 {
		t.Fatalf("ross is no longer held: %+v", held)
	}
	// The refusals name the account, not the spelling.
	key, err := os.ReadFile(auditKeyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	rossInTheLog := audit.Pseudonym(key, "ross")
	for _, r := range auditFor(t, root, "account.unlocked") {
		if r.Outcome != audit.Denied || r.Detail["for"] != rossInTheLog {
			t.Fatalf("a refusal: %+v", r)
		}
	}
	// Another administrator unlocks him, however they write his name, and
	// the record says whose lockout it was.
	if err := unlock(lee, "ro\u017fs"); err != nil {
		t.Fatal(err)
	}
	if held, _ := lockoutStore(root).Held(time.Now()); len(held) != 0 {
		t.Fatalf("still held: %+v", held)
	}
	done := auditFor(t, root, "account.unlocked")
	if last := done[len(done)-1]; last.Outcome != audit.Success || last.Detail["for"] != rossInTheLog {
		t.Fatalf("the unlock by another administrator: %+v", last)
	}
}
