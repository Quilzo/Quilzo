// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/saml"
)

// onlyOwner is a store whose one administrator is owner, acting with a
// token of their own, beside dana, who is an author.
func onlyOwner(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	// What the commands say goes nowhere: a token issued here is printed
	// under --json, and a credential is not written to the test's output.
	w.Out = &bytes.Buffer{}
	seedPolicy(t, root, [2]string{"owner", "admin"})
	asOnly(t, root, "owner")
	if err := cmdAuth(root, []string{"grant", "dana", "author"}); err != nil {
		t.Fatal(err)
	}
	return root
}

func administers(t *testing.T, root, who string) bool {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return pol.Evaluate(who, auth.ActGrant, "/").Allowed
}

// The last administrator is never revoked or denied from the command line,
// as the People screen and the access review already refuse it.
//
// `quilzo auth revoke owner admin`, run by the only administrator, said
// "removed 1 binding(s)" and left nobody able to grant anything: the grant
// back and a new token were refused, and the break-glass refused too,
// because the token that could no longer administer still counted as "an
// admin token still usable". With no other binding the policy was left
// empty, and an empty policy switches access control off.
func TestTheLastAdministratorIsNeverRevokedOrDeniedFromTheCommandLine(t *testing.T) {
	root := onlyOwner(t)
	if err := cmdAuth(root, []string{"revoke", "owner", "admin"}); err == nil {
		t.Error("the only administrator's admin binding was revoked")
	}
	if !administers(t, root, "owner") {
		t.Fatal("nobody administers the store after a revoke")
	}
	if err := cmdAuth(root, []string{"deny", "owner", "admin"}); err == nil {
		t.Error("the only administrator was denied admin")
	}
	if !administers(t, root, "owner") {
		t.Fatal("nobody administers the store after a deny")
	}

	// With nothing else in the policy, revoking it would have emptied it.
	bare := t.TempDir() + "/st"
	if err := cmdInit(bare); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, bare, [2]string{"owner", "admin"})
	asOnly(t, bare, "owner")
	if err := cmdAuth(bare, []string{"revoke", "owner", "admin"}); err == nil {
		t.Error("the only binding of the only administrator was revoked")
	}
	if pol, _ := loadPolicy(bare); len(pol.Bindings) == 0 {
		t.Fatal("the policy was emptied, which turns access control off")
	}

	// A second administrator may be removed, and either may then not be.
	seedPolicy(t, root, [2]string{"lee", "admin"})
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatalf("one of two administrators could not be removed: %v", err)
	}
}

// The break-glass counts an admin token as a way in only while the policy
// still lets its holder administer. A token that carries admin for
// somebody the policy no longer lets grant reaches nothing, and counting it
// refused the one recovery there was.
func TestARecoveryIsNotRefusedOverATokenThatCanNoLongerAdminister(t *testing.T) {
	root := onlyOwner(t)
	// Written by hand, as a store would be left by anything that took the
	// last administrator away before the guard did.
	pol, _ := loadPolicy(root)
	pol.Bindings = []auth.Binding{{Principal: "owner", Role: auth.RoleAuthor, Resource: "/"},
		{Principal: "dana", Role: auth.RoleAuthor, Resource: "/"}}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	_, printed := captureStdout(t)
	err := cmdRecover(root, []string{"--principal", "owner", "--reason", "locked out", "--i-have-filesystem-access"})
	_ = printed()
	if err != nil && strings.Contains(err.Error(), "still usable") {
		t.Fatalf("the recovery counted a token that administers nothing: %v", err)
	}
	if !administers(t, root, "owner") {
		t.Fatalf("the recovery did not give the store an administrator back: %v", err)
	}
}

// A store nobody has ever had access to is new, whichever command made
// its folders, so `init --admin` on it gives two factors from now, not the
// fortnight's grace an upgraded installation gets.
//
// `quilzo demo`, or `quilzo init --admni owner` with a typo, made the store,
// and the `init --admin owner` after it found one there and wrote nothing:
// the first `quilzo serve` then wrote the grace, and for two weeks a token
// alone opened the admin of a store that was a day old.
func TestAStoreNobodyHasEnteredGetsTwoFactorsFromInit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	w.Out = &bytes.Buffer{}

	root := demoStore(t)
	w.Out = &bytes.Buffer{}
	if err := runInit(root, []string{"--admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if from, ok := mfaFromIfSet(root); !ok || time.Until(from) > time.Minute {
		t.Errorf("a store made by demo gets two factors from %v (%v), not now", from, ok)
	}

	typo := t.TempDir() + "/st"
	if err := runInit(typo, []string{"--admni", "owner"}); err == nil {
		t.Fatal("a mistyped flag was accepted")
	}
	if isStore(typo) {
		t.Error("a mistyped flag made a store before it was refused")
	}
	if err := runInit(typo, []string{"--admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if from, ok := mfaFromIfSet(typo); !ok || time.Until(from) > time.Minute {
		t.Errorf("after a mistyped init, two factors start at %v (%v), not now", from, ok)
	}

	// A store somebody already signs in to keeps whatever it was given.
	used := onlyOwner(t)
	if err := runInit(used, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := mfaFromIfSet(used); ok {
		t.Error("init wrote a date for a store people already sign in to")
	}
}

// A name typed after --by is credited and never recorded in place of the
// verified caller who acted.
//
// `posture suppress --by 'Dana (CISO)'` wrote the risk acceptance to the
// audit log under Dana, unverified, and left out the administrator who ran
// it; `auth grant --by` set "granted by" to the name typed; and `checked set
// --by` let an author record somebody else's confirmation.
func TestAnyNameTypedAfterByIsCreditedNotRecorded(t *testing.T) {
	root := onlyOwner(t)
	granted := auditFor(t, root, "auth.granted")
	if len(granted) == 0 {
		t.Fatal("no grant on the record to compare with")
	}
	owner := granted[0].Principal

	if err := postureSuppress(root, []string{"mfa.no-second-factor", "--reason", "accepted by the board",
		"--by", "Dana (CISO)", "--days", "90"}); err != nil {
		t.Fatal(err)
	}
	got := auditFor(t, root, "posture.suppress")
	if len(got) != 1 || got[0].Principal != owner || !got[0].Verified {
		t.Errorf("the suppression is recorded as %+v, not as the administrator who made it", got)
	}
	f := &suppressionFile{}
	_ = loadJSON(suppressPath(root), f)
	if len(f.Suppressions) != 1 || !strings.HasPrefix(f.Suppressions[0].By, "owner") ||
		!strings.Contains(f.Suppressions[0].By, "Dana (CISO)") {
		t.Errorf("the suppression is by %+v", f.Suppressions)
	}

	if err := cmdAuth(root, []string{"grant", "mallory", "reader", "--by", "Dana (CISO)"}); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	for _, b := range pol.Snapshot() {
		if b.Principal == "mallory" && (b.GrantedBy != "owner" || !strings.Contains(b.Note, "Dana (CISO)")) {
			t.Errorf("mallory's grant is by %q, noted %q", b.GrantedBy, b.Note)
		}
	}

	pages, _ := draftPageIDs(root)
	if len(pages) == 0 {
		// The store has no draft pages; a demonstration gives it some.
		if err := cmdDemo(root, []string{"-publish=false", "-templates", t.TempDir() + "/tpl"}); err != nil {
			t.Fatal(err)
		}
		pages, _ = draftPageIDs(root)
	}
	ts, _ := loadTokens(root)
	dana, _, err := ts.Issue("dana", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := checkedSet(root, []string{pages[0], "--by", "Priya (Compliance)", "--note", "legal reviewed"}); err != nil {
		t.Fatal(err)
	}
	st, _ := openChecked(root)
	r, err := st.Get(pages[0])
	if err != nil || r.By != "dana" || !strings.Contains(r.Note, "Priya (Compliance)") {
		t.Errorf("the check is recorded as %+v %v", r, err)
	}
}

// `gateway budget CALLER` with no change to make shows the budget and
// keeps it, and one limit changed keeps the others.
//
// Asked with no flags, it wrote the caller a budget of zeros, which is
// unlimited, and said nothing; `--per-minute 10` alone dropped the
// character and token caps.
func TestAGatewayBudgetIsShownAndChangedOneLimitAtATime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	var buf bytes.Buffer
	w.Out = &buf
	budget := func() gateway.Budget {
		t.Helper()
		cfg, err := gateway.Load(gatewayPath(root))
		if err != nil || cfg == nil {
			t.Fatalf("%v %v", cfg, err)
		}
		for _, b := range cfg.Budgets {
			if b.Consumer == "chatbot:help" {
				return b
			}
		}
		return gateway.Budget{}
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--per-minute", "5",
		"--chars-per-day", "20000", "--tokens-per-day", "9000"}); err != nil {
		t.Fatal(err)
	}
	set := gateway.Budget{Consumer: "chatbot:help", PerMinute: 5, CharsPerDay: 20000, TokensPerDay: 9000}
	if budget() != set {
		t.Fatalf("the budget set is %+v", budget())
	}
	buf.Reset()
	if err := cmdGateway(root, []string{"budget", "chatbot:help"}); err != nil {
		t.Fatal(err)
	}
	if budget() != set {
		t.Errorf("asking for the budget changed it to %+v", budget())
	}
	var shown gateway.Budget
	if err := json.Unmarshal(buf.Bytes(), &shown); err != nil || shown != set {
		t.Errorf("the budget shown is %q (%v)", buf.String(), err)
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--per-minute", "10"}); err != nil {
		t.Fatal(err)
	}
	set.PerMinute = 10
	if budget() != set {
		t.Errorf("one limit changed left %+v", budget())
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--tokens-per-day", "0"}); err != nil {
		t.Fatal(err)
	}
	set.TokensPerDay = 0
	if budget() != set {
		t.Errorf("a limit set to unlimited left %+v", budget())
	}
}

// adminSafetyToken gives who a token as asOnly does, without acting as them.
func adminSafetyToken(t *testing.T, root, who string, role auth.Role) string {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue(who, who, role, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

// A second administrator can be set up in either order: granted admin and
// then given a passkey or a token, or given a passkey as an author and then
// granted admin. Granted first, every way they could sign in waited for a
// second administrator, and the only other one was them, with no way in.
//
// Once they have a way in, there are two, and one asks while the other
// decides: one administrator does not give herself the other's sign-in.
func TestASecondAdministratorIsSetUpInEitherOrder(t *testing.T) {
	root := onlyOwner(t)
	if err := cmdAuth(root, []string{"grant", "theo", "admin"}); err != nil {
		t.Fatal(err)
	}
	if !administers(t, root, "theo") {
		t.Fatal("the only administrator could not make theo one")
	}
	w.Out = &bytes.Buffer{}
	if err := cmdAuth(root, []string{"enrol", "theo", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 1 || links[0].Principal != "theo" {
		t.Fatalf("theo, an administrator with no way in, was given no link: %+v", links)
	}
	if pend, _ := dualStore(root).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("it waits for theo to approve his own way in: %+v", pend)
	}

	// The token, in the same order, on another store.
	other := onlyOwner(t)
	if err := cmdAuth(other, []string{"grant", "theo", "admin"}); err != nil {
		t.Fatal(err)
	}
	_, printed := captureStdout(t)
	err := tokenIssue(other, []string{"theo-cli", "--principal", "theo", "--role", "admin", "--ttl", "1h"})
	_ = printed()
	if err != nil {
		t.Fatal(err)
	}
	if pend, _ := dualStore(other).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("theo's first token waits for theo: %+v", pend)
	}

	// Theo now has a way in, so there are two administrators, and another
	// way in for either waits for the other.
	w.Out = &bytes.Buffer{}
	if err := cmdAuth(other, []string{"enrol", "theo", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if pend, _ := dualStore(other).Pending(time.Now()); len(pend) != 1 || pend[0].Kind != dual.Enrol {
		t.Fatalf("a link for an administrator who can sign in did not wait: %+v", pend)
	}

	// An administrator with a way in already is not given another alone.
	third := onlyOwner(t)
	seedPolicy(t, third, [2]string{"lee", "admin"})
	adminSafetyToken(t, third, "lee", auth.RoleAdmin)
	if err := cmdAuth(third, []string{"enrol", "lee", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(third).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("one administrator gave herself another's sign-in: %+v", links)
	}

	// Nor while a request of hers waits for the one with no way in: given
	// his sign-in, she would approve it as him.
	fourth := onlyOwner(t)
	seedPolicy(t, fourth, [2]string{"theo", "admin"})
	if err := cmdAuth(fourth, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(fourth, []string{"enrol", "theo", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(fourth).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("a link was given alone for the administrator a waiting request is for: %+v", links)
	}
}

// A token carries at most its holder's role, when it is issued and when it
// is listed.
//
// `token issue jun-pub --principal jun --role publisher`, for jun the
// author, issued it and listed it as publisher, and everything it was used
// for was refused: "jun is author on /; publish needs publisher".
func TestATokenCarriesNoMoreThanItsHoldersRole(t *testing.T) {
	root := onlyOwner(t)
	_, printed := captureStdout(t)
	err := tokenIssue(root, []string{"dana-pub", "--principal", "dana", "--role", "publisher", "--ttl", "1h"})
	_ = printed()
	if err == nil || !strings.Contains(err.Error(), "author") {
		t.Errorf("a publisher's token was issued for an author: %v", err)
	}

	// One issued before this was refused is listed as what it can use.
	adminSafetyToken(t, root, "dana", auth.RolePublisher)
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := tokenList(root); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, row := range got.Tokens {
		if row["principal"] == "dana" && row["role"] != string(auth.RoleAuthor) {
			t.Errorf("dana's token is listed as %v", row["role"])
		}
	}
}

// Before anybody administers the store, a change that would wait for a
// second administrator is not said to be the only administrator's.
func TestTheBootstrapDoesNotNameAnAdministratorNobodyIs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	t.Cleanup(func() { w = nil })
	apply, err := proposeSecond(root, resolveCaller(root, ""), dual.AuditLog, "move the audit log",
		dual.AuditLogChange{Dir: t.TempDir()}, "")
	if err != nil || !apply {
		t.Fatalf("%v %v", apply, err)
	}
	if strings.Contains(buf.String(), "only administrator") {
		t.Errorf("before anybody administers the store, it says: %s", buf.String())
	}
}

// Revoking a lesser grant from an administrator says what they still have
// once, not again in the words of the binding that gives it.
func TestARevokeSaysWhatIsLeftOnce(t *testing.T) {
	root := onlyOwner(t)
	seedPolicy(t, root, [2]string{"theo", "author"}, [2]string{"theo", "admin"})
	_, printed := captureStdout(t)
	err := cmdAuth(root, []string{"revoke", "theo", "author"})
	said := printed()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said, "theo still has admin on /") || strings.Contains(said, "granted at") {
		t.Errorf("the revoke said:\n%s", said)
	}
	// From a wider grant, where it comes from is still said.
	seedPolicy(t, root, [2]string{"kim", "reader"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "kim", Role: auth.RoleAuthor, Resource: "/blog"})
	}); err != nil {
		t.Fatal(err)
	}
	_, printed = captureStdout(t)
	err = cmdAuth(root, []string{"revoke", "kim", "author", "--on", "/blog"})
	said = printed()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said, "granted at /") {
		t.Errorf("an inherited grant left does not say where it comes from:\n%s", said)
	}
}

// usedToken gives who a token they have used, as one is once its holder
// has run a command with it, made at and ending at the times given.
func usedToken(t *testing.T, root, who string, role auth.Role, made, ends time.Time) string {
	t.Helper()
	ts, _ := loadTokens(root)
	_, tok, err := ts.Issue(who+"-cli", who, role, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ts.Tokens {
		if ts.Tokens[i].ID == tok.ID {
			ts.Tokens[i].CreatedAt, ts.Tokens[i].ExpiresAt = made.Unix(), ends.Unix()
			ts.Tokens[i].LastUsed = made.Unix()
		}
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return tok.ID
}

// An administrator who has signed in is the second of two from then on.
// Their sign-in is not the other's to give alone again because nothing of
// theirs works at the moment it is asked for.
//
// The first way in was approved alone whenever the administrator it was
// for held no token that worked and no passkey. So one administrator
// revoked the other's token, which is one administrator's to do, was told
// "lee has no way to sign in yet", issued herself a token as lee and
// approved her own request with it. A token of his that had run out did
// as well, and so did his signing in through the identity provider and
// holding no session that night.
func TestAnAdministratorWhoHasSignedInIsNotGivenAWayInAlone(t *testing.T) {
	now := time.Now()
	for name, second := range map[string]func(t *testing.T, root string) string{
		"whose token the other revoked": func(t *testing.T, root string) string {
			seedPolicy(t, root, [2]string{"lee", "admin"})
			id := usedToken(t, root, "lee", auth.RoleAdmin, now, now.Add(time.Hour))
			_, printed := captureStdout(t)
			err := cmdToken(root, []string{"revoke", id})
			_ = printed()
			if err != nil {
				t.Fatal(err)
			}
			return "lee"
		},
		"whose token ran out": func(t *testing.T, root string) string {
			// An administrator since yesterday, whose token was for an hour.
			if _, err := updatePolicy(root, func(p *auth.Policy) error {
				return p.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/",
					GrantedAt: now.Add(-24 * time.Hour).Unix()})
			}); err != nil {
				t.Fatal(err)
			}
			usedToken(t, root, "lee", auth.RoleAdmin, now.Add(-2*time.Hour), now.Add(-time.Hour))
			return "lee"
		},
		"who signs in through OpenID Connect": func(t *testing.T, root string) string {
			seedPolicy(t, root, [2]string{"lee@northwind.example", "admin"})
			if err := saveJSON(oidcPath(root), oidcConfig{Issuer: "https://id.northwind.example", ClientID: "quilzo"}); err != nil {
				t.Fatal(err)
			}
			return "lee@northwind.example"
		},
		"who signs in through SAML": func(t *testing.T, root string) string {
			seedPolicy(t, root, [2]string{"lee@northwind.example", "admin"})
			if err := os.MkdirAll(samlDir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			c := saml.Config{Name: "corp", Domains: []string{"northwind.example"}}
			if err := saveJSON(samlFile(root, c.Name), c); err != nil {
				t.Fatal(err)
			}
			return "lee@northwind.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := onlyOwner(t)
			who := second(t, root)
			if err := cmdAuth(root, []string{"enrol", who, "--for", "1h"}); err != nil {
				t.Fatal(err)
			}
			if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 0 {
				t.Errorf("a link that signs in as %s was given on one administrator's word: %+v", who, links)
			}

			// And a token as them, asked for with nothing else waiting.
			root = onlyOwner(t)
			who = second(t, root)
			_, printed := captureStdout(t)
			err := tokenIssue(root, []string{"again", "--principal", who, "--role", "admin", "--ttl", "1h"})
			_ = printed()
			if err != nil {
				t.Fatal(err)
			}
			ts, _ := loadTokens(root)
			for _, tok := range ts.Snapshot() {
				if tok.Name == "again" {
					t.Errorf("a token acting as %s was issued on one administrator's word", who)
				}
			}
		})
	}

	// What never made them a second administrator does not count: a first
	// token that ran out before anybody used it, and one from before they
	// were made an administrator, are no way in, and waiting on them would
	// be the dead end again.
	for name, second := range map[string]func(t *testing.T, root string){
		"a first token that ran out unused": func(t *testing.T, root string) {
			seedPolicy(t, root, [2]string{"theo", "admin"})
			ts, _ := loadTokens(root)
			_, tok, err := ts.Issue("theo-cli", "theo", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			for i := range ts.Tokens {
				if ts.Tokens[i].ID == tok.ID {
					ts.Tokens[i].ExpiresAt = now.Add(-time.Second).Unix()
				}
			}
			if err := saveJSON(tokensPath(root), ts); err != nil {
				t.Fatal(err)
			}
		},
		"a token from before they were an administrator": func(t *testing.T, root string) {
			usedToken(t, root, "theo", auth.RoleAuthor, now.Add(-2*time.Hour), now.Add(-time.Hour))
			seedPolicy(t, root, [2]string{"theo", "admin"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := onlyOwner(t)
			second(t, root)
			if err := cmdAuth(root, []string{"enrol", "theo", "--for", "1h"}); err != nil {
				t.Fatal(err)
			}
			if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 1 {
				t.Errorf("theo, who has never been able to act as an administrator, was given no link: %+v", links)
			}
		})
	}
}

// A token's ceiling is what its holder holds on its path or anywhere
// inside it, for as long as the grant lasts.
//
// The ceiling was the role held on the token's own path. A token over the
// whole site for kim, an author there and a publisher on /blog, was refused
// as publisher with "grant kim publisher first", and one for an analyst,
// who administers /@security and reads the rest, was refused as admin. One
// they did hold was listed as the lesser role, though it publishes /blog
// or administers the area: a list of credentials that says less than they
// can do. And a grant that had ended still counted, so a publisher's token
// was issued, and listed as one, for somebody whose publisher grant ran
// out yesterday.
func TestATokensCeilingIsWhatItsHolderHoldsWithinIt(t *testing.T) {
	root := onlyOwner(t)
	seedPolicy(t, root, [2]string{"kim", "author"}, [2]string{"ana", "reader"}, [2]string{"tam", "reader"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for _, b := range []auth.Binding{
			{Principal: "kim", Role: auth.RolePublisher, Resource: "/blog"},
			{Principal: "ana", Role: auth.RoleAdmin, Resource: auth.AreaSecurity},
			{Principal: "tam", Role: auth.RolePublisher, Resource: "/", Note: "cover for a week",
				Expires: time.Now().Add(-time.Hour).Unix()},
		} {
			if err := p.Grant(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	issue := func(name, who, role string) error {
		t.Helper()
		_, printed := captureStdout(t)
		err := tokenIssue(root, []string{name, "--principal", who, "--role", role, "--ttl", "1h"})
		_ = printed()
		return err
	}
	if err := issue("kim-site", "kim", "publisher"); err != nil {
		t.Errorf("a publisher's token for somebody who publishes /blog: %v", err)
	}
	if err := issue("kim-admin", "kim", "admin"); err == nil || !strings.Contains(err.Error(), "publisher") {
		t.Errorf("an administrator's token for somebody who holds publisher at most: %v", err)
	}
	if err := issue("ana-cli", "ana", "admin"); err != nil {
		t.Errorf("an administrator's token for somebody who administers /@security: %v", err)
	}
	if err := issue("tam-pub", "tam", "publisher"); err == nil || !strings.Contains(err.Error(), "reader") {
		t.Errorf("a publisher's token for somebody whose publisher grant has ended: %v", err)
	}

	// One issued before this was refused, for the grant that has ended.
	ts, _ := loadTokens(root)
	if _, _, err := ts.Issue("tam-old", "tam", auth.RolePublisher, "/", time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := tokenList(root); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	listed := map[string]any{}
	for _, row := range got.Tokens {
		listed[row["name"].(string)] = row["role"]
	}
	for name, want := range map[string]auth.Role{"kim-site": auth.RolePublisher, "ana-cli": auth.RoleAdmin,
		"tam-old": auth.RoleReader} {
		if listed[name] != string(want) {
			t.Errorf("%s is listed as %v, and can be used as %s", name, listed[name], want)
		}
	}
}
