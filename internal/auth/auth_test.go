package auth

import (
	"strings"
	"testing"
	"time"
)

// Access control fails silently. A hole grants something nobody asked for and
// nothing reports it, so these lean on the negative cases: what must *not* be
// allowed, and what must *not* be issuable.

func TestLadderIncludesEverythingBelow(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleReader) {
		t.Error("admin should include reader")
	}
	if RoleAuthor.AtLeast(RolePublisher) {
		t.Error("author must not include publisher — that is the boundary that matters")
	}
	if RoleNone.AtLeast(RoleReader) {
		t.Error("no binding must not imply read access")
	}
}

func TestGrantsInheritDownTheTree(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/blog"}))

	if d := p.Evaluate("sam", ActEditDraft, "/blog/2026/post"); !d.Allowed {
		t.Errorf("a grant on /blog should cover a page beneath it: %s", d.Reason)
	}
	if d := p.Evaluate("sam", ActEditDraft, "/legal"); d.Allowed {
		t.Error("a grant on /blog must not reach /legal")
	}
}

// Prefix matching is the obvious implementation and it is wrong: "/blog" would
// cover "/blog-drafts", granting access to a resource nobody named.
func TestSiblingPathsAreNotCovered(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/blog"}))
	if d := p.Evaluate("sam", ActEditDraft, "/blog-drafts/x"); d.Allowed {
		t.Error("/blog must not cover /blog-drafts")
	}
}

func TestPublishIsTheBoundary(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/"}))

	if d := p.Evaluate("sam", ActEditDraft, "/x"); !d.Allowed {
		t.Errorf("an author should write drafts: %s", d.Reason)
	}
	d := p.Evaluate("sam", ActPublish, "/x")
	if d.Allowed {
		t.Fatal("an author must not publish")
	}
	if !strings.Contains(d.Reason, "needs publisher") {
		t.Errorf("the refusal should name what is missing, got %q", d.Reason)
	}
}

// The GCP footgun this deliberately does not reproduce: inheritance there is
// additive and cannot be revoked from below, which forces the broad grant.
func TestDenyWinsAnywhereInTheTree(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RolePublisher, Resource: "/"}))
	must(t, p.Grant(Binding{Principal: "sam", Role: RolePublisher, Resource: "/legal", Deny: true}))

	if d := p.Evaluate("sam", ActPublish, "/blog/post"); !d.Allowed {
		t.Errorf("the site-wide grant should still work elsewhere: %s", d.Reason)
	}
	d := p.Evaluate("sam", ActPublish, "/legal/terms")
	if d.Allowed {
		t.Fatal("a deny on /legal must beat a grant on /")
	}
	if !strings.Contains(d.Reason, "denied") {
		t.Errorf("the reason should say it was denied, got %q", d.Reason)
	}
}

// Denying a rung must not leave the rungs above it open, or the deny closes
// nothing.
func TestDenyingALowRoleAlsoBlocksHigherOnes(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAdmin, Resource: "/"}))
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/secret", Deny: true}))

	if d := p.Evaluate("sam", ActPublish, "/secret/x"); d.Allowed {
		t.Error("denying author on /secret must also stop publishing there")
	}
}

// The case the first implementation got wrong, and that no test caught: a deny
// must be as narrow as it was written. Denying the ability to publish is not
// the same as denying the ability to look.
func TestDenyingAHighRoleLeavesLowerActionsAlone(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "dana", Role: RolePublisher, Resource: "/"}))
	must(t, p.Grant(Binding{Principal: "dana", Role: RolePublisher, Resource: "/legal", Deny: true}))

	if d := p.Evaluate("dana", ActPublish, "/legal/terms"); d.Allowed {
		t.Error("the deny should stop publishing")
	}
	if d := p.Evaluate("dana", ActView, "/legal/terms"); !d.Allowed {
		t.Errorf("denying publish must not remove read access: %s", d.Reason)
	}
	if d := p.Evaluate("dana", ActEditDraft, "/legal/terms"); !d.Allowed {
		t.Errorf("denying publish must not stop drafting: %s", d.Reason)
	}
}

func TestNoBindingMeansNoAccess(t *testing.T) {
	p := &Policy{}
	if d := p.Evaluate("stranger", ActView, "/"); d.Allowed {
		t.Error("default must be deny")
	}
}

func TestUnknownActionIsRefused(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAdmin, Resource: "/"}))
	d := p.Evaluate("sam", Action("delete-everything"), "/")
	if d.Allowed {
		t.Error("an unknown action must not be allowed, even for an admin")
	}
}

// The feature that makes this usable: an answer you can act on.
func TestDecisionExplainsItself(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/blog"}))
	d := p.Evaluate("sam", ActEditDraft, "/blog/post")

	if d.Binding == nil {
		t.Fatal("the deciding binding should be returned")
	}
	if d.Binding.Resource != "/blog" {
		t.Errorf("wrong binding cited: %v", d.Binding)
	}
	if len(d.Trail) == 0 {
		t.Error("the trail should show what was considered")
	}
	if !strings.Contains(d.Reason, "/blog") {
		t.Errorf("the reason should name where the grant came from, got %q", d.Reason)
	}
}

func TestPathsNormalise(t *testing.T) {
	p := &Policy{}
	must(t, p.Grant(Binding{Principal: "sam", Role: RoleReader, Resource: "blog/"}))
	if d := p.Evaluate("sam", ActView, "/blog"); !d.Allowed {
		t.Errorf("blog/ and /blog are the same place: %s", d.Reason)
	}
	if err := p.Grant(Binding{Principal: "sam", Role: RoleReader, Resource: "/blog"}); err == nil {
		t.Error("the same binding written differently should be refused as a duplicate")
	}
}

// -- tokens ------------------------------------------------------------------

func TestTokenIsShownOnceAndStoredHashed(t *testing.T) {
	ts := &TokenStore{}
	secret, tok, err := ts.Issue("ci", "sam", RoleAuthor, "/", time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, TokenPrefix) {
		t.Errorf("tokens need a prefix so scanners can spot a leak, got %q", secret)
	}
	if strings.Contains(tok.Hash, secret) || tok.Hash == secret {
		t.Fatal("the secret must not be recoverable from the stored record")
	}
	if len(secret) < 40 {
		t.Errorf("token looks too short to be 256 bits: %d chars", len(secret))
	}
}

func TestTokenCannotExceedItsIssuer(t *testing.T) {
	ts := &TokenStore{}
	_, _, err := ts.Issue("escalate", "sam", RoleAdmin, "/", time.Hour, RolePublisher)
	if err == nil {
		t.Fatal("a publisher must not mint an admin token")
	}
	if !strings.Contains(err.Error(), "does not create more") {
		t.Errorf("the refusal should explain why, got %q", err)
	}
}

func TestTokenMustExpire(t *testing.T) {
	ts := &TokenStore{}
	if _, _, err := ts.Issue("forever", "sam", RoleAuthor, "/", 0, RoleAdmin); err == nil {
		t.Fatal("a token with no expiry should be refused")
	}
}

func TestAuthenticateRejectsTheWrongToken(t *testing.T) {
	ts := &TokenStore{}
	secret, _, err := ts.Issue("ci", "sam", RoleAuthor, "/", time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	if _, err := ts.Authenticate(secret, now); err != nil {
		t.Fatalf("the real token should work: %v", err)
	}
	if _, err := ts.Authenticate(secret+"x", now); err == nil {
		t.Error("a modified token must not authenticate")
	}
	if _, err := ts.Authenticate("not-a-token", now); err == nil {
		t.Error("something without the prefix must not authenticate")
	}
}

func TestExpiredAndRevokedTokensStopWorking(t *testing.T) {
	ts := &TokenStore{}
	secret, tok, err := ts.Issue("short", "sam", RoleAuthor, "/", time.Minute, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	later := time.Now().Add(2 * time.Minute)
	if _, err := ts.Authenticate(secret, later); err == nil {
		t.Error("an expired token must not authenticate")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error should say it expired, got %q", err)
	}

	fresh, tok2, _ := ts.Issue("live", "sam", RoleAuthor, "/", time.Hour, RoleAdmin)
	_, rerr := ts.Revoke(tok2.ID)
	must(t, rerr)
	if _, err := ts.Authenticate(fresh, time.Now()); err == nil {
		t.Error("a revoked token must not authenticate")
	}
	if _, err := ts.Revoke(tok.ID); err != nil {
		t.Errorf("revoking an expired token should still work: %v", err)
	}
}

func TestLastUsedIsRecorded(t *testing.T) {
	ts := &TokenStore{}
	secret, _, _ := ts.Issue("ci", "sam", RoleAuthor, "/", time.Hour, RoleAdmin)
	if ts.Tokens[0].LastUsed != 0 {
		t.Fatal("a fresh token has not been used")
	}
	now := time.Now()
	if _, err := ts.Authenticate(secret, now); err != nil {
		t.Fatal(err)
	}
	if ts.Tokens[0].LastUsed != now.Unix() {
		t.Error("use should be recorded, so an unused credential can be found later")
	}
}

func TestStaleFindsForgottenTokens(t *testing.T) {
	ts := &TokenStore{}
	_, _, _ = ts.Issue("old", "sam", RoleAuthor, "/", 90*24*time.Hour, RoleAdmin)
	ts.Tokens[0].CreatedAt = time.Now().Add(-60 * 24 * time.Hour).Unix()

	stale := ts.Stale(time.Now(), 30*24*time.Hour)
	if len(stale) != 1 {
		t.Errorf("a token unused for 60 days should be reported stale, got %d", len(stale))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// -- exchange ----------------------------------------------------------------

// The point of a session: what you store and what you use stop being the same
// object, so exposure of the second is bounded by a clock.
func TestExchangeMintsAShortLivedSession(t *testing.T) {
	ts := &TokenStore{}
	parent, _, err := ts.Issue("ci", "alice", RolePublisher, "/", 720*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	secret, sess, err := ts.Exchange(parent, RoleNone, "", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if secret == parent {
		t.Fatal("a session must be a different credential")
	}
	if !sess.IsSession() {
		t.Error("a session should know its parent")
	}
	if d := time.Unix(sess.ExpiresAt, 0).Sub(now); d > DefaultSessionTTL+time.Second {
		t.Errorf("session lives %s, expected about %s", d, DefaultSessionTTL)
	}
	if _, err := ts.Authenticate(secret, now); err != nil {
		t.Errorf("the session should authenticate: %v", err)
	}
}

// A session narrows or stays the same. Widening would be an escalation path
// wearing the clothes of a convenience.
func TestASessionCannotWiden(t *testing.T) {
	ts := &TokenStore{}
	parent, _, _ := ts.Issue("ci", "alice", RoleAuthor, "/blog", 720*time.Hour, RoleAdmin)
	now := time.Now()

	if _, _, err := ts.Exchange(parent, RolePublisher, "", 0, now); err == nil {
		t.Error("a session must not carry more than its parent")
	}
	if _, _, err := ts.Exchange(parent, RoleNone, "/", 0, now); err == nil {
		t.Error("a session must not reach outside its parent's scope")
	}
	// Narrowing is fine, and is the reason to exchange at all.
	if _, sess, err := ts.Exchange(parent, RoleReader, "/blog/post", 0, now); err != nil {
		t.Errorf("narrowing should be allowed: %v", err)
	} else if sess.Role != RoleReader || sess.Resource != "/blog/post" {
		t.Errorf("the narrowed session is wrong: %+v", sess)
	}
}

func TestSessionLifetimeIsCapped(t *testing.T) {
	ts := &TokenStore{}
	parent, _, _ := ts.Issue("ci", "alice", RolePublisher, "/", 720*time.Hour, RoleAdmin)
	now := time.Now()

	if _, _, err := ts.Exchange(parent, RoleNone, "", 30*24*time.Hour, now); err == nil {
		t.Error("a session lasting a month is not a session")
	}

	// And never past the parent, or it outlives the credential it came from.
	short, _, _ := ts.Issue("short", "alice", RolePublisher, "/", 5*time.Minute, RoleAdmin)
	_, sess, err := ts.Exchange(short, RoleNone, "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if time.Unix(sess.ExpiresAt, 0).After(now.Add(6 * time.Minute)) {
		t.Error("the session outlived its parent")
	}
}

func TestASessionCannotBeExchangedAgain(t *testing.T) {
	ts := &TokenStore{}
	parent, _, _ := ts.Issue("ci", "alice", RolePublisher, "/", 720*time.Hour, RoleAdmin)
	now := time.Now()
	sessSecret, _, _ := ts.Exchange(parent, RoleNone, "", 0, now)

	// Chaining would let a session re-mint itself just before expiry and so
	// outlive both its parent and any revocation of it.
	if _, _, err := ts.Exchange(sessSecret, RoleNone, "", 0, now); err == nil {
		t.Error("a session should not be exchangeable")
	}
}

// Revocation that leaves sessions running is not revocation.
func TestRevokingAParentKillsItsSessions(t *testing.T) {
	ts := &TokenStore{}
	parentSecret, parent, _ := ts.Issue("ci", "alice", RolePublisher, "/", 720*time.Hour, RoleAdmin)
	now := time.Now()

	a, _, _ := ts.Exchange(parentSecret, RoleNone, "", 0, now)
	b, _, _ := ts.Exchange(parentSecret, RoleNone, "", 0, now)

	for _, s := range []string{a, b} {
		if _, err := ts.Authenticate(s, now); err != nil {
			t.Fatalf("session should work before revocation: %v", err)
		}
	}

	n, err := ts.Revoke(parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 sessions revoked, got %d", n)
	}
	for _, s := range []string{a, b} {
		if _, err := ts.Authenticate(s, now); err == nil {
			t.Error("a session outlived the revocation of its parent")
		}
	}
}
