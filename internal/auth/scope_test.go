package auth

import (
	"strings"
	"testing"
	"time"
)

// The gap this closes. "Reader on /" is the narrowest thing that could be
// issued before, and it is not narrow: the search indexer that needs English
// articles could read the German legal pages too.
func TestAScopedTokenReachesOnlyWhatItNames(t *testing.T) {
	s := Scope{Types: []string{"article"}, Locales: []string{"en"}, ReadOnly: true}

	if !s.AllowsType("article") {
		t.Error("the type it was issued for is refused")
	}
	if s.AllowsType("legal_notice") {
		t.Error("a type outside the scope is allowed")
	}
	if !s.AllowsLocale("en-GB") {
		t.Error("en-GB is refused by a scope naming en; a token that breaks " +
			"when somebody adds a regional variant gets replaced by an " +
			"unscoped one")
	}
	if s.AllowsLocale("de") {
		t.Error("a locale outside the scope is allowed")
	}
	if s.AllowsAction(ActEditDraft) {
		t.Error("a read-only token was allowed to write")
	}
	if !s.AllowsAction(ActView) {
		t.Error("a read-only token was refused a read")
	}
}

// An empty dimension means unrestricted, and getting this backwards would
// produce tokens that reach nothing while looking correct.
func TestAnEmptyScopeRestrictsNothing(t *testing.T) {
	var s Scope
	if !s.Empty() {
		t.Error("the zero scope is not empty")
	}
	for _, name := range []string{"article", "anything", ""} {
		if !s.AllowsType(name) {
			t.Errorf("the zero scope refused type %q", name)
		}
	}
	if !s.AllowsAction(ActPublish) {
		t.Error("the zero scope refused a write")
	}
}

// A page with no type bound to it is not a page of some secret type. Refusing
// those would mean a scoped token cannot read an untyped store at all, which
// is most of them.
func TestAnUntypedPageIsNotHiddenByATypeScope(t *testing.T) {
	s := Scope{Types: []string{"article"}}
	if !s.AllowsType("") {
		t.Error("a page with no type was hidden from a type-scoped token")
	}
}

// -- the safety property ------------------------------------------------------

// A scope only ever narrows. It is intersected with what the policy allows,
// never unioned — so a token issued by somebody who has misunderstood this can
// be too narrow and annoying, never too wide and dangerous.
func TestNarrowingOnlyEverNarrows(t *testing.T) {
	parent := Scope{Types: []string{"article", "page"}, Locales: []string{"en", "de"}}

	// A child asking for less gets less.
	child := parent.Narrow(Scope{Types: []string{"article"}})
	if child.AllowsType("page") {
		t.Error("narrowing to article still permits page")
	}

	// A child asking for MORE does not get it.
	wider := parent.Narrow(Scope{Types: []string{"secret_type"}})
	if wider.AllowsType("secret_type") {
		t.Error("a child asked for a type the parent does not have and got it")
	}
	if wider.AllowsType("article") {
		t.Error("the intersection is empty and should reach nothing")
	}

	// Read-only is sticky: a child of a read-only parent cannot write.
	ro := Scope{ReadOnly: true}.Narrow(Scope{ReadOnly: false})
	if !ro.ReadOnly {
		t.Error("a child cleared the parent's read-only flag")
	}
}

// The empty intersection is the case that goes wrong if written naively: an
// empty slice reads as "no restriction", so a child asking for something the
// parent does not have would end up unrestricted — the one direction this must
// never go.
func TestAnEmptyIntersectionReachesNothingRatherThanEverything(t *testing.T) {
	got := Scope{Types: []string{"a"}}.Narrow(Scope{Types: []string{"b"}})
	if len(got.Types) == 0 {
		t.Fatal("the intersection came out empty, which reads as unrestricted")
	}
	for _, name := range []string{"a", "b", "c", ""} {
		if name == "" {
			continue // untyped pages are deliberately always allowed
		}
		if got.AllowsType(name) {
			t.Errorf("a token with no overlapping types still reaches %q", name)
		}
	}
}

// A read-only scope must refuse an action it has never heard of, or the scope
// widens every time somebody adds one.
func TestReadOnlyRefusesUnknownActions(t *testing.T) {
	if (Scope{ReadOnly: true}).AllowsAction(Action("some-action-added-later")) {
		t.Error("a read-only token permitted an unknown action; the scope " +
			"would widen every time an action is added")
	}
}

// -- issuing ------------------------------------------------------------------

func TestAScopedTokenSurvivesIssuing(t *testing.T) {
	ts := &TokenStore{}
	want := Scope{Types: []string{"article"}, Locales: []string{"en"}, ReadOnly: true}
	_, tok, err := ts.IssueScoped("indexer", "search", RoleReader, "/",
		time.Hour, RoleAdmin, want)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Scope.String() != want.String() {
		t.Errorf("issued with scope %q, want %q", tok.Scope, want)
	}
	if !tok.Scope.ReadOnly {
		t.Error("the read-only flag was lost")
	}
}

// Every token issued before scoping existed has the zero value, which has to
// keep meaning "unrestricted" — otherwise the upgrade silently breaks every
// credential in the store.
func TestAnUnscopedTokenIsUnrestricted(t *testing.T) {
	ts := &TokenStore{}
	_, tok, err := ts.Issue("cli", "dana", RoleAdmin, "/", time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Scope.Empty() {
		t.Fatal("Issue produced a restricted token")
	}
	if !tok.Scope.AllowsType("anything") || !tok.Scope.AllowsAction(ActPublish) {
		t.Error("an unscoped token is restricted, which would break every " +
			"credential issued before this feature existed")
	}
}

// * is refused rather than treated as a wildcard. Somebody who writes it means
// "all" and would otherwise get a token scoped to a type literally called *,
// which matches nothing and fails closed in a way that looks like a bug.
func TestAWildcardIsRefusedRatherThanMisunderstood(t *testing.T) {
	for _, s := range []Scope{
		{Types: []string{"*"}}, {Locales: []string{"*"}}, {Types: []string{" "}},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%v was accepted", s)
		}
	}
}

// A refusal has to say which of five dimensions stopped the caller.
func TestARefusalNamesTheDimensionThatCausedIt(t *testing.T) {
	s := Scope{Types: []string{"article"}, Locales: []string{"en"}, ReadOnly: true}
	if why := s.Why(ActEditDraft, "article", "en"); !strings.Contains(why, "read-only") {
		t.Errorf("a write refusal says %q", why)
	}
	if why := s.Why(ActView, "legal", "en"); !strings.Contains(why, "legal") {
		t.Errorf("a type refusal says %q", why)
	}
	if why := s.Why(ActView, "article", "de"); !strings.Contains(why, "de") {
		t.Errorf("a locale refusal says %q", why)
	}
	if why := s.Why(ActView, "article", "en"); why != "" {
		t.Errorf("an allowed call was explained as a refusal: %q", why)
	}
}

// -- ownership, and why it is not a role --------------------------------------

// Every CMS vocabulary has a contributor: somebody who writes drafts and
// cannot publish. Mapping it onto a role ladder gets it wrong, because the
// distinction is not *less power*. A contributor does exactly what an author
// does; they do it to a smaller set of pages.
//
// So it is a constraint that composes with every role rather than a rung that
// composes with none.
func TestOwnOnlyComposesWithAnyRole(t *testing.T) {
	for _, role := range []Role{RoleAuthor, RolePublisher, RoleAdmin} {
		p := &Policy{}
		if err := p.Grant(Binding{
			Principal: "sam", Role: role, Resource: "/", OwnOnly: true,
		}); err != nil {
			t.Fatal(err)
		}
		// Their own page: allowed, at whatever the role permits.
		if d := p.EvaluateOwned("sam", ActEditDraft, "/mine", "sam"); !d.Allowed {
			t.Errorf("%s own-only could not edit their own page: %s",
				role, d.Reason)
		}
		// Somebody else's: refused, however senior.
		if d := p.EvaluateOwned("sam", ActEditDraft, "/theirs", "dana"); d.Allowed {
			t.Errorf("%s own-only edited a page created by dana", role)
		}
	}
}

// Reads are not restricted by ownership. An editorial team where people cannot
// read each other's drafts is not a team.
func TestOwnOnlyDoesNotRestrictReading(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/",
		OwnOnly: true})
	if d := p.EvaluateOwned("sam", ActView, "/theirs", "dana"); !d.Allowed {
		t.Errorf("an own-only contributor cannot read a colleague's draft: %s",
			d.Reason)
	}
}

// Content whose creator was never recorded is content an own-only principal
// has no claim to. Treating unknown as "yours" would make every unattributed
// page editable by everybody holding an own-only grant.
func TestUnknownOwnershipFailsClosed(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/",
		OwnOnly: true})
	d := p.EvaluateOwned("sam", ActEditDraft, "/orphan", "")
	if d.Allowed {
		t.Fatal("a page with no recorded creator was editable by an " +
			"own-only principal")
	}
	if !strings.Contains(d.Reason, "records") {
		t.Errorf("the refusal does not explain itself: %s", d.Reason)
	}
}

// An ordinary binding is unaffected, so this cannot have changed anybody's
// existing access.
func TestABindingWithoutOwnOnlyIsUnchanged(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "dana", Role: RoleAuthor, Resource: "/"})
	for _, creator := range []string{"dana", "someone-else", ""} {
		if d := p.EvaluateOwned("dana", ActEditDraft, "/x", creator); !d.Allowed {
			t.Errorf("an ordinary author was refused a page created by %q: %s",
				creator, d.Reason)
		}
	}
	if d := p.Evaluate("dana", ActEditDraft, "/x"); d.OwnsRequired {
		t.Error("an ordinary binding reported that ownership matters")
	}
}

// A caller using the plain Evaluate gets the old behaviour and a flag, rather
// than a wrong refusal. The flag is what makes the omission findable.
func TestPlainEvaluateReportsThatOwnershipMatters(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/",
		OwnOnly: true})
	d := p.Evaluate("sam", ActEditDraft, "/anything")
	if !d.Allowed {
		t.Fatal("plain Evaluate refused, which would break callers that " +
			"have not been updated")
	}
	if !d.OwnsRequired {
		t.Error("plain Evaluate did not report that ownership must be checked")
	}
}

// The refusal names who does own it, because "not permitted" leaves somebody
// unable to tell a mistake from a policy.
func TestTheRefusalNamesTheOwner(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/",
		OwnOnly: true})
	d := p.EvaluateOwned("sam", ActEditDraft, "/theirs", "dana")
	if !strings.Contains(d.Reason, "dana") {
		t.Errorf("the refusal does not say who owns it: %s", d.Reason)
	}
}

// Own-only stacks with the resource path rather than replacing it: a
// contributor scoped to /blog cannot reach /legal even for a page they wrote.
func TestOwnOnlyStacksWithTheResourcePath(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/blog",
		OwnOnly: true})
	if d := p.EvaluateOwned("sam", ActEditDraft, "/blog/post", "sam"); !d.Allowed {
		t.Errorf("refused inside their own scope: %s", d.Reason)
	}
	if d := p.EvaluateOwned("sam", ActEditDraft, "/legal/terms", "sam"); d.Allowed {
		t.Error("an own-only binding on /blog reached /legal")
	}
}
