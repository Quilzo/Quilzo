package auth

import (
	"fmt"
	"sort"
	"strings"
)

// A token's scope narrows what a credential may reach, beneath everything the
// policy already grants its principal.
//
// The existing controls answer "who are you" and "where in the tree". Neither
// answers the question an integration actually raises: the search indexer needs
// to read articles, in English, and nothing else. Handed a reader token it can
// read the unpublished legal pages, the German translations, and every content
// type in the store — because "reader on /" is the narrowest thing that could
// be issued, and it is not narrow.
//
// So a scope adds three dimensions to the two that exist:
//
//	role      what may be done          (already)
//	resource  where in the path tree    (already)
//	types     which content types       (new)
//	locales   which languages           (new)
//	readonly  writes refused outright   (new)
//
// Every dimension is an allow-list, empty meaning unrestricted, and every one
// only ever narrows. A scope cannot grant anything: it is intersected with the
// policy's answer, never unioned. That direction is the whole safety property
// — a token issued by somebody who has misunderstood this can be too narrow
// and annoying, never too wide and dangerous.
type Scope struct {
	// Types are content type names this token may touch. Empty means all.
	Types []string `json:"types,omitempty"`
	// Locales are language tags this token may touch. Empty means all.
	//
	// Matched on the language subtag as well as the full tag, so a token
	// scoped to "en" reaches en-GB and en-US. Requiring every regional variant
	// to be listed would produce tokens that break the first time somebody
	// adds a locale, and people respond to that by scoping to nothing.
	Locales []string `json:"locales,omitempty"`
	// ReadOnly refuses every write regardless of role.
	//
	// Separate from the role rather than folded into it, because the two
	// answer different questions. A publisher who wants a read-only token for
	// a dashboard should not have to pretend to be a reader — the token still
	// says who it acts for, and revoking it still cascades correctly.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Empty reports whether the scope restricts nothing.
func (s Scope) Empty() bool {
	return len(s.Types) == 0 && len(s.Locales) == 0 && !s.ReadOnly
}

// String renders a scope for display and for the audit record.
func (s Scope) String() string {
	if s.Empty() {
		return "unrestricted"
	}
	var parts []string
	if s.ReadOnly {
		parts = append(parts, "read-only")
	}
	if len(s.Types) > 0 {
		parts = append(parts, "types "+strings.Join(s.Types, "|"))
	}
	if len(s.Locales) > 0 {
		parts = append(parts, "locales "+strings.Join(s.Locales, "|"))
	}
	return strings.Join(parts, ", ")
}

// Validate refuses a scope that cannot mean what it appears to.
func (s Scope) Validate() error {
	for _, t := range s.Types {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("a content type in the scope is blank")
		}
		if t == "*" {
			// Refused rather than treated as "everything", because a caller
			// who writes * means "all" and would get a token scoped to a type
			// literally named "*", which matches nothing and fails closed in a
			// way that looks like the feature is broken.
			return fmt.Errorf(
				"* is not a wildcard here; leave --types off to mean every type")
		}
	}
	for _, l := range s.Locales {
		if strings.TrimSpace(l) == "" {
			return fmt.Errorf("a locale in the scope is blank")
		}
		if l == "*" {
			return fmt.Errorf(
				"* is not a wildcard here; leave --locales off to mean every locale")
		}
	}
	return nil
}

// Narrow returns a scope that is this one further restricted by another.
//
// Used when a token is exchanged for a session: the child can be narrower than
// the parent and can never be wider. An empty list on either side means "no
// restriction from that side", so intersecting has to treat it as the identity
// rather than as the empty set — the natural implementation of intersection
// gets that exactly backwards and produces a token that reaches nothing.
func (s Scope) Narrow(by Scope) Scope {
	out := Scope{ReadOnly: s.ReadOnly || by.ReadOnly}
	out.Types = intersect(s.Types, by.Types)
	out.Locales = intersect(s.Locales, by.Locales)
	return out
}

func intersect(a, b []string) []string {
	switch {
	case len(a) == 0:
		return append([]string(nil), b...)
	case len(b) == 0:
		return append([]string(nil), a...)
	}
	have := map[string]bool{}
	for _, v := range a {
		have[v] = true
	}
	var out []string
	for _, v := range b {
		if have[v] {
			out = append(out, v)
		}
	}
	if out == nil {
		// The intersection is genuinely empty: the child asked for something
		// the parent does not have. Represented by a value that matches
		// nothing rather than by an empty slice, which would read as "no
		// restriction" and silently widen the token — the one direction this
		// must never go.
		out = []string{nothing}
	}
	sort.Strings(out)
	return out
}

// nothing is a type and locale name that cannot exist, used to represent an
// empty intersection. Content type names are lowercase letters, digits and
// underscores, so a space and a slash are both unusable.
const nothing = "\x00 no overlap"

// AllowsType reports whether the scope permits touching a content type.
//
// The empty name is allowed whatever the scope says. A page with no type bound
// to it is not a page of some secret type — it is a page that predates types
// or was never bound — and refusing those would mean a scoped token cannot
// read an untyped store at all, which is most of them.
func (s Scope) AllowsType(name string) bool {
	if len(s.Types) == 0 || name == "" {
		return true
	}
	for _, t := range s.Types {
		if t == name {
			return true
		}
	}
	return false
}

// AllowsLocale reports whether the scope permits a language tag.
//
// A scope naming "en" reaches en-GB, because a token that breaks the first
// time somebody adds a regional variant is a token people replace with an
// unscoped one.
func (s Scope) AllowsLocale(tag string) bool {
	if len(s.Locales) == 0 || tag == "" {
		return true
	}
	want := strings.ToLower(tag)
	base, _, _ := strings.Cut(want, "-")
	for _, l := range s.Locales {
		have := strings.ToLower(l)
		if have == want || have == base {
			return true
		}
		// And the other direction: a scope naming en-GB does not reach en, or
		// a token for one region would read the source language too.
		if hb, _, _ := strings.Cut(have, "-"); hb == want && have == want {
			return true
		}
	}
	return false
}

// AllowsAction reports whether the scope permits an action at all, before any
// policy is consulted.
func (s Scope) AllowsAction(a Action) bool {
	if !s.ReadOnly {
		return true
	}
	needed, ok := Needs(a)
	if !ok {
		// An action this version does not know about, under a read-only
		// token. Refused: a scope that fails open on the actions it has not
		// heard of is a scope that widens every time one is added.
		return false
	}
	return needed == RoleReader
}

// Why explains a refusal, so a caller sees which dimension stopped them rather
// than a bare "forbidden" that could be any of five things.
func (s Scope) Why(a Action, typeName, locale string) string {
	if !s.AllowsAction(a) {
		return fmt.Sprintf("this token is read-only and %s writes", a)
	}
	if !s.AllowsType(typeName) {
		return fmt.Sprintf(
			"this token is scoped to %s and that page is a %s",
			strings.Join(s.Types, ", "), typeName)
	}
	if !s.AllowsLocale(locale) {
		return fmt.Sprintf(
			"this token is scoped to %s and that page is %s",
			strings.Join(s.Locales, ", "), locale)
	}
	return ""
}

// -- the limits a credential itself carries ----------------------------------

// Covers reports whether a grant or a scope on `scope` reaches `target`.
//
// Exported because three surfaces ask this question and two of them had grown
// their own copy. Segment-aware: "/blog" must not cover "/blog-drafts", and a
// second implementation that got that wrong would be a hole in exactly one
// interface.
func Covers(scope, target string) bool { return covers(scope, target) }

// CheckCredential applies the limits a credential carries, over and above what
// the policy grants the principal holding it.
//
// A token narrows and never widens: its role caps the session, its resource
// caps the subtree, and its scope caps the actions, types and locales. The
// policy answers "may this person do this"; this answers "may they do it with
// the credential in their hand". Both have to hold.
//
// It is one function because it was three, and the three did not agree. The
// command line checked role, path and scope; the content API checked role and
// scope but not path; the browser interface checked scope and nothing else —
// so a token issued `--role reader` to an administrator was refused a publish
// on the command line and could grant somebody admin through the browser. The
// principal really was an administrator, and the credential really was meant
// to be a read-only one; only the CLI was reading the second half.
//
// That is the failure this project keeps having: a control enforced where it
// was written rather than everywhere it is used. So the check is here, in the
// package that owns the model, and each surface calls it rather than
// reimplementing the parts it remembers.
//
// Returns nil when the credential permits the action.
func CheckCredential(role Role, resource string, scope Scope, action Action,
	target string) error {

	need, known := Needs(action)
	if !known {
		// Refused rather than allowed, for the same reason Evaluate refuses:
		// a typo in a caller must not become a permission.
		return fmt.Errorf(
			"unknown action %q; refusing rather than guessing what it needs",
			action)
	}
	if !role.AtLeast(need) {
		return fmt.Errorf(
			"this credential carries %s and %s needs %s. A token limits the "+
				"session even when the principal holds more in general",
			role, action, need)
	}
	if resource != "" && !covers(resource, target) {
		return fmt.Errorf(
			"this credential is scoped to %s and does not reach %s",
			normalise(resource), normalise(target))
	}
	if !scope.AllowsAction(action) {
		return fmt.Errorf("%s", scope.Why(action, "", ""))
	}
	return nil
}
