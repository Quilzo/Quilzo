package site

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

func envs(t *testing.T) *Envs {
	t.Helper()
	e := &Envs{Environments: []Env{
		{Name: "staging", Ref: "env-staging", Order: 10,
			Description: "where it is checked"},
		{Name: "production", Ref: RefLive, Order: 100, Production: true},
	}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	return e
}

// The property that makes this worth doing at all. Elsewhere staging and
// production are separate databases with a copy job between them, and "it
// worked in staging" is a hope. Here promotion is a pointer moving to an
// object that already exists.
func TestProductionEndsUpWithTheExactBytesStagingHad(t *testing.T) {
	s := newStore(t)
	e := envs(t)

	if _, err := SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About"),
	}, "first", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(s, e, "draft", "staging", false); err != nil {
		t.Fatal(err)
	}
	staged := s.GetRef("env-staging")

	// Work continues on the draft while staging is being checked, which is
	// the case the copy-job design gets wrong.
	if _, err := SaveDraft(s, map[string]any{
		"index": page("Home, rewritten"),
	}, "later work", "dana"); err != nil {
		t.Fatal(err)
	}

	p, err := Promote(s, e, "staging", "production", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Commit != staged {
		t.Fatalf("production got %s, staging had %s", p.Commit, staged)
	}
	if got := s.GetRef(RefLive); got != staged {
		t.Errorf("live is %s, staging was %s — the later draft leaked into "+
			"production", got, staged)
	}

	// And the content is the content that was checked, not merely equivalent.
	live, err := PagesAt(s, s.GetRef(RefLive))
	if err != nil {
		t.Fatal(err)
	}
	title, _ := live["index"].(map[string]any)["title"].(string)
	if title != "Home" {
		t.Errorf("production is serving %q, which is not what was staged", title)
	}
}

// Promoting twice is a normal thing for a pipeline to do.
func TestPromotingTwiceIsIdempotent(t *testing.T) {
	s := newStore(t)
	e := envs(t)
	SaveDraft(s, map[string]any{"index": page("Home")}, "first", "dana")
	Promote(s, e, "draft", "staging", false)

	first, err := Promote(s, e, "staging", "production", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Promote(s, e, "staging", "production", false)
	if err != nil {
		t.Fatalf("the second promotion failed: %v", err)
	}
	if !second.Identical {
		t.Error("promoting the same commit twice was not reported as a no-op")
	}
	if second.Commit != first.Commit {
		t.Error("the second promotion moved something")
	}
}

// An environment sequence exists so that things pass through it, and a
// pipeline that can silently skip staging is one that eventually does.
func TestSkippingAnEnvironmentMustBeAskedFor(t *testing.T) {
	s := newStore(t)
	e := envs(t)
	SaveDraft(s, map[string]any{"index": page("Home")}, "first", "dana")

	_, err := Promote(s, e, "draft", "production", false)
	if err == nil {
		t.Fatal("a draft went straight to production with no objection")
	}
	if !strings.Contains(err.Error(), "skip") {
		t.Errorf("the refusal does not say how to proceed: %v", err)
	}

	if _, err := Promote(s, e, "draft", "production", true); err != nil {
		t.Fatalf("--skip did not work: %v", err)
	}
}

// Promoting backwards is how a production commit ends up in staging and
// everybody's model of which is ahead stops being true.
func TestPromotingBackwardsIsRefused(t *testing.T) {
	s := newStore(t)
	e := envs(t)
	SaveDraft(s, map[string]any{"index": page("Home")}, "first", "dana")
	Promote(s, e, "draft", "staging", false)
	Promote(s, e, "staging", "production", false)

	if _, err := Promote(s, e, "production", "staging", true); err == nil {
		t.Error("production was promoted back into staging")
	}
}

// -- the status question ------------------------------------------------------

// What somebody actually asks: what is waiting to go out, and where.
func TestStatusSaysWhatIsWaiting(t *testing.T) {
	s := newStore(t)
	e := envs(t)
	SaveDraft(s, map[string]any{"index": page("Home"), "about": page("About")},
		"first", "dana")

	st, err := Status(s, e)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 {
		t.Fatalf("%d environments reported", len(st))
	}
	if st[0].Env.Name != "staging" {
		t.Errorf("the first is %q; they should be in promotion order",
			st[0].Env.Name)
	}
	if !st[0].Empty || st[0].Pending != 2 {
		t.Errorf("staging should be empty with 2 pending, got %+v", st[0])
	}

	Promote(s, e, "draft", "staging", false)
	st, _ = Status(s, e)
	if !st[0].Same {
		t.Error("staging matches the draft and did not say so")
	}
	if st[1].Pending != 2 {
		t.Errorf("production should have 2 waiting, got %d", st[1].Pending)
	}
}

// -- configuration --------------------------------------------------------

// A store that has never heard of environments must keep working exactly as
// it did, which means the default set names the ref that already exists.
func TestTheDefaultSetIsTheStoreThatAlreadyExists(t *testing.T) {
	d := DefaultEnvs()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	prod := d.Production()
	if prod.Ref != RefLive {
		t.Errorf("the default production ref is %q, not the live ref that "+
			"every existing deployment already uses", prod.Ref)
	}
	if ref, err := d.RefFor("production"); err != nil || ref != RefLive {
		t.Errorf("RefFor(production) = %q, %v", ref, err)
	}
}

func TestAnUnusableEnvironmentSetIsRefused(t *testing.T) {
	for _, tc := range []struct {
		why string
		e   Envs
	}{
		{"no environments", Envs{}},
		{"no production", Envs{Environments: []Env{
			{Name: "staging", Ref: "a", Order: 1}}}},
		{"two productions", Envs{Environments: []Env{
			{Name: "a", Ref: "a", Order: 1, Production: true},
			{Name: "b", Ref: "b", Order: 2, Production: true}}}},
		{"duplicate name", Envs{Environments: []Env{
			{Name: "a", Ref: "x", Order: 1, Production: true},
			{Name: "a", Ref: "y", Order: 2}}}},
		{"shared ref", Envs{Environments: []Env{
			{Name: "a", Ref: "same", Order: 1, Production: true},
			{Name: "b", Ref: "same", Order: 2}}}},
		{"points at the draft", Envs{Environments: []Env{
			{Name: "a", Ref: RefDraft, Order: 1, Production: true}}}},
		{"bad name", Envs{Environments: []Env{
			{Name: "Staging Env!", Ref: "x", Order: 1, Production: true}}}},
	} {
		if err := tc.e.Validate(); err == nil {
			t.Errorf("a set with %s was accepted", tc.why)
		}
	}
}

// An environment pointing at the draft would publish every edit as it is
// typed, so it is named as its own case.
func TestAnEnvironmentCannotPointAtTheDraft(t *testing.T) {
	err := (&Envs{Environments: []Env{
		{Name: "oops", Ref: RefDraft, Order: 1, Production: true},
	}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "work in progress") {
		t.Errorf("got %v", err)
	}
}

// A typo must not resolve to an empty ref and serve an empty site, which
// looks like content loss.
func TestAnUnknownEnvironmentIsRefusedRatherThanTreatedAsARef(t *testing.T) {
	e := envs(t)
	if _, err := e.RefFor("prod"); err == nil {
		t.Error("a near-miss name resolved to something")
	}
	if _, err := e.RefFor("env-staging"); err == nil {
		t.Error("a raw ref name was accepted as an environment")
	}
	if ref, err := e.RefFor("draft"); err != nil || ref != RefDraft {
		t.Errorf("draft should always resolve: %q %v", ref, err)
	}
}

var _ = store.Store{}
