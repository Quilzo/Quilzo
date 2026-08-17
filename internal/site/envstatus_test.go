package site

import (
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// Adding staging to a site that is already published.
//
// The first thing anybody does with environments, and it broke both surfaces
// that show them. Status walks the sequence comparing each environment to the
// one before it, and the branch for "the one before holds nothing" existed only
// for an environment that was itself empty. Production — which has a commit —
// fell through to a Diff against an empty string, which is not an object id,
// and the error took the whole listing with it.
//
// So `scrivet env list` and the publishing screen both stopped working at the
// exact moment the feature started being used.
func TestAnEnvironmentInsertedBeforeALiveOneDoesNotBreakTheListing(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	// Staging, inserted before production, and never promoted to.
	envs := DefaultEnvs()
	envs.Environments = append(envs.Environments, Env{
		Name: "staging", Ref: "env-staging", Order: 50,
	})

	states, err := Status(s, envs)
	if err != nil {
		t.Fatalf("listing environments failed: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("got %d environments, want 2", len(states))
	}

	staging, production := states[0], states[1]
	if staging.Env.Name != "staging" || production.Env.Name != "production" {
		t.Fatalf("wrong order: %s then %s", staging.Env.Name, production.Env.Name)
	}
	if !staging.Empty {
		t.Error("staging has never been promoted to and is not reported empty")
	}
	if production.Empty {
		t.Error("production holds the published commit and is reported empty")
	}
	// Not behind anything. Production is ahead of staging here, and reporting
	// "1 change waiting" would tell somebody to promote content backwards.
	if production.Pending != 0 {
		t.Errorf("production reports %d change(s) waiting on an empty staging",
			production.Pending)
	}
}
