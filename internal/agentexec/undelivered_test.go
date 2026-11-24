// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentexec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/mcpclient"
)

// keyspy remembers the idempotency key each call was made with.
type keyspy struct {
	keys []string
	err  error
}

func (k *keyspy) Call(ctx context.Context, _ agent.Integration, _ string, _ map[string]any) (string, error) {
	key, _ := mcpclient.IdempotencyKeyOf(ctx)
	k.keys = append(k.keys, key)
	return "done", k.err
}

// A step's call is named by its run and step: the same step asked again
// carries the same key, another step another. One that fails is kept, with
// its key, for a person to settle; one that was cancelled is not.
func TestAStepsWriteIsNamedAndKeptWhenItFails(t *testing.T) {
	spy := &keyspy{err: errors.New("crm answered 503")}
	var kept []Undelivered
	tl := Tools{Installed: installed("api.example.com"), Call: spy, Undelivered: func(u Undelivered) { kept = append(kept, u) }}
	s := agent.NewSession(toolAgent(), nil)
	act := agent.Action{Tool: "lookup", Input: map[string]any{"q": "acme"}}
	for _, n := range []int{3, 3, 4} {
		_, _ = tl.Perform(s)(agent.WithStep(context.Background(), "run-1", n), act)
	}
	if len(spy.keys) != 3 || spy.keys[0] == "" || spy.keys[0] != spy.keys[1] || spy.keys[1] == spy.keys[2] {
		t.Fatalf("%v", spy.keys)
	}
	if len(kept) != 3 || kept[0].Run != "run-1" || kept[0].Step != 3 || kept[0].Key != spy.keys[0] ||
		kept[0].Integration != "crm" || kept[0].Tool != "lookup" || kept[0].Agent != "errands" {
		t.Fatalf("%+v", kept)
	}
	// Not named by a run: no key, and still kept when it fails.
	_, _ = tl.Perform(s)(context.Background(), act)
	if spy.keys[3] != "" || len(kept) != 4 {
		t.Fatalf("%v %d", spy.keys, len(kept))
	}
	// Cancelled: the run stopped, nothing failed.
	ctx, cancel := context.WithCancel(agent.WithStep(context.Background(), "run-1", 5))
	cancel()
	_, _ = tl.Perform(s)(ctx, act)
	if len(kept) != 4 {
		t.Fatal("a cancelled call was kept as undelivered")
	}
	spy.err = nil
	_, _ = tl.Perform(s)(agent.WithStep(context.Background(), "run-1", 6), act)
	if len(kept) != 4 {
		t.Fatal("a call that got through was kept")
	}
}

// Why a write did not get through is cut where a character starts. A person
// reads it to decide whether to send the write again, and an integration's
// error in its own language would otherwise end in U+FFFD on that screen.
func TestAnUndeliveredWritesLongErrorIsCutBetweenCharacters(t *testing.T) {
	// Two errors a byte apart, because what is said around the error is not
	// this test's to know: wherever the bound falls, it is inside a
	// character in one of them.
	for _, said := range []string{strings.Repeat("中", 200), "a" + strings.Repeat("中", 200)} {
		var kept []Undelivered
		tl := Tools{Installed: installed("api.example.com"), Call: &keyspy{err: errors.New(said)},
			Undelivered: func(u Undelivered) { kept = append(kept, u) }}
		s := agent.NewSession(toolAgent(), nil)
		_, _ = tl.Perform(s)(context.Background(), agent.Action{Tool: "lookup", Input: map[string]any{"q": "acme"}})
		if len(kept) != 1 {
			t.Fatalf("%d kept", len(kept))
		}
		if e := kept[0].Error; len(e) > 300 || !utf8.ValidString(e) {
			t.Fatalf("%d bytes, ending %q", len(e), e[len(e)-3:])
		}
	}
}
