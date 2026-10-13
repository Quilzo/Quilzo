// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package actioncache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/vault"
)

func page(from, body string) agent.Observation {
	return agent.Observation{From: from, Body: body}
}

// A flow that worked is remembered against the page it started on, and
// replayed without the model; the page that follows is what it was
// remembered to be, so the flow goes on from memory too.
func TestAFlowThatWorkedIsReplayedWithoutTheModel(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	model := countingDecider([]agent.Action{
		{Op: "browser_click", Input: map[string]any{"ref": "e3"}},
		{Op: "browser_read"},
	})
	d := Wrap(model.decide, s, "buyer", "dana", nil, nil)
	goal := "buy paper"
	home := page("browser_open", "the shop front, [e3] button \"Buy\"")

	// First run: the model decides both steps, and both are recorded.
	a, err := d(context.Background(), goal, []agent.Observation{home})
	if err != nil || a.Op != "browser_click" {
		t.Fatalf("%+v %v", a, err)
	}
	list := page("browser_click", "the cart, [e7] link \"Checkout\"")
	a, err = d(context.Background(), goal, []agent.Observation{home, list})
	if err != nil || a.Op != "browser_read" {
		t.Fatalf("%+v %v", a, err)
	}
	done := page("browser_read", "the cart, [e7] link \"Checkout\"")
	_, _ = d(context.Background(), goal, []agent.Observation{home, list, done})
	if model.calls != 2 {
		t.Fatalf("the model was called %d times for a two-step flow", model.calls)
	}

	// Second run, same goal, same first page: both steps come from the
	// cache and the model is not asked at all.
	fresh := countingDecider(nil)
	d = Wrap(fresh.decide, s, "buyer", "dana", nil, nil)
	if a, err = d(context.Background(), goal, []agent.Observation{home}); err != nil || a.Op != "browser_click" || a.Input["ref"] != "e3" {
		t.Fatalf("the replay did not give the remembered click: %+v %v", a, err)
	}
	if a, err = d(context.Background(), goal, []agent.Observation{home, list}); err != nil || a.Op != "browser_read" {
		t.Fatalf("the flow did not continue from memory: %+v %v", a, err)
	}
	if fresh.calls != 0 {
		t.Errorf("the model was asked %d times on a remembered flow", fresh.calls)
	}
}

// A replay whose page is not the one remembered falls back to the model:
// the cache confirms itself, or it is nothing.
func TestAReplayThatDoesNotLandFallsBackToTheModel(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	model := countingDecider([]agent.Action{{Op: "browser_click", Input: map[string]any{"ref": "e3"}}})
	d := Wrap(model.decide, s, "buyer", "dana", nil, nil)
	home := page("browser_open", "the shop front")
	_, _ = d(context.Background(), "buy", []agent.Observation{home})
	list := page("browser_click", "the cart")
	_, _ = d(context.Background(), "buy", []agent.Observation{home, list})

	// Same first page, but the click lands somewhere new.
	fresh := countingDecider([]agent.Action{{Op: "browser_read"}})
	var events []Event
	d = Wrap(fresh.decide, s, "buyer", "dana", func(e Event) { events = append(events, e) }, nil)
	if a, err := d(context.Background(), "buy", []agent.Observation{home}); err != nil || a.Op != "browser_click" {
		t.Fatalf("the replay did not come first: %+v %v", a, err)
	}
	moved := page("browser_click", "a page the flow has never seen")
	a, err := d(context.Background(), "buy", []agent.Observation{home, moved})
	if err != nil || a.Op != "browser_read" || fresh.calls != 1 {
		t.Fatalf("the model was not asked after the page changed: %+v %v calls=%d", a, err, fresh.calls)
	}
	fellBack := false
	for _, e := range events {
		fellBack = fellBack || e.FellBack
	}
	if !fellBack {
		t.Error("the fallback was not noted")
	}
	// And the stale entry is gone: the next run on the same page asks the
	// model, not the memory.
	again := countingDecider([]agent.Action{{Op: "browser_read"}})
	d = Wrap(again.decide, s, "buyer", "dana", nil, nil)
	if a, err := d(context.Background(), "buy", []agent.Observation{home}); err != nil || a.Op != "browser_read" || again.calls != 1 {
		t.Fatalf("a dropped entry was replayed: %+v %v calls=%d", a, err, again.calls)
	}
}

// A replay that is refused — by the gate or by a person — drops its
// entry, because replaying it again next turn is a loop with a model
// nowhere in it.
func TestARefusedReplayIsDroppedNotLooped(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	model := countingDecider([]agent.Action{{Op: "browser_click", Input: map[string]any{"ref": "e3"}}})
	d := Wrap(model.decide, s, "buyer", "dana", nil, nil)
	home := page("browser_open", "the shop front")
	_, _ = d(context.Background(), "buy", []agent.Observation{home})
	_, _ = d(context.Background(), "buy", []agent.Observation{home, page("browser_click", "the cart")})

	fresh := countingDecider([]agent.Action{{Op: "browser_read"}})
	d = Wrap(fresh.decide, s, "buyer", "dana", nil, nil)
	if a, err := d(context.Background(), "buy", []agent.Observation{home}); err != nil || a.Op != "browser_click" {
		t.Fatalf("%+v %v", a, err)
	}
	refused := agent.Observation{From: "quilzo", Body: "refused: a person declined", Trusted: true}
	a, err := d(context.Background(), "buy", []agent.Observation{home, refused})
	if err != nil || a.Op != "browser_read" || fresh.calls != 1 {
		t.Fatalf("the refusal looped back to the memory: %+v %v calls=%d", a, err, fresh.calls)
	}
}

// Signing in is never remembered: a flow that includes a credential is
// decided each time, in front of the person who owns it.
func TestSigningInIsNeverRemembered(t *testing.T) {
	if Caches("browser_sign_in") {
		t.Error("browser_sign_in is cached")
	}
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	model := countingDecider([]agent.Action{{Op: "browser_sign_in", Input: map[string]any{"credential": "shop"}}})
	d := Wrap(model.decide, s, "buyer", "dana", nil, nil)
	home := page("browser_open", "the sign-in page")
	_, _ = d(context.Background(), "buy", []agent.Observation{home})
	_, _ = d(context.Background(), "buy", []agent.Observation{home, page("browser_sign_in", "signed in")})

	fresh := countingDecider([]agent.Action{{Op: "browser_read"}})
	d = Wrap(fresh.decide, s, "buyer", "dana", nil, nil)
	if a, err := d(context.Background(), "buy", []agent.Observation{home}); err != nil || a.Op != "browser_read" || fresh.calls != 1 {
		t.Fatalf("a sign-in was replayed from memory: %+v %v", a, err)
	}
}

// Only browser observations key a decision: a run that has not opened a
// page has nothing to remember against, and nothing a page said is taken
// as this program's own words.
func TestKeysComeFromThePageAndNothingElse(t *testing.T) {
	if Key("buyer", "dana", "buy", nil) != "" {
		t.Error("no observations at all made a key")
	}
	if Key("buyer", "dana", "buy", []agent.Observation{page("read_page", "a draft")}) != "" {
		t.Error("a store observation keyed a decision")
	}
	if Key("buyer", "dana", "buy", []agent.Observation{{From: "quilzo", Body: "refused", Trusted: true}}) != "" {
		t.Error("this program's own words keyed a decision")
	}
	if Key("buyer", "dana", "buy", []agent.Observation{page("browser_open", "a page")}) == "" {
		t.Error("a page did not key a decision")
	}
	a := Key("buyer", "dana", "buy", []agent.Observation{page("browser_open", "a page")})
	b := Key("buyer", "dana", "sell", []agent.Observation{page("browser_open", "a page")})
	c := Key("buyer", "dana", "buy", []agent.Observation{page("browser_open", "another page")})
	if a == b || b == c || a == c {
		t.Error("different goals and pages made one key")
	}
}

// The inputs a cache holds — text a model once typed into a page — are
// sealed when there is a keyring, and the index beside them carries only
// digests. Without the key they cannot be read, and a cache that cannot
// be read replays nothing.
func TestInputsAreSealedAndUnreadableWithoutTheKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	kr, err := vault.NewKeyring("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := Open(path, "buyer", kr)
	s.Record("k1", agent.Action{Op: "browser_type", Input: map[string]any{"ref": "e2", "text": "hunter2"}}, "after")

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Error("a typed secret sits in the clear index")
	}
	var file map[string]any
	if json.Unmarshal(b, &file) != nil {
		t.Fatal(err)
	}
	if _, clear := nestedKey(file, "inputs", "clear"); clear {
		t.Error("the inputs were written unsealed beside a keyring")
	}

	// With the key: the flow replays.
	s2, _ := Open(path, "buyer", kr)
	if a, _, ok := s2.Lookup("k1"); !ok || a.Input["text"] != "hunter2" {
		t.Fatalf("the sealed inputs did not come back: %+v %v", a, ok)
	}
	// Without it: nothing replays, and the model decides.
	s3, _ := Open(path, "buyer", nil)
	if _, _, ok := s3.Lookup("k1"); ok {
		t.Error("a sealed cache replayed without its key")
	}
}

// A cache is bounded: an agent that has remembered more than its share
// forgets the least recently used, not the flow it is standing on.
func TestACacheIsBounded(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	for i := 0; i < MaxEntries+10; i++ {
		s.Record("k"+strings.Repeat("a", i+1), agent.Action{Op: "browser_read"}, "")
	}
	if len(s.index) > MaxEntries {
		t.Fatalf("%d entries for one agent", len(s.index))
	}
}

func nestedKey(m map[string]any, a, b string) (any, bool) {
	x, ok := m[a].(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := x[b]
	return v, ok
}

type counting struct {
	actions []agent.Action
	calls   int
	decide  agent.Decide
}

func countingDecider(actions []agent.Action) *counting {
	c := &counting{actions: actions}
	c.decide = func(context.Context, string, []agent.Observation) (agent.Action, error) {
		if c.calls >= len(c.actions) {
			return agent.Action{}, errors.New("the model was asked beyond its script")
		}
		a := c.actions[c.calls]
		c.calls++
		return a, nil
	}
	return c
}

func open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, "buyer", nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A replay answers from memory without asking the decider, and whatever
// the decider was holding over from its last answer — a dialect's open
// batch — is forgotten: a remembered step belongs to no batch anybody is
// still working through.
func TestAReplayForgetsWhatTheDeciderWasHoldingOver(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	model := countingDecider([]agent.Action{{Op: "browser_click", Input: map[string]any{"ref": "e3"}}})
	d := Wrap(model.decide, s, "buyer", "dana", nil, nil)
	home := page("browser_open", "the shop front")
	_, _ = d(context.Background(), "buy", []agent.Observation{home})
	_, _ = d(context.Background(), "buy", []agent.Observation{home, page("browser_click", "the cart")})

	held := "stale batch"
	fresh := countingDecider(nil)
	d = Wrap(fresh.decide, s, "buyer", "dana", nil, func() { held = "forgotten" })
	if a, err := d(context.Background(), "buy", []agent.Observation{home}); err != nil || a.Op != "browser_click" {
		t.Fatalf("the replay did not come first: %+v %v", a, err)
	}
	if held != "forgotten" {
		t.Error("a replay left the decider's batch standing")
	}
}

// A look leaves a placeholder that names a page by address alone; keying
// on it would share one memory between two states of one address.
func TestALookDoesNotKeyAMemory(t *testing.T) {
	seen := []agent.Observation{
		page("browser_open", "the outline of the page"),
		{From: "browser_look", Body: "a screenshot of https://shop.example.com/ is with this message"},
	}
	if key := Key("buyer", "dana", "buy", seen); key == "" {
		t.Fatal("no key at all was made")
	}
	two := []agent.Observation{
		page("browser_open", "the outline of the page"),
		{From: "browser_look", Body: "a screenshot of https://shop.example.com/ is with this message"},
		page("browser_read", "the outline, differently laid out now"),
	}
	one := []agent.Observation{
		page("browser_open", "the outline of the page"),
		{From: "browser_look", Body: "a screenshot of https://shop.example.com/ is with this message"},
		page("browser_read", "the outline, as it first was"),
	}
	if Key("buyer", "dana", "buy", one) == Key("buyer", "dana", "buy", two) {
		t.Error("two states of one address shared a key through a look's placeholder")
	}
}

// What a run typed is the person's it ran for: the same goal on the same
// form, run for somebody else, is decided afresh and never types the first
// person's words.
func TestOnePersonsFlowIsNotReplayedForAnother(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "cache.json"))
	form := page("browser_open", "the delivery form, [e2] textbox \"Address\"")
	typed := agent.Action{Op: "browser_type", Input: map[string]any{"ref": "e2", "text": "12 Elm Street"}}
	d := Wrap(countingDecider([]agent.Action{typed}).decide, s, "buyer", "dana", nil, nil)
	if _, err := d(context.Background(), "fill in my address", []agent.Observation{form}); err != nil {
		t.Fatal(err)
	}
	after := page("browser_type", "the delivery form, [e2] textbox \"Address\" 12 Elm Street")
	_, _ = d(context.Background(), "fill in my address", []agent.Observation{form, after})

	other := countingDecider([]agent.Action{{Op: "browser_read"}})
	d = Wrap(other.decide, s, "buyer", "sam", nil, nil)
	a, err := d(context.Background(), "fill in my address", []agent.Observation{form})
	if err != nil {
		t.Fatal(err)
	}
	if a.Op == "browser_type" || other.calls != 1 {
		t.Fatalf("another person's run replayed what was typed for dana: %+v", a)
	}
}
