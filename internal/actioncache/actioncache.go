// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package actioncache remembers a browser flow that worked, and replays it
// without a model call.
//
// # What a replay is, and is not
//
// A replay is not trust. A cached action goes through everything a decided
// one does — the session's gate, the breaker, ask-first with a person —
// because the cache sits in front of the decision, not beside the checks.
// What it changes is only who answers: the page asks the same question and
// this answers from memory instead of a model.
//
// # How a memory is kept honest
//
// An entry is keyed by the agent, the goal, and a digest of the page the
// decision was made on; it records the action and a digest of the page
// that followed it. A replay therefore confirms itself: the next page
// either is the one the flow remembers — and the next key is found — or it
// is not, and nothing matches, and the model is asked. No replay is ever
// "probably fine"; it is either exactly what worked or it is nothing. An
// action that fails drops its entry, because what worked once does not
// work now.
//
// The one action never kept is signing in: a flow that includes a
// credential is a flow that must be decided each time, in front of the
// person who owns it.
//
// # Evidence
//
// The inputs a cache holds are text a model once chose to type into a
// page, so they are sealed with the store's keyring like a run's frames,
// and the index beside them carries only digests. Every replay is handed
// to the run's record through Note, so a receipt can say which steps ran
// without a model and against what page.
package actioncache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/vault"
)

// MaxEntries bounds one agent's cache. Flows are short and an agent that
// has accumulated more than this many (page, action) pairs is not
// remembering flows, it is remembering the internet.
const MaxEntries = 128

// Entry is one remembered step of a flow, as it sits in the clear index:
// the action by name, never its inputs — those are sealed — and the page
// that followed it.
type Entry struct {
	// Key is what the decision was made on: the agent, the goal, and the
	// page. Opaque here; made by Key.
	Key string `json:"key"`
	// Op is what worked.
	Op string `json:"op"`
	// After is the digest of the page that followed, which a replay
	// expects to see again.
	After string    `json:"after,omitempty"`
	When  time.Time `json:"when"`
	Hits  int       `json:"hits"`
}

// Store is one agent's cache, on disk beside its runs.
type Store struct {
	mu       sync.Mutex
	path     string
	index    map[string]Entry // by Key, digests only in the clear
	inputs   map[string]map[string]any
	kr       *vault.Keyring
	agentAAD []byte
}

// Open loads a cache, sealed with the keyring when there is one. A file
// that cannot be read is an empty cache: the worst a lost cache does is
// spend model calls.
func Open(path, agent string, kr *vault.Keyring) (*Store, error) {
	s := &Store{path: path, index: map[string]Entry{}, inputs: map[string]map[string]any{},
		kr: kr, agentAAD: []byte("action-cache/v1/" + agent)}
	if b, err := os.ReadFile(path); err == nil {
		var file struct {
			Entries []Entry        `json:"entries"`
			Inputs  map[string]any `json:"inputs,omitempty"`
		}
		if json.Unmarshal(b, &file) == nil {
			for _, e := range file.Entries {
				if len(s.index) < MaxEntries {
					s.index[e.Key] = e
				}
			}
			if file.Inputs != nil {
				if kr != nil {
					if sealed, ok := file.Inputs["sealed"].(map[string]any); ok {
						if raw, err := json.Marshal(sealed); err == nil {
							var sv vault.Sealed
							if json.Unmarshal(raw, &sv) == nil {
								if clear, err := kr.Open(&sv, s.agentAAD); err == nil {
									_ = json.Unmarshal(clear, &s.inputs)
								}
							}
						}
					}
					// Without the keyring the inputs stay sealed, and the
					// cache holds entries it cannot replay: they fail the
					// Lookup below and are recorded afresh.
				} else if plain, ok := file.Inputs["clear"].(map[string]any); ok {
					for k, v := range plain {
						if m, ok := v.(map[string]any); ok {
							s.inputs[k] = m
						}
					}
				}
			}
		}
	}
	return s, nil
}

// Lookup is the action remembered for a key, and the page it expects to
// see after. Nothing is replayed without its inputs: an entry whose inputs
// cannot be read is not an entry.
func (s *Store) Lookup(key string) (agent.Action, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.index[key]
	if !ok || e.Op == "" {
		return agent.Action{}, "", false
	}
	in := s.inputs[key]
	if in == nil && expectsInput(e.Op) {
		// Held without its inputs: an entry that cannot be replayed is not
		// an entry, and the model decides.
		return agent.Action{}, "", false
	}
	e.Hits++
	e.When = time.Now().UTC()
	s.index[key] = e
	return agent.Action{Op: e.Op, Input: in}, e.After, true
}

// expectsInput says whether an op only makes sense carrying something.
func expectsInput(op string) bool {
	switch op {
	case "browser_open", "browser_type", "browser_choose":
		return true
	}
	return false
}

// Record remembers a step that worked, and the page that followed it.
func (s *Store) Record(key string, a agent.Action, after string) {
	if !Caches(a.Op) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, kept := s.index[key]
	if !kept {
		if len(s.index) >= MaxEntries {
			s.evict()
		}
		e = Entry{Key: key, When: time.Now().UTC()}
	}
	e.Op, e.After, e.When = a.Op, after, time.Now().UTC()
	s.index[key] = e
	if a.Input == nil {
		delete(s.inputs, key)
	} else {
		s.inputs[key] = a.Input
	}
	s.write()
}

// Drop forgets a key's entry: what worked once did not work now.
func (s *Store) Drop(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.index[key]; !ok {
		return
	}
	delete(s.index, key)
	delete(s.inputs, key)
	s.write()
}

// evict makes room by forgetting the least recently used entry. The one
// that pays for itself stays longest.
func (s *Store) evict() {
	var oldest string
	var when time.Time
	for k, e := range s.index {
		if oldest == "" || e.When.Before(when) {
			oldest, when = k, e.When
		}
	}
	if oldest != "" {
		delete(s.index, oldest)
		delete(s.inputs, oldest)
	}
}

// write puts the cache on disk: an index of digests in the clear, and the
// inputs — text a model once typed into a page — sealed when there is a
// keyring. A cache that cannot be written is still correct in memory; the
// run goes on.
func (s *Store) write() {
	file := struct {
		Entries []Entry        `json:"entries"`
		Inputs  map[string]any `json:"inputs,omitempty"`
	}{Entries: make([]Entry, 0, len(s.index)), Inputs: map[string]any{}}
	for _, e := range s.index {
		file.Entries = append(file.Entries, e)
	}
	if s.kr != nil {
		if clear, err := json.Marshal(s.inputs); err == nil {
			if sealed, err := s.kr.Seal(clear, s.agentAAD); err == nil {
				if b, err := vault.Marshal(sealed); err == nil {
					var raw map[string]any
					if json.Unmarshal(b, &raw) == nil {
						file.Inputs["sealed"] = raw
					}
				}
			}
		}
	} else {
		file.Inputs["clear"] = map[string]any{}
		for k, v := range s.inputs {
			file.Inputs["clear"].(map[string]any)[k] = v
		}
	}
	if b, err := json.MarshalIndent(file, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
		_ = atomicfile.Write(s.path, b, 0o600)
	}
}

// Caches says whether an action is ever kept. Browser actions except
// signing in: those are a flow. Everything else — store operations, tools,
// delegations, a sign-in — is decided, not remembered.
func Caches(op string) bool {
	if op == "browser_sign_in" {
		return false
	}
	return agent.IsBrowser(op)
}

// Key is what a decision was made on: the agent, the person the run is
// for, the goal, and the page. The person is in it because what a run typed
// is that person's: the same goal on the same form, run for somebody else,
// must not type the first person's words. Empty when there is no page to
// key against, which is the first turn and every turn of a run that never
// opens one.
func Key(name, person, goal string, seen []agent.Observation) string {
	page := ""
	for i := len(seen) - 1; i >= 0; i-- {
		if seen[i].Err == nil && agent.IsBrowser(seen[i].From) && !seen[i].Trusted {
			if seen[i].From == "browser_look" {
				// A look leaves a placeholder — the address, and a note that
				// a picture travelled — which names a page by address alone:
				// two states of one address would share a key. The outline
				// before it is the page this can key on.
				continue
			}
			page = seen[i].Body
			break
		}
	}
	if page == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(name + "\x00" + person + "\x00" + goal + "\x00" + page))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Event tells the run's record what the cache did.
type Event struct {
	// Replay is true when the decision came from the cache.
	Replay bool
	// Digest is the key the decision was made against.
	Digest string
	// Op is what was replayed, or recorded.
	Op string
	// FellBack is true when a replay's page was not the one remembered.
	FellBack bool
}

// Note is told what the cache did, once per decision it touched.
type Note func(Event)

// Wrap puts the cache in front of a decider. The inner decider is asked
// only when nothing is remembered for the page in front of the run, and
// every step — replayed or decided — is confirmed by the page that
// follows it before the flow goes on.
//
// reset, when not nil, is called whenever a replay answers from memory:
// whatever the inner decider was holding over from its last answer — a
// dialect's open batch — belongs to a plan this flow is no longer on.
func Wrap(inner agent.Decide, s *Store, agentName, person string, note Note, reset func()) agent.Decide {
	var lastKey string
	var lastAction agent.Action
	var lastAfter string
	var replayed bool

	return func(ctx context.Context, goal string, seen []agent.Observation) (agent.Action, error) {
		// First, the step that just ran: confirmed, recorded, or dropped.
		if lastKey != "" && len(seen) > 0 {
			o := seen[len(seen)-1]
			if o.Err == nil && o.From == lastAction.Op {
				d := digest(o.Body)
				if replayed && lastAfter != "" && d != lastAfter {
					// The page is not the one the flow remembers: the entry
					// is wrong now, and the model decides from here.
					s.Drop(lastKey)
					if note != nil {
						note(Event{Digest: lastKey, Op: lastAction.Op, FellBack: true})
					}
				} else {
					s.Record(lastKey, lastAction, d)
				}
			} else if replayed && (o.Err != nil ||
				(o.From == "quilzo" && strings.HasPrefix(o.Body, "refused:"))) {
				// The replayed action itself failed, or was refused — by the
				// gate, or by a person. Either way the flow remembered is a
				// flow this run will not complete, and replaying it again
				// next turn is a loop with a model nowhere in it.
				s.Drop(lastKey)
			}
			lastKey, lastAfter, replayed = "", "", false
		}

		key := Key(agentName, person, goal, seen)
		if key != "" {
			if a, after, ok := s.Lookup(key); ok {
				if reset != nil {
					reset()
				}
				lastKey, lastAction, lastAfter, replayed = key, a, after, true
				if note != nil {
					note(Event{Replay: true, Digest: key, Op: a.Op})
				}
				return a, nil
			}
		}
		a, err := inner(ctx, goal, seen)
		if err != nil {
			return a, err
		}
		if key != "" && Caches(a.Op) {
			lastKey, lastAction, replayed = key, a, false
		}
		return a, nil
	}
}

func digest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}
