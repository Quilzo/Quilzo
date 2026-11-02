// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package chatact carries what a visitor asked a chatbot's agent to do,
// from the public site to the admin server, and the answer back.
//
// The public site runs confined (it can write only its own state) and so
// cannot run an agent: agents need the store, the models and the policy.
// So the site writes a request into a folder it may write, the admin
// server's dispatcher takes it, runs the agent, and writes the answer
// beside it, and the visitor's page, which polls, shows it. Each request
// has an id nobody can guess, which is the only way to its answer; both
// are kept a day and then deleted.
package chatact

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Keep is how long a request and its answer are kept.
const Keep = 24 * time.Hour

// Request is what a visitor asked.
type Request struct {
	ID      string `json:"id"`
	Chatbot string `json:"chatbot"`
	Action  string `json:"action"`
	// Args are what the visitor gave, by the action's field names: their
	// words, never trusted.
	Args map[string]string `json:"args,omitempty"`
	// Token is the host site's signed word about who they are
	// (assistant.VerifyVisitor), as the visitor's page carried it. The
	// admin server verifies it itself: a request is written by the public
	// site, and nothing in it is taken on the site's word.
	Token string    `json:"token,omitempty"`
	At    time.Time `json:"at"`
}

// States an answer is in.
const (
	Working = "working"
	Done    = "done"
	// Person is an answer a person will give instead: the run read
	// something not everybody may see, or it waits for a person.
	Person = "person"
	Failed = "failed"
)

// Result is the answer to a request.
type Result struct {
	ID     string    `json:"id"`
	State  string    `json:"state"`
	Answer string    `json:"answer,omitempty"`
	At     time.Time `json:"at"`
}

// Queue is the folder requests and answers are kept in.
type Queue struct{ Dir string }

var reID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewID is an id nobody can guess.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidID reports whether s is an id this package made.
func ValidID(s string) bool { return reID.MatchString(s) }

func (q Queue) req(id string) string { return filepath.Join(q.Dir, id+".request.json") }
func (q Queue) res(id string) string { return filepath.Join(q.Dir, id+".result.json") }

// Put keeps a request.
func (q Queue) Put(r Request) error {
	if !ValidID(r.ID) {
		return errors.New("not a request's id")
	}
	if err := os.MkdirAll(q.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return atomicfile.Write(q.req(r.ID), b, 0o600)
}

// Pending are the requests nobody has answered yet, oldest first.
func (q Queue) Pending() ([]Request, error) {
	ents, err := os.ReadDir(q.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".request.json")
		if !ok || !ValidID(id) {
			continue
		}
		if _, err := os.Stat(q.res(id)); err == nil {
			continue
		}
		b, err := os.ReadFile(q.req(id))
		if err != nil {
			continue
		}
		var r Request
		if json.Unmarshal(b, &r) == nil && r.ID == id {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// Answer keeps a request's answer. A request already answered keeps its
// answer unless this is the run finishing what it started (from Working).
func (q Queue) Answer(r Result) error {
	if !ValidID(r.ID) {
		return errors.New("not a request's id")
	}
	if prev, ok := q.Result(r.ID); ok && prev.State != Working {
		return fmt.Errorf("request %s is answered already", r.ID)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return atomicfile.Write(q.res(r.ID), b, 0o600)
}

// Claim marks a request as being worked on, if nobody has: true when this
// caller has it.
func (q Queue) Claim(id string, now time.Time) (bool, error) {
	if !ValidID(id) {
		return false, errors.New("not a request's id")
	}
	b, _ := json.Marshal(Result{ID: id, State: Working, At: now.UTC()})
	f, err := os.OpenFile(q.res(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr == nil, werr
}

// Result is a request's answer, when there is one.
func (q Queue) Result(id string) (Result, bool) {
	if !ValidID(id) {
		return Result{}, false
	}
	b, err := os.ReadFile(q.res(id))
	if err != nil {
		return Result{}, false
	}
	var r Result
	if json.Unmarshal(b, &r) != nil || r.ID != id {
		return Result{}, false
	}
	return r, true
}

// Exists reports whether a request was made.
func (q Queue) Exists(id string) bool {
	if !ValidID(id) {
		return false
	}
	_, err := os.Stat(q.req(id))
	return err == nil
}

// Prune deletes requests and answers older than Keep, and says how many.
func (q Queue) Prune(now time.Time) int {
	ents, err := os.ReadDir(q.Dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		fi, err := e.Info()
		if err == nil && now.Sub(fi.ModTime()) > Keep && os.Remove(filepath.Join(q.Dir, e.Name())) == nil {
			n++
		}
	}
	return n
}
