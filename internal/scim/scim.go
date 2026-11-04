// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package scim lets a company's identity provider keep Quilzo's people in
// step with its own: SCIM 2.0 (RFC 7643, RFC 7644), as Okta and Microsoft
// Entra speak it.
//
// # What it is for
//
// The person who leaves. Access granted by hand is removed by hand, which is
// to say late or never. With provisioning, the identity provider tells this
// program the moment somebody is deactivated, and their access ends then:
// their grants are withdrawn and every session and token they hold stops
// working.
//
// # What it may do, and what it may not
//
// The identity provider names people and puts them in groups. It does not
// grant anything. A person here decides, once, what each group means — the
// "Security team" group is the analyst job, the "Editors" group is publisher
// — and provisioning only ever applies those mappings. A group nobody mapped
// grants nothing; a compromised provisioning token can move people between
// the mapped groups and cannot make anybody an administrator unless a
// person already mapped a group to that.
//
// Grants made this way are marked as made by provisioning and are the only
// ones it ever changes. Access somebody granted by hand is never touched.
//
// # What is stored
//
// The user name the provider sent (the name a person signs in as), whether
// they are active, the provider's own id for them, and which groups contain
// whom. Display names and emails are accepted and not kept: nothing here
// needs them.
package scim

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
)

// Schema identifiers, from RFC 7643 and RFC 7644.
const (
	SchemaUser     = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaList     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError    = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatch    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaSPConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// User is one provisioned person.
type User struct {
	ID         string    `json:"id"`
	UserName   string    `json:"userName"`
	ExternalID string    `json:"externalId,omitempty"`
	Active     bool      `json:"active"`
	Created    time.Time `json:"created"`
	Modified   time.Time `json:"modified"`
}

// Group is one provisioned group and who is in it.
type Group struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName"`
	ExternalID  string    `json:"externalId,omitempty"`
	Members     []string  `json:"members"` // user ids
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
}

// State is everything provisioning knows.
type State struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
	// Mapping is what each group means here: a group's display name to a
	// role ("reader" … "admin") or a job ("analyst" …), and for a job
	// granted only for a time the day that time is over ("auditor until
	// 2026-12-31", MappedUntil). Set by a person.
	Mapping map[string]string `json:"mapping"`
}

// A job granted only for a time (auth.Job.Ends) is mapped with the day its
// access ends, as granting it by hand is, and what provisioning grants for
// it ends then. The day is written into the mapping, so it is shown, sent
// and stored wherever the mapping already is.
//
// A group mapped to auditor was accepted with no day, and its members held
// auditor for as long as they stayed in the group: on the reference stack
// `auth list` showed the auditor with no until date, while a hand grant of
// auditor is refused without one. An assessor is there for an assessment,
// and a group nobody remembered to empty is access nobody remembered to
// remove.
const untilWord = " until "

// ErrMustEnd is a mapping to a job granted only for a time with no day its
// access ends. Each surface says how to give one.
var ErrMustEnd = errors.New("ends by itself, and a group's lasts while somebody is in the group, so it is " +
	"mapped with the day it ends")

// MappedUntil is a mapping to what that ends at the start of day.
func MappedUntil(what string, day time.Time) string {
	return what + untilWord + day.UTC().Format(time.DateOnly)
}

// SplitMapping is what a mapping grants and the day that ends, zero for a
// mapping that lasts while somebody is in the group. what is returned even
// when the day cannot be read, so a caller asking what a mapping makes
// somebody still reads it.
func SplitMapping(mapping string) (what string, until time.Time, err error) {
	what, day, ok := strings.Cut(mapping, untilWord)
	if !ok {
		return mapping, time.Time{}, nil
	}
	until, err = time.Parse(time.DateOnly, day)
	if err != nil {
		return what, time.Time{}, fmt.Errorf("%q does not end on a day, like 2026-12-31", mapping)
	}
	return what, until, nil
}

// CheckEnds refuses a mapping whose end does not fit what it grants: a job
// granted only for a time with no day (ErrMustEnd) or with a day gone by,
// and a day on anything else, which would be dropped rather than kept.
// Provisioning grants nothing for a mapping it refuses, which is how a
// mapping saved before mappings carried a day, or whose day has passed,
// takes back what it gave.
func CheckEnds(mapping string, now time.Time) error {
	what, until, err := SplitMapping(mapping)
	if err != nil {
		return err
	}
	job, isJob := auth.JobNamed(what)
	switch {
	case isJob && job.Ends && until.IsZero():
		return fmt.Errorf("%s access %w", what, ErrMustEnd)
	case !until.IsZero() && !(isJob && job.Ends):
		return fmt.Errorf("%s lasts while somebody is in the group; only a job granted for a time is mapped "+
			"with the day it ends", what)
	case !until.IsZero() && !now.Before(until):
		return fmt.Errorf("%s has already ended", mapping)
	}
	return nil
}

// Errors a caller distinguishes.
var (
	ErrNotFound = errors.New("no such resource")
	ErrConflict = errors.New("that userName or displayName is already in use")
)

// Store keeps the state in one file.
type Store struct {
	Path string
	Now  func() time.Time
	mu   sync.Mutex
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Load reads the state; a missing file is an empty one.
func (s *Store) Load() (*State, error) {
	st := &State{Mapping: map[string]string{}}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	if st.Mapping == nil {
		st.Mapping = map[string]string{}
	}
	return st, nil
}

func (s *Store) save(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.Path, b, 0o600)
}

// Update runs a change against the state and saves it, under one lock.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.Load()
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	return s.save(st)
}

// Read runs a read against the state under the same lock.
func (s *Store) Read(fn func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.Load()
	if err != nil {
		return err
	}
	fn(st)
	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// User finds one by id.
func (st *State) User(id string) (*User, bool) {
	for i := range st.Users {
		if st.Users[i].ID == id {
			return &st.Users[i], true
		}
	}
	return nil, false
}

// UserNamed finds one by user name, which compares without case: an
// identity provider and a person typing an address disagree about it.
func (st *State) UserNamed(name string) (*User, bool) {
	for i := range st.Users {
		if strings.EqualFold(st.Users[i].UserName, name) {
			return &st.Users[i], true
		}
	}
	return nil, false
}

// Group finds one by id.
func (st *State) Group(id string) (*Group, bool) {
	for i := range st.Groups {
		if st.Groups[i].ID == id {
			return &st.Groups[i], true
		}
	}
	return nil, false
}

// GroupsOf is the display names of every group a user is in.
func (st *State) GroupsOf(userID string) []string {
	var out []string
	for _, g := range st.Groups {
		for _, m := range g.Members {
			if m == userID {
				out = append(out, g.DisplayName)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Grants is what a user should hold here: the mapped meaning of each group
// they are in, nothing if they are inactive, and nothing for a group nobody
// mapped.
func (st *State) Grants(userID string) []string {
	u, ok := st.User(userID)
	if !ok || !u.Active {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range st.GroupsOf(userID) {
		if m := st.Mapping[g]; m != "" && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// removeMember takes a user out of every group.
func (st *State) removeMember(userID string) {
	for i := range st.Groups {
		kept := st.Groups[i].Members[:0]
		for _, m := range st.Groups[i].Members {
			if m != userID {
				kept = append(kept, m)
			}
		}
		st.Groups[i].Members = kept
	}
}
