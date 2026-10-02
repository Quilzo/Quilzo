// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
	// role ("reader" … "admin") or a job ("analyst" …). Set by a person.
	Mapping map[string]string `json:"mapping"`
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
