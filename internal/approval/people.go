// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Who a pseudonym is, for the approvals.
//
// An approval names its people by the pseudonyms the register knows them
// by, never by name: the register cannot forget, and a name is what a
// person may ask to be forgotten. The map from a name to its pseudonym is
// the register's own subject map, in its side store (Register.SubjectFor,
// side.Store's Enrol and Lookup), which every surface names its writers by.
// So the person who proposed a decision on the command line is the person
// the admin refuses to let approve it, and the reverse, and an erasure
// erases them from the one map there is.
//
// The approvals kept a map of their own in approvals/people.json until the
// subject map was wired in its place, and it named the same people by
// other pseudonyms: one person was two, and could approve what they had
// raised. MigratePeople moves that file into the subject map, keeping every
// pseudonym it gave, and deletes it.

// People names a person, or an agent, by the pseudonym that stands for them
// in the register, minting one the first time.
type People interface {
	Pseudonym(name string) (register.ID, error)
}

// SubjectMap is People as the register's subject map keeps them.
type SubjectMap struct{ Register *register.Register }

// Pseudonym is the name's pseudonym, minted in the subject map the first
// time it is asked for. A name an agent goes by is enrolled as an agent's.
func (m SubjectMap) Pseudonym(name string) (register.ID, error) {
	if strings.TrimSpace(name) == "" {
		return "", errRefused("a person is named, and nobody was")
	}
	return m.Register.SubjectFor(name, subjectType(name))
}

// Known is the name's pseudonym if the subject map holds one, minting
// nothing: what a read asks, so that looking at what waits writes nobody
// into the map.
func (m SubjectMap) Known(name string) (register.ID, bool) {
	if strings.TrimSpace(name) == "" {
		return "", false
	}
	id, ok, err := m.Register.Side().Lookup(name)
	if err != nil || !ok {
		return "", false
	}
	return register.ID(id), true
}

// Who is the name a pseudonym stands for, or "" when it stands for nobody
// the map still names.
func (m SubjectMap) Who(id register.ID) string {
	p, err := m.Register.Side().Who(string(id))
	if err != nil {
		return ""
	}
	return p.Name
}

// subjectType is what sort of subject a name is: an agent's, by the names
// agents go by, or a person's.
func subjectType(name string) register.SubjectType {
	key := auth.PersonKey(name)
	for _, p := range agentPrefixes {
		if strings.HasPrefix(key, p) {
			return "agent"
		}
	}
	return "person"
}

// agentName is the name an agent that proposed something is kept under in
// the subject map: apart from any person's, whose principal could be the
// same word.
func agentName(agent string) string { return "agent:" + agent }

// known is a name's pseudonym as a read asks it: without minting, where the
// map can say so.
func known(p People, name string) (register.ID, bool, error) {
	if k, ok := p.(interface {
		Known(string) (register.ID, bool)
	}); ok {
		id, found := k.Known(name)
		return id, found, nil
	}
	id, err := p.Pseudonym(name)
	return id, err == nil, err
}

// whoIs is the name the subject map holds for a pseudonym, where the map
// can say it.
func whoIs(p People, id register.ID) string {
	if w, ok := p.(interface{ Who(register.ID) string }); ok {
		return w.Who(id)
	}
	return ""
}

func init() { register.MigrateWith(MigratePeople) }

// peopleFile is the shape of the approvals' own map, as it was kept in
// approvals/people.json: each name, as auth.PersonKey keys it, and its
// pseudonym.
type peopleFile struct {
	People map[string]register.ID `json:"people"`
}

// PeoplePath is where the approvals kept their own map of people, before
// the subject map was the one map.
func PeoplePath(root string) string { return filepath.Join(root, "approvals", "people.json") }

// MigratePeople moves the approvals' own map of people into the register's
// subject map, each name under the pseudonym it was given, so that every
// approval already in the register still names the person it named; then
// it deletes the file, and the names the requests and batches waiting for
// approvers kept beside each signature. A pseudonym somebody was erased
// under is not brought back. A store with no such file has nothing to move.
func MigratePeople(r *register.Register) error {
	root := r.Store.Root()
	raw, err := os.ReadFile(PeoplePath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pf peopleFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return fmt.Errorf("the approvals' map of people, %s, does not read: %w", PeoplePath(root), err)
	}
	s := r.Side()
	for name, id := range pf.People {
		if !id.Valid() || strings.TrimSpace(name) == "" {
			continue
		}
		if _, err := r.Get(register.ErasureID(id)); err == nil {
			continue
		}
		if _, err := s.Adopt(name, string(subjectType(name)), string(id)); err != nil {
			return fmt.Errorf("the approvals' map names %s, and the subject map cannot take it: %w", id, err)
		}
	}
	if err := forgetNames(root); err != nil {
		return err
	}
	if err := os.Remove(PeoplePath(root)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// forgetNames takes the names out of the files that wait beside the store:
// each signature of a request kept who gave it, and each batch who it was
// shown to, and both are known by pseudonym now. Read as they are kept now
// and written back, neither holds the name any longer.
func forgetNames(root string) error {
	for _, name := range []string{"requests.json", "batches.json"} {
		path := filepath.Join(root, "approvals", name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		var err error
		if name == "requests.json" {
			err = atomicfile.Update(path, func(*requestsFile) error { return nil })
		} else {
			err = atomicfile.Update(path, func(*batchesFile) error { return nil })
		}
		if err != nil {
			return err
		}
	}
	return nil
}
