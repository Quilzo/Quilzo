// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"path/filepath"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Who a pseudonym is, for the approvals.
//
// An approval names its people by the pseudonyms the register knows them
// by, never by name: the register cannot forget, and a name is what a
// person may ask to be forgotten. The map from a name to its pseudonym is
// kept beside the store, where an entry can be deleted, and a pseudonym is
// 128 random bits, so nobody can work out from somebody's address which
// approvals are theirs.
//
// People is what the module needs of that map. PeopleFile keeps it for the
// approvals until the register's own subject map is wired in its place; the
// two mint pseudonyms the same way, so moving the entries across changes no
// record.

// People names a person, or an agent, by the pseudonym that stands for them
// in the register, minting one the first time.
type People interface {
	Pseudonym(name string) (register.ID, error)
}

// PeopleFile is People kept in one file beside the store.
type PeopleFile struct{ Path string }

// peopleFile is the file's shape: each name, as auth.PersonKey keys it, and
// its pseudonym.
type peopleFile struct {
	People map[string]register.ID `json:"people"`
}

// PeopleAt is the map of the store at root.
func PeopleAt(root string) PeopleFile {
	return PeopleFile{Path: filepath.Join(root, "approvals", "people.json")}
}

// Pseudonym is the name's pseudonym, minted and kept the first time it is
// asked for. Two spellings of one person ("Dana", "dana ") are one person,
// as every second-person check takes them.
func (f PeopleFile) Pseudonym(name string) (register.ID, error) {
	key := auth.PersonKey(name)
	if key == "" {
		return "", errRefused("a person is named, and nobody was")
	}
	var out register.ID
	err := atomicfile.Update(f.Path, func(pf *peopleFile) error {
		if id, ok := pf.People[key]; ok {
			out = id
			return atomicfile.ErrUnchanged
		}
		id, err := register.NewSubjectID()
		if err != nil {
			return err
		}
		if pf.People == nil {
			pf.People = map[string]register.ID{}
		}
		pf.People[key], out = id, id
		return nil
	})
	return out, err
}

// Forget deletes a name's entry, after which its pseudonym names nobody and
// the approvals that hold it say "a person since erased".
func (f PeopleFile) Forget(name string) error {
	return atomicfile.Update(f.Path, func(pf *peopleFile) error {
		if _, ok := pf.People[auth.PersonKey(name)]; !ok {
			return atomicfile.ErrUnchanged
		}
		delete(pf.People, auth.PersonKey(name))
		return nil
	})
}

// Who is the name a pseudonym stands for, or "" when it stands for nobody
// the map still names.
func (f PeopleFile) Who(id register.ID) string {
	var out string
	_ = atomicfile.Update(f.Path, func(pf *peopleFile) error {
		for name, have := range pf.People {
			if have == id {
				out = name
			}
		}
		return atomicfile.ErrUnchanged
	})
	return out
}
