// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/register"
)

// Who decides, and the words they give.
//
// A record names a person by a pseudonym and holds a justification as the
// digest of its words (internal/register's Subject and Text). The map from
// a pseudonym to the person, and the words, are kept outside the store,
// where they can be erased. The register's own side store does this for
// every module once it is merged; until then a Keeper here does it for the
// programme, behind an interface that store can stand in for.

// Keeper keeps who a pseudonym stands for and the words of a Text.
type Keeper interface {
	// Pseudonym is the pseudonym that stands for a person, an account or
	// an agent, minted the first time they are named.
	Pseudonym(name string, typ register.SubjectType) (register.ID, error)
	// Keep keeps words and gives their digest, which is what a record
	// holds.
	Keep(words string) (register.Text, error)
	// Words is the words a digest was kept for, if they are still kept.
	Words(t register.Text) (string, bool)
}

// TextOf is the digest a record holds for some words: SHA-256 over them,
// as the side store names what it keeps.
func TextOf(words string) register.Text {
	sum := sha256.Sum256([]byte(words))
	return register.Text("sha256:" + hex.EncodeToString(sum[:]))
}

// MaxWords is the most a justification may be, in bytes. A justification
// is a few sentences; a document is evidence, sealed as a raw file.
const MaxWords = 4000

// checkWords refuses what is not a justification: nothing, too much, or
// bytes that are not text.
func checkWords(words string) error {
	switch {
	case strings.TrimSpace(words) == "":
		return fmt.Errorf("say why, in a sentence or two")
	case len(words) > MaxWords:
		return fmt.Errorf("a justification is at most %d bytes, and this is %d", MaxWords, len(words))
	case !utf8.ValidString(words) || strings.ContainsRune(words, 0):
		return fmt.Errorf("a justification is text")
	}
	return nil
}

// FileKeeper keeps both in files in a directory beside the store: one file
// for each person, named by the hash of their name, and one for each
// justification, named by its digest. Erasing either is removing its file.
//
// On a store encrypted at rest it keeps no words, because nothing beside an
// encrypted store is written in the clear: the record holds the digest, and
// the screens say the words are not kept here. Pseudonyms are kept, because
// without them no decision could be made at all, and each file holds only
// the name a person signs in with.
type FileKeeper struct {
	Dir string
	// NoWords is set for a store encrypted at rest.
	NoWords bool
	mu      sync.Mutex
}

type person struct {
	Name      string               `json:"name"`
	Pseudonym register.ID          `json:"pseudonym"`
	Type      register.SubjectType `json:"type"`
}

func (k *FileKeeper) personPath(name string) string {
	sum := sha256.Sum256([]byte("quilzo programme person v1\n" + name))
	return filepath.Join(k.Dir, "subjects", hex.EncodeToString(sum[:])+".json")
}

func (k *FileKeeper) Pseudonym(name string, typ register.SubjectType) (register.ID, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("a person who decides is named")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	path := k.personPath(name)
	if b, err := os.ReadFile(path); err == nil {
		var p person
		if err := json.Unmarshal(b, &p); err != nil || p.Name != name || !p.Pseudonym.Valid() {
			return "", fmt.Errorf("the pseudonym kept for %s cannot be read", name)
		}
		return p.Pseudonym, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id, err := register.NewSubjectID()
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(person{Name: name, Pseudonym: id, Type: typ})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := atomicfile.Write(path, b, 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func (k *FileKeeper) textPath(t register.Text) (string, bool) {
	if !t.Valid() {
		return "", false
	}
	return filepath.Join(k.Dir, "text", strings.TrimPrefix(string(t), "sha256:")), true
}

func (k *FileKeeper) Keep(words string) (register.Text, error) {
	if err := checkWords(words); err != nil {
		return "", err
	}
	t := TextOf(words)
	if k.NoWords {
		return t, nil
	}
	path, _ := k.textPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := atomicfile.Write(path, []byte(words), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func (k *FileKeeper) Words(t register.Text) (string, bool) {
	if words, ok := starterWords(t); ok {
		return words, true
	}
	path, ok := k.textPath(t)
	if !ok {
		return "", false
	}
	b, err := os.ReadFile(path)
	// Words that no longer hash to their name were changed beside the
	// store, and are not what was decided on.
	if err != nil || TextOf(string(b)) != t {
		return "", false
	}
	return string(b), true
}

// MemKeeper keeps both in memory, for tests and for a process that
// decides nothing.
type MemKeeper struct {
	mu     sync.Mutex
	people map[string]register.ID
	words  map[register.Text]string
}

func (k *MemKeeper) Pseudonym(name string, _ register.SubjectType) (register.ID, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("a person who decides is named")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.people == nil {
		k.people = map[string]register.ID{}
	}
	if id, ok := k.people[name]; ok {
		return id, nil
	}
	id, err := register.NewSubjectID()
	if err != nil {
		return "", err
	}
	k.people[name] = id
	return id, nil
}

func (k *MemKeeper) Keep(words string) (register.Text, error) {
	if err := checkWords(words); err != nil {
		return "", err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.words == nil {
		k.words = map[register.Text]string{}
	}
	t := TextOf(words)
	k.words[t] = words
	return t, nil
}

func (k *MemKeeper) Words(t register.Text) (string, bool) {
	if words, ok := starterWords(t); ok {
		return words, true
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	w, ok := k.words[t]
	return w, ok
}
