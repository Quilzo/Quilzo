// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/register"
)

// Who decides, and the words they give.
//
// A record names a person by a pseudonym and holds a justification as the
// digest of its words (internal/register's Subject and Text). Both live in
// the register's side store, beside the store, where they can be erased:
// the pseudonym in its subject map, which every surface names its writers
// by, and the words under their digest (Register.PutText, TextOf). The
// programme keeps neither itself.
//
// It did, in programme/subjects and programme/text, before the side store
// was the one place for both, and named people there by pseudonyms of its
// own: the person who raised a decision on the command line was somebody
// else to the approvals. MigrateKeeper moves those files into the side
// store, each person keeping the pseudonym the records hold, and deletes
// them.

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

// keepWords keeps a person's justification for a record of kind in the
// side store, as a write of the kind is asked of the policy, and gives the
// digest the record holds.
func (p *Programme) keepWords(by register.Actor, kind register.Kind, words string) (register.Text, error) {
	if err := checkWords(words); err != nil {
		return "", fmt.Errorf("%w: %v", register.ErrInvalid, err)
	}
	return p.Reg.PutText(by, kind, words)
}

// Words is the words a justification's digest names, where they are held:
// a starter's own, which this program carries, or what a person wrote,
// kept in the register's side store until it is erased.
func (p *Programme) Words(t register.Text) (string, bool) {
	if words, ok := starterWords(t); ok {
		return words, true
	}
	h := p.Reg.TextOf(t)
	return h.Words, h.State == register.TextHeld
}

func init() { register.MigrateWith(MigrateKeeper) }

// keeperDir is where the programme kept who each pseudonym was and the
// words of justifications, before the side store kept both.
func keeperDir(root string) string { return filepath.Join(root, "programme") }

// keptPerson is one person's file as the programme kept it.
type keptPerson struct {
	Name      string               `json:"name"`
	Pseudonym register.ID          `json:"pseudonym"`
	Type      register.SubjectType `json:"type"`
}

// MigrateKeeper moves what the programme kept beside the store into the
// register's side store: each person into the subject map under the
// pseudonym the programme gave them, so every decision already made still
// names them, and the words of each justification under the kinds whose
// records hold its digest. Then it deletes the files. Words changed beside
// the store since they were kept are not what was decided on, and are not
// moved; a person erased since is not brought back. A store with nothing
// there has nothing to move.
func MigrateKeeper(r *register.Register) error {
	dir := keeperDir(r.Store.Root())
	subjects, texts := filepath.Join(dir, "subjects"), filepath.Join(dir, "text")
	people, err := os.ReadDir(subjects)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	words, err := os.ReadDir(texts)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(people) == 0 && len(words) == 0 {
		return nil
	}
	s := r.Side()
	for _, de := range people {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(subjects, de.Name()))
		if err != nil {
			return err
		}
		var kp keptPerson
		if err := json.Unmarshal(raw, &kp); err != nil || !kp.Pseudonym.Valid() || strings.TrimSpace(kp.Name) == "" {
			return fmt.Errorf("the programme's file %s does not read as a person's", de.Name())
		}
		if _, err := r.Get(register.ErasureID(kp.Pseudonym)); err == nil {
			continue
		}
		typ := string(kp.Type)
		if typ == "" {
			typ = "person"
		}
		if _, err := s.Adopt(kp.Name, typ, string(kp.Pseudonym)); err != nil {
			return fmt.Errorf("the programme names %s, and the subject map cannot take it: %w", kp.Pseudonym, err)
		}
	}
	if len(words) > 0 {
		held, err := textKinds(r)
		if err != nil {
			return err
		}
		for _, de := range words {
			raw, err := os.ReadFile(filepath.Join(texts, de.Name()))
			if err != nil {
				return err
			}
			t := TextOf(string(raw))
			if string(t) != "sha256:"+de.Name() {
				continue
			}
			kinds := held[t]
			if len(kinds) == 0 {
				kinds = []register.Kind{register.KindApplicability}
			}
			for _, k := range kinds {
				if _, err := s.Put(string(k), "text", raw); err != nil {
					return err
				}
			}
		}
	}
	for _, d := range []string{subjects, texts} {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
	}
	// The directory goes too when nothing else is in it.
	_ = os.Remove(dir)
	return nil
}

// textKinds is, for each justification's digest the programme's records
// hold, the kinds of the records that hold it.
func textKinds(r *register.Register) (map[register.Text][]register.Kind, error) {
	out := map[register.Text][]register.Kind{}
	v, err := r.At("")
	if err != nil {
		return nil, err
	}
	add := func(t register.Text, k register.Kind) {
		for _, have := range out[t] {
			if have == k {
				return
			}
		}
		out[t] = append(out[t], k)
	}
	for _, k := range []register.Kind{register.KindApplicability, register.KindMapping, register.KindControl} {
		if err := v.Each(k, func(e register.Entry, _ map[string]any) error {
			switch rec := e.Record.(type) {
			case register.Applicability:
				add(rec.Justification, k)
			case register.Mapping:
				add(rec.Rationale, k)
			case register.Control:
				add(rec.Objective, k)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
