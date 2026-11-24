// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/vault"
)

// Sealing a file kept beside the store, as the store seals its objects.
//
// Some of what a store's owner keeps cannot live in the store, because the
// store cannot forget: the register's side store holds free text and the
// map from a pseudonym to a person, each erasable on its own. Those files
// are as sensitive as anything in objects/, and an encrypted store that kept
// them in the clear beside it would protect the hashes and leak the names.
// So they are sealed with the store's own keyring, when it has one, without
// the keyring leaving this package.

// Seal is payload as a file beside the store holds it: sealed under the
// store's keyring with aad bound in, or as it is when the store is not
// encrypted. aad names what the file is, so a sealed file moved to stand for
// another does not open.
func (s *Store) Seal(payload, aad []byte) ([]byte, error) {
	s.mu.Lock()
	kr := s.keys
	s.mu.Unlock()
	if kr == nil {
		return payload, nil
	}
	sealed, err := kr.Seal(payload, aad)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt a file beside the store: %w", err)
	}
	return vault.Marshal(sealed)
}

// Unseal is the payload of a file Seal wrote. A file in the clear is
// returned as it is, because a store can be half converted: turning
// encryption on does not rewrite what was written before.
func (s *Store) Unseal(body, aad []byte) ([]byte, error) {
	if !vault.IsSealed(body) {
		return body, nil
	}
	s.mu.Lock()
	kr := s.keys
	s.mu.Unlock()
	if kr == nil {
		return nil, fmt.Errorf("a file beside the store is encrypted and no key was supplied")
	}
	sealed, err := vault.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("a file beside the store is malformed: %w", err)
	}
	return kr.Open(sealed, aad)
}
