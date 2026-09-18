// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/vault"
)

// Moving every object to the active key, which is what rotation means.
//
// # What rotation was
//
// `quilzo vault rotate` added a key, made it active, and printed:
//
//	nothing was re-encrypted. Rotation rewraps data keys, which is
//	why it is cheap enough to actually do.
//
// It rewrapped nothing. vault.Keyring.Rewrap — the function that entire
// sentence is about — had no caller anywhere outside its own tests. So every
// object stayed wrapped under whatever key sealed it, the old key remained
// mandatory to read the store forever, and the operator was told the opposite
// in the same breath.
//
// That is not a missing optimisation. The operational promise of envelope
// encryption is that a compromised key encryption key can be retired. Without
// this it never can be: the command an operator runs after a key leaks leaves
// the leaked key just as necessary as it was before, and says it did the work.
//
// # Why this is here and not in internal/vault
//
// Because the additional authenticated data is the object id, and the object
// id is this package's idea — the filename, derived from the hash of the
// plaintext. internal/vault seals bytes and knows nothing about where they
// live. Rewrapping needs both halves, and this is the half that would
// otherwise have to export its layout.

// Rewrapped reports what one rotation pass did.
type Rewrapped struct {
	// Moved is how many objects were rewrapped to the active key.
	Moved int
	// Current is how many were already on it, which is every object on a
	// second run.
	Current int
	// Plain is how many were stored before encryption was enabled and are
	// still in the clear.
	//
	// Reported rather than converted. Sealing them now would rewrite objects
	// this pass was not asked to touch, and the operator who enabled the vault
	// was told "objects already written stay in the clear; only new ones are
	// sealed" — a rotation that quietly changed that would be a different
	// command wearing this one's name.
	Plain int
}

// Rewrap moves every sealed object onto the keyring's active key.
//
// The content is never decrypted. Each object's data key is unwrapped with the
// key that sealed it and re-wrapped with the active one — thirty-two bytes per
// object — which is the property that makes rotation cheap enough to actually
// happen.
//
// Every key that ever sealed anything must still be loaded, or this cannot
// unwrap what it finds. That is the same requirement reading the store has, so
// a rotation that can run is one the operator could already read with; and
// after it runs, it is the requirement that goes away.
func (s *Store) Rewrap() (Rewrapped, error) {
	var out Rewrapped
	if s.keys == nil {
		return out, fmt.Errorf(
			"this store is not encrypted, so there is nothing to rewrap")
	}

	shards, err := os.ReadDir(s.objects)
	if err != nil {
		return out, err
	}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		dir := filepath.Join(s.objects, shard.Name())
		names, err := os.ReadDir(dir)
		if err != nil {
			return out, err
		}
		for _, n := range names {
			if strings.HasPrefix(n.Name(), ".") {
				continue
			}
			oid := shard.Name() + n.Name()
			path := filepath.Join(dir, n.Name())

			body, err := os.ReadFile(path)
			if err != nil {
				return out, err
			}
			if !vault.IsSealed(body) {
				out.Plain++
				continue
			}
			sealed, err := vault.Unmarshal(body)
			if err != nil {
				return out, fmt.Errorf("object %s: %w", oid, err)
			}
			moved, err := s.keys.Rewrap(sealed, []byte(oid))
			if err != nil {
				// Named, because the useful message is which object and
				// which key rather than that something failed. An operator
				// who has retired a key too early finds out here, before
				// anything is written.
				return out, fmt.Errorf("object %s: %w", oid, err)
			}
			if moved == sealed {
				// Rewrap returns the same pointer when it is already on the
				// active key, which is the cheap way to say "nothing to do"
				// without comparing structs.
				out.Current++
				continue
			}
			next, err := vault.Marshal(moved)
			if err != nil {
				return out, fmt.Errorf("object %s: %w", oid, err)
			}
			// Written the way every other object is: to a temporary name and
			// renamed. A reader that arrives mid-rotation sees the old object
			// or the new one, and both decrypt.
			//
			// Synced regardless of the store's durability mode. The rest of
			// this program defers because an unflushed object is unreachable
			// garbage; here the object is already reachable, and a crash
			// between the rename and the flush would leave content wrapped
			// under a key the operator is about to be told they can retire.
			if err := writeAtomic(path, next, 0o400, true); err != nil {
				return out, fmt.Errorf("object %s: %w", oid, err)
			}
			out.Moved++
		}
	}
	return out, nil
}
