// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Decoys: credentials nothing legitimate uses.
//
// A decoy token looks exactly like an access token, and is planted where a
// real one could be found: an old wiki page, a CI variable, a laptop's
// configuration. It opens nothing. Somebody presenting one has a copy of
// something they should not, and that is known the moment they try it,
// which is before they have found a token that works.
//
// Only a hash is kept, as for real tokens, so this file is no more use to a
// thief than the token store is. The note says where it was planted, which
// is what tells a person afterwards where the leak was.

// Decoy is one planted credential.
type Decoy struct {
	ID   string    `json:"id"`
	Hash string    `json:"hash"`
	Note string    `json:"note"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
}

// maxDecoys bounds the list.
const maxDecoys = 100

func decoyHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// AddDecoy makes a decoy token and returns it, once; only its hash is kept.
// It has the shape of an access token, prefix and length, so nothing tells
// the two apart but trying it.
func AddDecoy(root, note, by string, now time.Time) (string, Decoy, error) {
	note = strings.TrimSpace(note)
	if note == "" || len(note) > 200 || strings.ContainsAny(note, "\r\n") {
		return "", Decoy{}, errors.New("say where it will be planted, on one line of at most 200 characters")
	}
	secret, err := auth.NewSecret()
	if err != nil {
		return "", Decoy{}, err
	}
	d := Decoy{ID: newID(), Hash: decoyHash(secret), Note: note, By: by, At: now}
	err = Change(root, now, func(st *State) error {
		if len(st.Decoys) >= maxDecoys {
			return fmt.Errorf("%d decoys are planted already; remove one first", maxDecoys)
		}
		st.Decoys = append(st.Decoys, d)
		return nil
	})
	if err != nil {
		return "", Decoy{}, err
	}
	return secret, d, nil
}

// RemoveDecoy takes a decoy out, when what it was planted in is gone.
func RemoveDecoy(root, id string, now time.Time) error {
	return Change(root, now, func(st *State) error {
		for i, d := range st.Decoys {
			if d.ID == id {
				st.Decoys = append(st.Decoys[:i], st.Decoys[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no decoy %s", id)
	})
}

// Decoy reports whether a presented secret is a decoy. The comparison runs
// over every decoy in constant time, so trying one says nothing about the
// others.
func (g *Guard) Decoy(secret string, now time.Time) (Decoy, bool) {
	st := g.state(now)
	secret = strings.TrimSpace(secret)
	if len(st.Decoys) == 0 || !strings.HasPrefix(secret, auth.TokenPrefix) {
		return Decoy{}, false
	}
	want := []byte(decoyHash(secret))
	var found Decoy
	ok := false
	for _, d := range st.Decoys {
		if subtle.ConstantTimeCompare([]byte(d.Hash), want) == 1 {
			found, ok = d, true
		}
	}
	return found, ok
}
