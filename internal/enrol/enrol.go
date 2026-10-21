// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package enrol keeps one-time links that add a passkey for one person.
//
// Two factors are compulsory, and the first passkey has to come from
// somewhere. A token alone cannot add one, or a copied token would bind
// its copier's key; so somebody already trusted (the operator at the
// store's machine, or an administrator signed in with two factors) issues
// a link for one named person, and opening it lets exactly that: add a
// passkey for that person, once, within a day. Nothing else is reached
// through it.
//
// A link is a 256-bit secret, kept only as its hash, so the file that holds
// them can be read without anybody being able to enrol from it. A new link
// for a person replaces their earlier one, so there is never more than one
// way in waiting for anybody.
package enrol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// MaxLife is the longest a link may wait to be used.
const MaxLife = 24 * time.Hour

// Prefix marks an enrolment secret, so one pasted somewhere it does not
// belong is recognisable for what it is.
const Prefix = "qzenrol_"

// ErrNoLink is a secret that names no live link: unknown, used, ended or
// replaced. Which of those is not said, to whoever presented it.
var ErrNoLink = errors.New("this enrolment link does not work: it has been used, it has ended, or it was replaced")

// Link is one waiting enrolment.
type Link struct {
	Hash      string    `json:"hash"`
	Principal string    `json:"principal"`
	By        string    `json:"by"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

type file struct {
	Links []Link `json:"links"`
}

// Store keeps the links in one file.
type Store struct {
	Path string
}

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

// Issue makes a link for principal, lasting life (at most MaxLife), issued
// by by, and returns its secret once. Any earlier link for the same person
// stops working.
func (s Store) Issue(principal, by string, life time.Duration, now time.Time) (string, Link, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return "", Link{}, errors.New("an enrolment link is for somebody: name them")
	}
	if life <= 0 || life > MaxLife {
		return "", Link{}, fmt.Errorf("an enrolment link lasts more than nothing and at most %s", MaxLife)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Link{}, err
	}
	secret := Prefix + strings.ToLower(enc.EncodeToString(raw))
	l := Link{Hash: hashOf(secret), Principal: principal, By: by, Created: now.UTC(), Expires: now.UTC().Add(life)}
	err := atomicfile.Update(s.Path, func(f *file) error {
		kept := f.Links[:0]
		for _, x := range f.Links {
			if !strings.EqualFold(x.Principal, principal) && now.Before(x.Expires) {
				kept = append(kept, x)
			}
		}
		f.Links = append(kept, l)
		return nil
	})
	if err != nil {
		return "", Link{}, err
	}
	return secret, l, nil
}

// Peek is the live link a secret names, without using it.
func (s Store) Peek(secret string, now time.Time) (Link, error) {
	var found Link
	var ok bool
	err := atomicfile.Update(s.Path, func(f *file) error {
		found, ok = match(f.Links, secret, now)
		return atomicfile.ErrUnchanged
	})
	if err != nil {
		return Link{}, err
	}
	if !ok {
		return Link{}, ErrNoLink
	}
	return found, nil
}

// Take uses a link: it is gone once a passkey has been added through it.
func (s Store) Take(secret string, now time.Time) (Link, error) {
	var found Link
	var ok bool
	err := atomicfile.Update(s.Path, func(f *file) error {
		found, ok = match(f.Links, secret, now)
		if !ok {
			return atomicfile.ErrUnchanged
		}
		kept := f.Links[:0]
		for _, x := range f.Links {
			if x.Hash != found.Hash && now.Before(x.Expires) {
				kept = append(kept, x)
			}
		}
		f.Links = kept
		return nil
	})
	if err != nil {
		return Link{}, err
	}
	if !ok {
		return Link{}, ErrNoLink
	}
	return found, nil
}

// Revoke ends any link waiting for principal, and reports whether there was one.
func (s Store) Revoke(principal string, now time.Time) (bool, error) {
	removed := false
	err := atomicfile.Update(s.Path, func(f *file) error {
		kept := f.Links[:0]
		for _, x := range f.Links {
			if strings.EqualFold(x.Principal, principal) {
				removed = true
				continue
			}
			if now.Before(x.Expires) {
				kept = append(kept, x)
			}
		}
		f.Links = kept
		return nil
	})
	return removed, err
}

// Waiting are the live links, for the commands and screens that list them.
func (s Store) Waiting(now time.Time) ([]Link, error) {
	var out []Link
	err := atomicfile.Update(s.Path, func(f *file) error {
		for _, x := range f.Links {
			if now.Before(x.Expires) {
				out = append(out, x)
			}
		}
		return atomicfile.ErrUnchanged
	})
	return out, err
}

func match(links []Link, secret string, now time.Time) (Link, bool) {
	if !strings.HasPrefix(strings.TrimSpace(secret), Prefix) {
		return Link{}, false
	}
	want := hashOf(secret)
	for _, x := range links {
		if subtle.ConstantTimeCompare([]byte(x.Hash), []byte(want)) == 1 && now.Before(x.Expires) {
			return x, true
		}
	}
	return Link{}, false
}
