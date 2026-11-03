// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package accessreview

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Store keeps reviews as one file each, access/reviews/ID.json, because a
// review is the evidence: a file an auditor can be handed whole, with every
// reason in it, beside an audit log that carries none of them.
type Store struct{ Dir string }

// ErrOpen is starting a review while another is still being decided. One
// at a time, so "the review" always means one snapshot and one set of
// decisions about it.
var ErrOpen = errors.New("a review is already open; close it first")

func (s *Store) path(id string) string { return filepath.Join(s.Dir, id+".json") }

// lock serialises every change to the reviews, across the admin and the
// command line, so two people deciding at once both land and a second
// start cannot slip past the first.
func (s *Store) lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	return atomicfile.Lock(filepath.Join(s.Dir, ".lock"))
}

// List is every review, oldest first.
func (s *Store) List() ([]*Review, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Review
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		r := &Review{}
		if err := json.Unmarshal(b, r); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out, nil
}

// Current is the open review, or nil when there is none.
func (s *Store) Current() (*Review, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.Open() {
			return r, nil
		}
	}
	return nil, nil
}

// LastClosed is when the latest review closed, if one ever has.
func (s *Store) LastClosed() (time.Time, bool, error) {
	all, err := s.List()
	if err != nil {
		return time.Time{}, false, err
	}
	var last time.Time
	for _, r := range all {
		if !r.Open() && r.Closed.After(last) {
			last = r.Closed
		}
	}
	return last, !last.IsZero(), nil
}

func (s *Store) save(r *Review) error {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path(r.ID), append(b, '\n'), 0o600)
}

// NewID is a review's name: when it started, and enough chance that two
// started in one second are not one file.
func NewID(now time.Time) string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// Start keeps a new review, refused while another is open.
func (s *Store) Start(r *Review) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if open, err := s.Current(); err != nil {
		return err
	} else if open != nil {
		return fmt.Errorf("%w (review %s, started %s)", ErrOpen, open.ID, open.Started.Format("2 January 2006"))
	}
	return s.save(r)
}

// Update changes the open review under the lock, and keeps it if change
// succeeds. With no review open it says so and changes nothing.
func (s *Store) Update(change func(*Review) error) (*Review, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	r, err := s.Current()
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("no review is open: quilzo access review start begins one")
	}
	if err := change(r); err != nil {
		return nil, err
	}
	return r, s.save(r)
}
