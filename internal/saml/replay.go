// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"sync"
	"time"
)

// Seen remembers assertion IDs until they could no longer be valid, so each
// is used once. The request binding already stops a captured response from
// being replayed in another browser; this stops it being replayed in the
// same one.
type Seen struct {
	mu  sync.Mutex
	ids map[string]time.Time
}

// MaxSeen bounds the memory. Past it, the oldest are not dropped: new
// sign-ins are refused, because forgetting an ID early is the one failure
// that would let a replay through.
const MaxSeen = 100000

// Use records id until until, and reports false if it was already used or
// the store is full.
func (s *Seen) Use(id string, until, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ids == nil {
		s.ids = map[string]time.Time{}
	}
	if len(s.ids) >= MaxSeen/2 {
		for k, t := range s.ids {
			if now.After(t.Add(Skew)) {
				delete(s.ids, k)
			}
		}
	}
	if t, ok := s.ids[id]; ok && !now.After(t.Add(Skew)) {
		return false
	}
	if len(s.ids) >= MaxSeen {
		return false
	}
	s.ids[id] = until
	return true
}
