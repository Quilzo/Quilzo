package telegram

import (
	"sync"
	"time"
)

// Memory is a Spender for a single process.
//
// # Why the honest name matters
//
// This is correct for one process and wrong for two. Two replicas with separate
// memories will each accept the same link once, so a single-use token is
// two-use — and that is the sort of hole that never shows up in testing because
// testing runs one process.
//
// So the type is called Memory rather than DefaultSpender or SpenderImpl, and
// this comment says the limit out loud. An operator running more than one of
// these needs a Spender they both see, and the interface exists so that is a
// small change rather than a rewrite.
//
// # Why it forgets
//
// A spent nonce only has to be remembered until the link it belongs to would
// have expired anyway — after that the expiry check refuses it regardless, so
// keeping the nonce buys nothing and the map grows forever. Sweeping on write
// rather than on a timer keeps this dependency-free and means an idle process
// holds nothing.
type Memory struct {
	mu    sync.Mutex
	spent map[string]time.Time
	// Now is the clock, injectable so the sweep is testable without sleeping.
	// Nil means time.Now.
	Now func() time.Time
	// MaxEntries bounds the map so that a flood of forged links cannot be used
	// to exhaust memory. Zero means the default.
	MaxEntries int
}

// defaultMaxEntries is the ceiling on remembered nonces.
//
// A nonce entry is about eighty bytes, so this is a few megabytes at worst.
// It is high enough that no legitimate traffic reaches it and low enough that
// somebody replaying forged links cannot turn this map into the outage.
const defaultMaxEntries = 50_000

// NewMemory returns a Spender for this process.
func NewMemory() *Memory {
	return &Memory{spent: map[string]time.Time{}}
}

// Spend records a nonce and reports whether it was unused.
//
// One lock across the check and the write, because two simultaneous taps of the
// same link is exactly the case a separate check-then-write loses.
func (m *Memory) Spend(nonce string, expires time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	if m.spent == nil {
		m.spent = map[string]time.Time{}
	}

	// Sweep first, so an expired entry does not block a nonce that has come
	// round again and does not count towards the ceiling.
	for key, when := range m.spent {
		if now.After(when) {
			delete(m.spent, key)
		}
	}

	if _, used := m.spent[nonce]; used {
		return false
	}

	limit := m.MaxEntries
	if limit <= 0 {
		limit = defaultMaxEntries
	}
	if len(m.spent) >= limit {
		// Refuse rather than evict. Evicting the oldest entry to make room
		// would let somebody with a flood of forged links push a real spent
		// nonce out of the map and then replay it — turning a memory bound
		// into a replay primitive. Refusing is a denial of service on new
		// links, which is visible, recoverable, and the better failure.
		return false
	}
	m.spent[nonce] = expires
	return true
}

// Len is how many spent nonces are being remembered, for a status screen.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.spent)
}
