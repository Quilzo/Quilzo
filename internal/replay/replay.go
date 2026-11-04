// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package replay remembers the identifiers of one-time proofs and tokens,
// for as long as each could be presented again, so each is good once.
//
// One cache for what three had each written for themselves: DPoP proofs
// (internal/dpop), agent credential proofs (internal/agentcred) and
// exchanged identity tokens (internal/federate). Their rules had drifted.
// The DPoP one had no bound and swept everything it held on every request
// under one lock, and anybody can make a valid DPoP proof with a key of
// their own before a token is looked at: 65,636 proofs took close to two
// minutes to remember, and the memory grew with whatever was sent.
package replay

import (
	"container/heap"
	"sync"
	"time"
)

// DefaultMax is how many identifiers a Cache remembers at once when its
// Max is not set.
const DefaultMax = 1 << 16

// Cache remembers identifiers until each one's time is up. The zero value
// is ready to use.
type Cache struct {
	// Max bounds how many identifiers are remembered at once; zero is
	// DefaultMax.
	Max int

	mu    sync.Mutex
	until map[string]time.Time
	queue byUntil
}

// First reports whether id is new, and remembers it until until.
//
// Those whose time has passed are forgotten first, soonest first, so a call
// costs what it forgets and not everything remembered. A cache full of
// identifiers still in their time refuses a new one rather than forget one
// early, which would let that one be presented again: under a flood, new
// proofs wait for room, and none is accepted twice.
func (c *Cache) First(id string, until, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until == nil {
		c.until = map[string]time.Time{}
	}
	for len(c.queue) > 0 && now.After(c.queue[0].until) {
		delete(c.until, heap.Pop(&c.queue).(entry).id)
	}
	if _, seen := c.until[id]; seen {
		return false
	}
	max := c.Max
	if max <= 0 {
		max = DefaultMax
	}
	if len(c.until) >= max {
		return false
	}
	c.until[id] = until
	heap.Push(&c.queue, entry{id: id, until: until})
	return true
}

// Seen reports whether id is remembered and its time is not up, without
// remembering it.
//
// For a caller that may remember an identifier only once what it stands
// for has been done: a security event whose action failed has to come back
// and be done, and First, which remembers as it answers, would turn the
// retry into a replay refused for having been seen.
func (c *Cache) Seen(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.until[id]
	return ok && !now.After(until)
}

// Full reports whether a new identifier would be refused for want of room,
// so a caller can say "later" rather than act on what it could not then
// remember.
func (c *Cache) Full(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.queue) > 0 && now.After(c.queue[0].until) {
		delete(c.until, heap.Pop(&c.queue).(entry).id)
	}
	max := c.Max
	if max <= 0 {
		max = DefaultMax
	}
	return len(c.until) >= max
}

// Len is how many identifiers are remembered now.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.until)
}

type entry struct {
	id    string
	until time.Time
}

// byUntil is a heap with the identifier whose time is up soonest on top.
type byUntil []entry

func (q byUntil) Len() int           { return len(q) }
func (q byUntil) Less(i, j int) bool { return q[i].until.Before(q[j].until) }
func (q byUntil) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *byUntil) Push(x any)        { *q = append(*q, x.(entry)) }
func (q *byUntil) Pop() any {
	old := *q
	e := old[len(old)-1]
	*q = old[:len(old)-1]
	return e
}
