// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// An identifier is good once while its time lasts, the cache holds no more
// than its bound, and those whose time is up make room, soonest first.
func TestAnIdentifierIsGoodOnceAndTheCacheIsBounded(t *testing.T) {
	c := &Cache{Max: 3}
	now := time.Unix(1787000000, 0)
	if !c.First("a", now.Add(time.Minute), now) || c.First("a", now.Add(time.Minute), now.Add(30*time.Second)) {
		t.Fatal("an identifier was not good exactly once")
	}
	c.First("b", now.Add(2*time.Minute), now)
	c.First("c", now.Add(3*time.Minute), now)
	if c.First("d", now.Add(time.Minute), now) || c.Len() != 3 {
		t.Fatalf("a full cache took another: %d", c.Len())
	}
	// a's time is up: it goes, and only it.
	later := now.Add(90 * time.Second)
	if !c.First("d", later.Add(time.Minute), later) || c.Len() != 3 {
		t.Fatalf("no room once a's time was up: %d", c.Len())
	}
	if c.First("b", later.Add(time.Minute), later) {
		t.Error("b was forgotten before its time")
	}
	if !c.First("a", later.Add(time.Minute), now.Add(10*time.Minute)) || c.Len() != 1 {
		t.Errorf("after everyone's time, %d remembered", c.Len())
	}
}

// Many callers at once, under -race: each identifier is accepted once.
func TestAnIdentifierIsAcceptedOnceUnderLoad(t *testing.T) {
	var c Cache
	now := time.Unix(1787000000, 0)
	var mu sync.Mutex
	accepted := map[string]int{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				id := fmt.Sprint(i)
				if c.First(id, now.Add(time.Minute), now) {
					mu.Lock()
					accepted[id]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	for id, n := range accepted {
		if n != 1 {
			t.Errorf("%s accepted %d times", id, n)
		}
	}
	if len(accepted) != 500 {
		t.Errorf("%d accepted", len(accepted))
	}
}

// Seen asks without remembering, so an identifier looked at and not yet
// acted on can still be remembered, once, after; Full says a new one would
// be refused for want of room, and stops saying so when time makes room.
func TestSeenAsksWithoutRememberingAndFullSaysWhenThereIsNoRoom(t *testing.T) {
	c := &Cache{Max: 2}
	now := time.Unix(1787000000, 0)
	if c.Seen("a", now) {
		t.Fatal("an identifier never given was seen")
	}
	if !c.First("a", now.Add(time.Minute), now) {
		t.Fatal("asking whether it was seen remembered it")
	}
	if !c.Seen("a", now.Add(30*time.Second)) || c.Seen("a", now.Add(2*time.Minute)) {
		t.Error("seen is not while its time lasts")
	}
	if c.Full(now) {
		t.Error("one of two is full")
	}
	c.First("b", now.Add(time.Minute), now)
	if !c.Full(now) {
		t.Error("two of two is not full")
	}
	if c.Full(now.Add(2 * time.Minute)) {
		t.Error("still full after everyone's time was up")
	}
}
