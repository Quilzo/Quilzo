// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package rate is a steady rate with room for a burst, per key.
//
// The sign-in throttle is the wrong shape for anything a person does on
// purpose and often: it counts failures and makes each one wait longer
// than the last, which is right for somebody guessing a token and wrong
// for somebody asking a chatbot their sixth question. This is the shape a
// conversation needs — a burst at once, then a steady pace — as the
// generic cell rate algorithm keeps it: one number per key, the time the
// key's budget is next whole, so nothing is stored per request and nothing
// sleeps.
package rate

import (
	"sync"
	"time"
)

// Limiter gives each key a burst and a steady rate.
type Limiter struct {
	// Every is the steady rate: one unit per Every.
	Every time.Duration
	// Burst is how many units may be spent at once.
	Burst int
	// MaxKeys bounds memory: past it, keys whose budget is whole again are
	// forgotten first, which loses nothing, then any.
	MaxKeys int

	mu  sync.Mutex
	tat map[string]time.Time
}

// PerHour is a limiter allowing n an hour on average and burst at once.
func PerHour(n, burst int) *Limiter {
	if n < 1 {
		n = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{Every: time.Hour / time.Duration(n), Burst: burst, MaxKeys: 65536}
}

// Allow spends one unit for key, or says how long until one is free.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tat == nil {
		l.tat = map[string]time.Time{}
	}
	t, ok := l.tat[key]
	if !ok || t.Before(now) {
		t = now
	}
	next := t.Add(l.Every)
	if at := next.Add(-time.Duration(l.Burst) * l.Every); at.After(now) {
		return false, at.Sub(now)
	}
	if !ok && l.MaxKeys > 0 && len(l.tat) >= l.MaxKeys {
		for k, v := range l.tat {
			if !v.After(now) {
				delete(l.tat, k)
			}
		}
		for k := range l.tat {
			if len(l.tat) < l.MaxKeys {
				break
			}
			delete(l.tat, k)
		}
	}
	l.tat[key] = next
	return true, 0
}
