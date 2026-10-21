// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package lockout is smart lockout: failures that belong to an account
// lock out the places they come from, not the person.
//
// A hard lockout (so many failures and the account stops) is a denial of
// service anybody can aim at anybody whose name they know. So, as Microsoft
// Entra's smart lockout and Okta's unknown-device lockout do, failures from
// places an account has never signed in from successfully are counted on
// their own: past Threshold, those places are locked out of that account
// for LockFor, doubling each time it happens again up to MaxLock, while the
// places the person really signs in from keep working. That meets PCI DSS
// 8.3.4's numbers for whoever is guessing (no more than ten attempts, then
// at least thirty minutes) without handing them the account's owner.
//
// Underneath, NIST SP 800-63B-4 3.2.2's ceiling: Ceiling consecutive
// failures on one account, from anywhere, disables the method they were
// made with until the person proves themselves another way or an
// administrator lets it work again.
//
// The record is a file, shared by every process that serves the store and
// kept across restarts, so a restart does not hand a guesser a fresh count.
// It holds account names and the networks people sign in from, which
// identify people; it is kept beside the token store, as private as that.
package lockout

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// The numbers. Threshold and LockFor are PCI DSS 8.3.4's; Ceiling is NIST
// SP 800-63B-4's upper bound; MaxLock stops the doubling at a day.
const (
	Threshold = 10
	LockFor   = 30 * time.Minute
	MaxLock   = 24 * time.Hour
	Ceiling   = 100
	// MaxPlaces is how many familiar places an account keeps; the oldest
	// goes first.
	MaxPlaces = 16
)

// Place is a network an account has signed in from: an IPv4 /24 or an
// IPv6 /48, so a laptop moving between addresses on one network stays
// familiar, and the record holds no exact address.
type Place struct {
	Network string    `json:"network"`
	Seen    time.Time `json:"seen"`
}

// Account is one account's record.
type Account struct {
	Name     string  `json:"name"`
	Familiar []Place `json:"familiar,omitempty"`
	// Consecutive is every failure since the last success, from anywhere.
	Consecutive int `json:"consecutive,omitempty"`
	// Strange counts failures from unfamiliar places since the last
	// lockout of them; LockedUntil is when that lockout ends, and Strikes
	// how many there have been, which doubles the next one.
	Strange     int       `json:"strange,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitzero"`
	Strikes     int       `json:"strikes,omitempty"`
	// Disabled is when Ceiling was reached; zero while it has not been.
	Disabled time.Time `json:"disabled,omitzero"`
	// Since is how many failures there were before the last success, for
	// the person to be told once.
	Since int `json:"since,omitempty"`
}

type file struct {
	Accounts []Account `json:"accounts"`
}

// Store is the record, in one file.
type Store struct {
	Path string
}

// Decision is whether an attempt on an account may go ahead, from where.
type Decision struct {
	Allowed bool
	// RetryAfter is how long until a locked-out place may try again; zero
	// for a disabled account, which waits for a person.
	RetryAfter time.Duration
	// Disabled says the ceiling was reached.
	Disabled bool
	Why      string
}

// Event is what a failure changed, for the record and the automations.
type Event string

const (
	// NoEvent is a failure that changed nothing anybody needs to hear.
	NoEvent Event = ""
	// Locked is unfamiliar places locked out of an account.
	Locked Event = "locked"
	// Disabled is the ceiling reached.
	Disabled Event = "disabled"
)

// PlaceOf is the network an address belongs to, or "" when it is not one.
func PlaceOf(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
}

func (a *Account) familiar(place string) bool {
	for _, p := range a.Familiar {
		if p.Network == place {
			return true
		}
	}
	return false
}

func decide(a Account, place string, now time.Time) Decision {
	if !a.Disabled.IsZero() {
		return Decision{Disabled: true, Why: fmt.Sprintf("%d failed sign-ins in a row on this account, so signing in "+
			"to it this way is off until you sign in another way or an administrator turns it back on", Ceiling)}
	}
	if place != "" && !a.familiar(place) && now.Before(a.LockedUntil) {
		wait := a.LockedUntil.Sub(now)
		return Decision{RetryAfter: wait, Why: fmt.Sprintf("too many failed sign-ins on this account from places it "+
			"is not used from, so they are locked out of it for %s", wait.Round(time.Minute))}
	}
	return Decision{Allowed: true}
}

// Check is whether an attempt on name from addr may go ahead. It records
// nothing.
func (s Store) Check(name, addr string, now time.Time) (Decision, error) {
	var d Decision
	err := atomicfile.Update(s.Path, func(f *file) error {
		d = Decision{Allowed: true}
		if a := find(f, name); a != nil {
			d = decide(*a, PlaceOf(addr), now)
		}
		return atomicfile.ErrUnchanged
	})
	return d, err
}

// Fail records a failed attempt on name from addr, and says what it changed.
func (s Store) Fail(name, addr string, now time.Time) (Decision, Event, error) {
	var d Decision
	ev := NoEvent
	err := atomicfile.Update(s.Path, func(f *file) error {
		a := find(f, name)
		if a == nil {
			f.Accounts = append(f.Accounts, Account{Name: name})
			a = &f.Accounts[len(f.Accounts)-1]
		}
		place := PlaceOf(addr)
		a.Consecutive++
		if a.Consecutive >= Ceiling && a.Disabled.IsZero() {
			a.Disabled, ev = now.UTC(), Disabled
		}
		if place == "" || !a.familiar(place) {
			a.Strange++
			if a.Strange >= Threshold && ev == NoEvent {
				lock := LockFor << min(a.Strikes, 10)
				if lock > MaxLock || lock <= 0 {
					lock = MaxLock
				}
				a.LockedUntil, a.Strikes, a.Strange, ev = now.UTC().Add(lock), a.Strikes+1, 0, Locked
			}
		}
		d = decide(*a, place, now)
		return nil
	})
	return d, ev, err
}

// Succeed records a sign-in that worked: the count starts again, the place
// becomes familiar, and how many failures came before is returned once, to
// be told to the person.
func (s Store) Succeed(name, addr string, now time.Time) (int, error) {
	since := 0
	err := atomicfile.Update(s.Path, func(f *file) error {
		a := find(f, name)
		if a == nil {
			f.Accounts = append(f.Accounts, Account{Name: name})
			a = &f.Accounts[len(f.Accounts)-1]
		}
		since = a.Consecutive + a.Since
		a.Consecutive, a.Strange, a.Since = 0, 0, 0
		if place := PlaceOf(addr); place != "" {
			kept := []Place{{Network: place, Seen: now.UTC()}}
			for _, p := range a.Familiar {
				if p.Network != place {
					kept = append(kept, p)
				}
			}
			if len(kept) > MaxPlaces {
				kept = kept[:MaxPlaces]
			}
			a.Familiar = kept
		}
		return nil
	})
	return since, err
}

// Unlock lets an account work again from everywhere: the ceiling, the
// lockout of unfamiliar places and the counts are cleared, and the
// failures are kept to be told to the person when they next sign in. It
// reports whether the account was held.
func (s Store) Unlock(name string, now time.Time) (bool, error) {
	found := false
	err := atomicfile.Update(s.Path, func(f *file) error {
		a := find(f, name)
		if a == nil || (a.Disabled.IsZero() && !now.Before(a.LockedUntil)) {
			return atomicfile.ErrUnchanged
		}
		found = true
		a.Since += a.Consecutive
		a.Consecutive, a.Strange, a.Strikes = 0, 0, 0
		a.LockedUntil, a.Disabled = time.Time{}, time.Time{}
		return nil
	})
	return found, err
}

// Held are the accounts locked out from somewhere, or disabled, now.
func (s Store) Held(now time.Time) ([]Account, error) {
	var out []Account
	err := atomicfile.Update(s.Path, func(f *file) error {
		for _, a := range f.Accounts {
			if !a.Disabled.IsZero() || now.Before(a.LockedUntil) {
				out = append(out, a)
			}
		}
		return atomicfile.ErrUnchanged
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

func find(f *file, name string) *Account {
	for i := range f.Accounts {
		if strings.EqualFold(f.Accounts[i].Name, name) {
			return &f.Accounts[i]
		}
	}
	return nil
}
