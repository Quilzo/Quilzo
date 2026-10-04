// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Guard is the shield as a server consults it on every request: read from
// the store at most once a second, and only again when the file changed,
// so a block set by one process is in force in every other within a
// second and costs nothing to look up.
type Guard struct {
	Root string
	// Key is the audit log's pseudonymisation key, so a request's source
	// gets the same handle the log gave it.
	Key []byte
	// ASN says which provider an address belongs to, when the geo
	// database is loaded; nil otherwise.
	ASN func(netip.Addr) (uint32, bool)

	mu      sync.Mutex
	st      *State
	read    os.FileInfo
	checked time.Time
}

// changed reports whether a file is not the one last read. The time alone
// is not enough: it moves in ticks of a few milliseconds, and two changes
// within one tick have the same. Each change is a new file renamed into
// place, so the file itself differs too, and almost always its size.
func changed(fi, read os.FileInfo) bool {
	return read == nil || !os.SameFile(fi, read) || !fi.ModTime().Equal(read.ModTime()) || fi.Size() != read.Size()
}

func (g *Guard) state(now time.Time) *State {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.st != nil && now.Sub(g.checked) < time.Second {
		return g.st
	}
	g.checked = now
	fi, err := os.Stat(Path(g.Root))
	if err != nil {
		g.st, g.read = &State{}, nil
		return g.st
	}
	if g.st != nil && !changed(fi, g.read) {
		return g.st
	}
	st, err := Load(g.Root)
	if err != nil {
		// A shield that cannot be read protects nothing, and stopping
		// every request because of it would be the attack. It keeps what
		// it last read, and the posture check reports the file.
		if g.st == nil {
			g.st = &State{}
		}
		return g.st
	}
	g.st, g.read = st, fi
	return g.st
}

// Refresh makes the next lookup read the file, for a process that just
// changed it.
func (g *Guard) Refresh() {
	g.mu.Lock()
	g.checked, g.read = time.Time{}, nil
	g.mu.Unlock()
}

// Handle is a source's handle, as the audit log names it.
func (g *Guard) Handle(addr string) string {
	if len(g.Key) == 0 {
		return ""
	}
	return audit.Pseudonym(g.Key, addr)
}

// trusted reports addresses that are never blocked: this machine and the
// declared networks.
func trusted(st *State, a netip.Addr) bool {
	if a.IsLoopback() {
		return true
	}
	for _, t := range st.Trusted {
		if p, err := netip.ParsePrefix(t); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// Blocked reports the block, if any, on a request from addr to where
// (Admin or Site).
func (g *Guard) Blocked(addr, where string, now time.Time) (Protection, bool) {
	st := g.state(now)
	if len(st.Protections) == 0 {
		return Protection{}, false
	}
	a, err := netip.ParseAddr(strings.Trim(addr, "[]"))
	if err != nil {
		return Protection{}, false
	}
	a = a.Unmap()
	if trusted(st, a) {
		return Protection{}, false
	}
	handle := ""
	asn := ""
	for _, p := range st.Protections {
		if p.Kind != Block || !p.ActiveAt(now) || (p.Where != All && p.Where != where) {
			continue
		}
		kind, value, _ := strings.Cut(p.Target, ":")
		switch kind {
		case "source":
			if handle == "" {
				handle = g.Handle(a.String())
			}
			if handle != "" && handle == value {
				return p, true
			}
		case "net":
			if pfx, err := netip.ParsePrefix(value); err == nil && pfx.Contains(a) {
				return p, true
			}
		case "asn":
			if g.ASN == nil {
				continue
			}
			if asn == "" {
				if n, ok := g.ASN(a); ok {
					asn = strconv.FormatUint(uint64(n), 10)
				} else {
					asn = "-"
				}
			}
			if asn == value {
				return p, true
			}
		}
	}
	return Protection{}, false
}

// Feature reports the shield on a feature: on "chatbot:NAME" it finds one
// on that chatbot or on every chatbot, and the same for forms.
func (g *Guard) Feature(target string, now time.Time) (Protection, bool) {
	st := g.state(now)
	name, _, _ := strings.Cut(target, ":")
	every := map[string]string{"chatbot": "chatbots", "form": "forms"}[name]
	var found Protection
	ok := false
	for _, p := range st.Protections {
		if p.Kind != Feature || !p.ActiveAt(now) {
			continue
		}
		if p.Target == target || (every != "" && p.Target == every) {
			// Off outranks limited, whichever was set first.
			if !ok || p.Level == Off {
				found, ok = p, true
			}
		}
	}
	return found, ok
}

func (g *Guard) only(kind, target string, now time.Time) (Protection, bool) {
	for _, p := range g.state(now).Protections {
		if p.Kind == kind && p.Target == target && p.ActiveAt(now) {
			return p, true
		}
	}
	return Protection{}, false
}

// Lockdown reports whether the admin is locked down.
func (g *Guard) Lockdown(now time.Time) (Protection, bool) { return g.only(Lockdown, "", now) }

// Frozen reports whether publishing is frozen.
func (g *Guard) Frozen(now time.Time) (Protection, bool) { return g.only(Freeze, "", now) }

// AgentPaused reports whether an agent is paused.
func (g *Guard) AgentPaused(name string, now time.Time) (Protection, bool) {
	return g.only(Agent, name, now)
}

// Active is everything in force, for a screen.
func (g *Guard) Active(now time.Time) []Protection { return g.state(now).Active(now) }
