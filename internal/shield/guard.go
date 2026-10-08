// SPDX-FileCopyrightText: 2026 Rashik Adhikari
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
	"github.com/quilzo/quilzo/internal/clientip"
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
	ix      *index
	read    os.FileInfo
	checked time.Time

	slow limiter
}

// index is the protections that refuse or slow a request, by what they
// match: a request costs a few map lookups, not a pass over every
// protection, however many are in force.
type index struct {
	src  map[string][]int
	net  map[int]map[netip.Prefix][]int
	asn  map[string][]int
	bits []int
}

func compile(st *State) *index {
	ix := &index{src: map[string][]int{}, net: map[int]map[netip.Prefix][]int{}, asn: map[string][]int{}}
	for i, p := range st.Protections {
		if p.Kind != Block && p.Kind != Slow {
			continue
		}
		kind, value, _ := strings.Cut(p.Target, ":")
		switch kind {
		case "source":
			ix.src[value] = append(ix.src[value], i)
		case "net":
			pfx, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			pfx = pfx.Masked()
			if ix.net[pfx.Bits()] == nil {
				ix.net[pfx.Bits()] = map[netip.Prefix][]int{}
				ix.bits = append(ix.bits, pfx.Bits())
			}
			ix.net[pfx.Bits()][pfx] = append(ix.net[pfx.Bits()][pfx], i)
		case "asn":
			ix.asn[value] = append(ix.asn[value], i)
		}
	}
	return ix
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
		g.st, g.ix, g.read = &State{}, compile(&State{}), nil
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
			g.st, g.ix = &State{}, compile(&State{})
		}
		return g.st
	}
	g.st, g.ix, g.read = st, compile(st), fi
	return g.st
}

// snapshot is the state and its index, read together.
func (g *Guard) snapshot(now time.Time) (*State, *index) {
	st := g.state(now)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ix == nil || g.st != st {
		g.ix = compile(st)
	}
	return st, g.ix
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

// Handles are the handles an address may have in the audit log: its
// source (one IPv4 address, or an IPv6 /64; clientip.Source), which is what
// is recorded now, and for IPv6 the single address with and without
// brackets, which older entries hold, so a block taken from any of them
// holds.
func (g *Guard) Handles(a netip.Addr) []string {
	if len(g.Key) == 0 || !a.IsValid() {
		return []string{}
	}
	a = a.Unmap()
	out := []string{g.Handle(clientip.Source(a))}
	if a.Is6() {
		out = append(out, g.Handle(a.String()), g.Handle("["+a.String()+"]"))
	}
	return out
}

// trusted reports addresses that are never blocked: anything on the inside
// (this machine, private networks, carrier-grade NAT) and the declared
// networks.
func trusted(st *State, a netip.Addr) bool {
	if clientip.Local(a) {
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
	return g.match(Block, addr, where, now)
}

// Slowed reports the slowing, if any, on a request from addr to where.
func (g *Guard) Slowed(addr, where string, now time.Time) (Protection, bool) {
	return g.match(Slow, addr, where, now)
}

func (g *Guard) match(kind, addr, where string, now time.Time) (Protection, bool) {
	st, ix := g.snapshot(now)
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
	var cands []int
	if len(ix.src) > 0 {
		for _, h := range g.Handles(a) {
			cands = append(cands, ix.src[h]...)
		}
	}
	for _, bits := range ix.bits {
		if pfx, err := a.Prefix(bits); err == nil {
			cands = append(cands, ix.net[bits][pfx]...)
		}
	}
	if len(ix.asn) > 0 && g.ASN != nil {
		if n, ok := g.ASN(a); ok {
			cands = append(cands, ix.asn[strconv.FormatUint(uint64(n), 10)]...)
		}
	}
	vouched := -1 // not looked up yet
	for _, i := range cands {
		p := st.Protections[i]
		if p.Kind != kind || !p.ActiveAt(now) || (p.Where != All && p.Where != where) {
			continue
		}
		// An administrator who signed in strongly from here keeps the
		// admin whatever a playbook did, to a network or a provider as
		// well as the source; only a person can keep them out of it.
		if p.Auto && where == Admin {
			if vouched < 0 {
				vouched = 0
				if st.IsVouched(g.Handles(a), now) {
					vouched = 1
				}
			}
			if vouched == 1 {
				continue
			}
		}
		return p, true
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

// Suspended reports a token, or the token a session was exchanged from,
// that the shield has suspended.
func (g *Guard) Suspended(id string, now time.Time) (Protection, bool) {
	return g.only(Token, id, now)
}

// AgentPaused reports whether an agent is paused.
func (g *Guard) AgentPaused(name string, now time.Time) (Protection, bool) {
	return g.only(Agent, name, now)
}

// State is the record as this guard last read it, for a host that needs
// more than one answer from it.
func (g *Guard) State(now time.Time) *State { return g.state(now) }

// Active is everything in force, for a screen.
func (g *Guard) Active(now time.Time) []Protection { return g.state(now).Active(now) }
