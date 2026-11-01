// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
)

// edge decides who each request on one surface came from, once, for
// everything behind it (internal/clientip), and says on standard error and
// in the audit log which machine forwarded addresses that were not
// believed (forwarders).
func edge(root, local string, next http.Handler) http.Handler {
	return edgeTo(root, local, os.Stderr, next)
}

// edgeTo is edge, saying what it finds on to.
func edgeTo(root, local string, to io.Writer, next http.Handler) http.Handler {
	resolve := proxies(root, local)
	return clientip.Middleware(resolve, newForwarders(root, local, resolve, to).watch(next))
}

// proxies is the resolver a surface decides clients with, as the
// configuration says: re-read at most once a second, so naming a proxy
// takes effect without a restart. local is the surface's own yes/no
// setting that its proxy is on this machine (site.trusted_proxy,
// admin.trusted_proxy).
//
// A configuration that cannot be read believes no proxy, and keeps what it
// last read if it read one: the direction that fails is "every limit keys on
// the proxy", which is the old behaviour, never "every caller chooses".
func proxies(root, local string) func() *clientip.Resolver {
	var (
		mu  sync.Mutex
		at  time.Time
		cur *clientip.Resolver
	)
	return func() *clientip.Resolver {
		mu.Lock()
		defer mu.Unlock()
		if cur != nil && time.Since(at) < time.Second {
			return cur
		}
		at = time.Now()
		cfg, err := loadConfig(root)
		if err != nil {
			if cur == nil {
				cur = &clientip.Resolver{}
			}
			return cur
		}
		cur = resolverFrom(cfg, local)
		return cur
	}
}

// resolverFrom is the resolver one configuration describes. Named proxies
// are the ones believed. With none named, the surface's own setting
// assumes one on this machine, on loopback, and nowhere else: a private
// network, a container bridge or carrier-grade NAT is a place, and whatever
// else is there can write X-Forwarded-For as well as the proxy can.
func resolverFrom(cfg *config.Config, local string) *clientip.Resolver {
	ps, err := clientip.ParseProxies(cfg.Strings("network.trusted_proxies"))
	if err != nil {
		return &clientip.Resolver{}
	}
	if len(ps) == 0 && cfg.Bool(local) {
		return &clientip.Resolver{Proxies: clientip.Loopback(), Assumed: true}
	}
	return &clientip.Resolver{Proxies: ps}
}

// assumedProxy is the line a surface starts with when its proxy is assumed
// rather than named: whom it believes, and what a proxy anywhere else
// needs. Empty when proxies are named or none is said to be there.
func assumedProxy(root, local string) string {
	cfg, err := loadConfig(root)
	if err != nil || !resolverFrom(cfg, local).Assumed {
		return ""
	}
	return "a forwarded address is believed from this machine only (" + local +
		"); name a proxy anywhere else in network.trusted_proxies"
}

// Machines that forward and are not believed.
//
// A machine that is not a named proxy is the client, whatever it says it
// forwards (internal/clientip). When it is in fact the proxy or CDN in
// front, every visitor behind it is its address: one bucket for every
// limit, and a block on it a block on all of them. No one request tells
// which, and a header that made the shield hold back would be a way past
// it, so the edge watches what each machine forwards over time, and says
// once of each it finds what it saw and the command that names it: on
// standard error, with the address, and in the audit log
// (shield.unnamed-proxy), under the handle the shield blocks it by. It
// finds
//
//   - a machine that forwards manyDifferent different values within
//     forwardWindow, however proxies are configured; and
//   - while a proxy is only assumed on this machine (site.trusted_proxy,
//     admin.trusted_proxy), a machine on the network that sends
//     X-Forwarded-For at all: the proxy in front may be there, and is
//     believed only when named, so its first request is enough.
//
// What a machine it reported sends carries a mark (unnamedProxy), so a
// block on it says that it may be holding everybody behind it, and an
// administrator signing in through it vouches for nobody behind it. Nothing
// holds back for it: a mark anybody could earn by writing headers is not a
// reason to block anybody less.
const (
	// One client writing its own header sends one value, or a few while
	// somebody tests by hand; eight different ones is eight people behind
	// one machine. Within an hour rather than minutes, so the proxy in
	// front of a quiet site, a visitor every few minutes, is still found.
	// What it says ("within an hour") is written to match.
	manyDifferent = 8
	forwardWindow = time.Hour
	// maxWatched is how many machines are watched at once; past it, the one
	// heard from longest ago is forgotten. Each holds at most manyDifferent
	// digests, so neither a flood of machines nor one of values grows
	// anything.
	maxWatched = 256
	// maxReported is how many machines one process ever names, so a
	// network full of callers writing the header cannot fill the log.
	maxReported = 16
)

type forwarders struct {
	root, local string
	resolve     func() *clientip.Resolver
	to          io.Writer
	now         func() time.Time
	seed        maphash.Seed

	// any is set once a machine is reported: until then a request that
	// forwards nothing has nothing to look up.
	any atomic.Bool

	mu       sync.Mutex
	watched  map[netip.Addr]*watched
	reported map[netip.Addr]bool
}

// watched is what one machine forwarded lately: a digest of each different
// value (clientip.Claim), with when it was last sent.
type watched struct {
	heard time.Time
	seen  []sighting
}

type sighting struct {
	digest uint64
	at     time.Time
}

func newForwarders(root, local string, resolve func() *clientip.Resolver, to io.Writer) *forwarders {
	return &forwarders{root: root, local: local, resolve: resolve, to: to, now: time.Now,
		seed: maphash.MakeSeed(), watched: map[netip.Addr]*watched{}, reported: map[netip.Addr]bool{}}
}

type unnamedProxyKey struct{}

// unnamedProxy reports whether a request came from a machine the edge
// reported as probably a proxy nobody named.
func unnamedProxy(r *http.Request) bool {
	v, _ := r.Context().Value(unnamedProxyKey{}).(bool)
	return v
}

func (f *forwarders) watch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A peer the resolver believed reads as Forwarded, and its client
		// is somebody else; one it did not, as the connection. A named
		// proxy's own request reads as the connection too, and is not
		// counted: it has been named.
		c := clientip.FromRequest(r)
		if c.Via == clientip.Connection && c.Peer.IsValid() {
			digest, forwards := clientip.Claim(r, f.seed)
			if forwards || f.any.Load() {
				if res := f.resolve(); !res.Trusts(c.Peer) && f.saw(c.Peer, digest, forwards, r, res) {
					r = r.WithContext(context.WithValue(r.Context(), unnamedProxyKey{}, true))
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// saw counts what a machine that is not believed forwarded, reports it
// when it is found, and says whether it has been.
func (f *forwarders) saw(peer netip.Addr, digest uint64, forwards bool, r *http.Request, res *clientip.Resolver) bool {
	f.mu.Lock()
	if f.reported[peer] {
		f.mu.Unlock()
		return true
	}
	if !forwards || len(f.reported) >= maxReported {
		f.mu.Unlock()
		return false
	}
	n := 0
	assumed := res != nil && res.Assumed && clientip.Local(peer) && len(r.Header.Values("X-Forwarded-For")) > 0
	if !assumed {
		if n = f.count(peer, digest, f.now()); n < manyDifferent {
			f.mu.Unlock()
			return false
		}
	}
	f.reported[peer] = true
	delete(f.watched, peer)
	f.any.Store(true)
	f.mu.Unlock()
	f.report(peer, n, res)
	return true
}

// count adds a value to what a machine forwarded, forgetting what is older
// than the window, and answers how many different ones it holds.
func (f *forwarders) count(peer netip.Addr, digest uint64, now time.Time) int {
	wt := f.watched[peer]
	if wt == nil {
		if len(f.watched) >= maxWatched {
			var oldest netip.Addr
			for a, x := range f.watched {
				if !oldest.IsValid() || x.heard.Before(f.watched[oldest].heard) {
					oldest = a
				}
			}
			delete(f.watched, oldest)
		}
		wt = &watched{}
		f.watched[peer] = wt
	}
	wt.heard = now
	kept, fresh := wt.seen[:0], true
	for _, s := range wt.seen {
		if now.Sub(s.at) >= forwardWindow {
			continue
		}
		if s.digest == digest {
			s.at, fresh = now, false
		}
		kept = append(kept, s)
	}
	if fresh && len(kept) < manyDifferent {
		kept = append(kept, sighting{digest, now})
	}
	wt.seen = kept
	return len(kept)
}

// report says once what was found of a machine: on standard error with its
// address and the command whole, and in the audit log under the handle the
// shield would block it by, which keeps its address out of the log as every
// source's is. n is how many different values it forwarded; none for a
// machine found by its first X-Forwarded-For while a proxy is assumed.
func (f *forwarders) report(peer netip.Addr, n int, res *clientip.Resolver) {
	var said, seen string
	switch {
	case n == 0:
		said = fmt.Sprintf("%s sent X-Forwarded-For and is not believed: %s believes a proxy on this machine only.",
			peer, f.local)
		seen = "sent X-Forwarded-For while " + f.local + " believes a proxy on this machine only"
	default:
		held := "a block on it is a block on all of them"
		if clientip.ThisMachine(peer) {
			held = "the shield blocks none of them"
		}
		said = fmt.Sprintf("%s forwarded %d different addresses within an hour and is not believed, so every "+
			"visitor behind it is %s: one bucket for every limit, and %s.", peer, n, peer, held)
		seen = fmt.Sprintf("forwarded %d different addresses within an hour", n)
	}
	how, command, fix := nameIt(f.local, res, peer)
	fmt.Fprintf(f.to, "  %s%s If %s is the proxy in front, %s:%s\n      %s\n", yellow, said, peer, how, reset, command)
	// Denied, as the site's own signals are: what it sent was not believed.
	record(f.root, audit.Record{Action: "shield.unnamed-proxy", Resource: "/", Outcome: audit.Denied,
		Principal: clientip.Source(peer), Kind: audit.KindUnknown,
		Detail: map[string]string{"surface": strings.TrimSuffix(f.local, ".trusted_proxy"), "seen": seen, "fix": fix}})
}

// nameIt is how a machine that forwards is made the proxy that is
// believed, as the configuration stands: in words, as the command, and as
// a fix with no address in it, for the audit log. The list is replaced
// whole by config set, so the command keeps the proxies already named.
func nameIt(local string, res *clientip.Resolver, peer netip.Addr) (how, command, fix string) {
	var named []string
	if res != nil && !res.Assumed {
		for _, p := range res.Proxies {
			if p.IsSingleIP() {
				named = append(named, p.Addr().String())
			} else {
				named = append(named, p.String())
			}
		}
	}
	switch {
	case len(named) == 0 && clientip.ThisMachine(peer):
		// A proxy on this machine is believed by the surface's own setting;
		// naming it would let any program here choose its address on the
		// site and the admin both.
		return "turn " + local + " on", "quilzo config set " + local + " true",
			"turn " + local + " on, if it is the proxy in front"
	case len(named) == 0:
		// The list is one for both surfaces, and naming anything in it ends
		// the assumption for both, so the hint says so before it is
		// followed rather than leaving a proxy on this machine to stop
		// being believed without a word.
		return "name it. Naming any proxy ends the assumption that one is on this machine, for the site " +
				"and the admin both, so a proxy there is then believed only if it is named too",
			"quilzo config set network.trusted_proxies " + peer.String(),
			"name it in network.trusted_proxies, if it is the proxy in front"
	}
	how = "name it with the others"
	if clientip.ThisMachine(peer) {
		how += ", though naming this machine lets any program on it choose its address on the site and the admin both"
	}
	return how, "quilzo config set network.trusted_proxies " + strings.Join(append(named, peer.String()), ","),
		"name it in network.trusted_proxies with the others, if it is the proxy in front"
}
