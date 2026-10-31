// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
)

// edge decides who each request on one surface came from, once, for
// everything behind it (internal/clientip), and says on standard error
// which machine on the network forwarded an address that was not believed.
func edge(root, local string, next http.Handler) http.Handler {
	resolve := proxies(root, local)
	return clientip.Middleware(resolve, unbelieved(local, resolve, os.Stderr, next))
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

// maxUnbelieved is how many different machines unbelieved names, so a
// network full of callers writing the header cannot fill the log.
const maxUnbelieved = 16

// unbelieved says, the first time it sees each one, a machine on the
// network that sent X-Forwarded-For and was not believed because only a
// proxy on this machine is assumed, and how to name it if it is the proxy
// in front. Without this, behind such a proxy every visitor is the proxy,
// every limit one bucket for all of them, and nothing says why.
//
// Only while the proxy is assumed: a deployment that names its proxies
// has said which they are, and one that says nothing has no proxy, so a
// header from anywhere else is somebody writing their own.
func unbelieved(local string, resolve func() *clientip.Resolver, to io.Writer, next http.Handler) http.Handler {
	var (
		mu   sync.Mutex
		said = map[netip.Addr]bool{}
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A peer the resolver believed reads as Forwarded; one it did not,
		// with the header, as the connection.
		c := clientip.FromRequest(r)
		if c.Via == clientip.Connection && clientip.Local(c.Peer) &&
			len(r.Header.Values("X-Forwarded-For")) > 0 {
			if res := resolve(); res != nil && res.Assumed {
				mu.Lock()
				first := !said[c.Peer] && len(said) < maxUnbelieved
				if first {
					said[c.Peer] = true
				}
				mu.Unlock()
				// The list is one for both surfaces, and naming anything in
				// it ends the assumption for both, so the hint says so
				// before it is followed rather than leaving a proxy on this
				// machine to stop being believed without a word.
				if first {
					fmt.Fprintf(to, "  %s%s sent X-Forwarded-For and is not believed: %s believes "+
						"a proxy on this machine only. If %s is the proxy in front, name it. Naming "+
						"any proxy ends that for the site and the admin both, so a proxy on this "+
						"machine is then believed only if it is named too:%s\n"+
						"      quilzo config set network.trusted_proxies %s\n",
						yellow, c.Peer, local, c.Peer, reset, c.Peer)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
