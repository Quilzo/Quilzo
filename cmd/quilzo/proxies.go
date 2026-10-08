// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
)

// proxies is the resolver a surface decides clients with, as the
// configuration says: re-read at most once a second, so naming a proxy
// takes effect without a restart. inside is the surface's own yes/no
// setting (site.trusted_proxy, admin.trusted_proxy).
//
// A configuration that cannot be read believes no proxy, and keeps what it
// last read if it read one: the direction that fails is "every limit keys on
// the proxy", which is the old behaviour, never "every caller chooses".
func proxies(root, inside string) func() *clientip.Resolver {
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
		cur = resolverFrom(cfg, inside)
		return cur
	}
}

// resolverFrom is the resolver one configuration describes.
func resolverFrom(cfg *config.Config, inside string) *clientip.Resolver {
	ps, err := clientip.ParseProxies(cfg.Strings("network.trusted_proxies"))
	if err != nil {
		return &clientip.Resolver{}
	}
	if len(ps) == 0 && cfg.Bool(inside) {
		return &clientip.Resolver{Proxies: clientip.Inside(), Assumed: true}
	}
	return &clientip.Resolver{Proxies: ps}
}
