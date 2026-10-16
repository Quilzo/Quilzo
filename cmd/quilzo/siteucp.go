// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/url"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/rate"
	"github.com/quilzo/quilzo/internal/ucp"
)

// ucpCatalogue builds the UCP catalogue from configuration, or says why it
// cannot be served.
//
// Each refusal is a configuration that would look switched on from outside
// and answer nothing useful: no listing to read, a listing that needs an
// argument UCP has no way to give, or an origin a platform would refuse to
// fetch from.
func ucpCatalogue(cfg *config.Config, st *public.Site) (*ucp.Catalog, error) {
	if st.Catalogue == "" || st.Listings == nil || st.Listings.Set == nil {
		return nil, fmt.Errorf("ucp.catalogue is on and no catalogue is served, " +
			"so there is nothing to offer. Name a listing with site.catalogue, " +
			"or turn ucp.catalogue off")
	}
	l, ok := st.Listings.Set.Get(st.Catalogue)
	if !ok {
		return nil, fmt.Errorf("site.catalogue names %q and no listing has that name", st.Catalogue)
	}
	for _, p := range l.Params {
		if p.Default == "" {
			return nil, fmt.Errorf("the catalogue listing %q takes %q with no default; "+
				"a UCP search has no way to give it one, so every answer would be "+
				"empty. Give the parameter a default, or name another listing",
				l.Name, p.Name)
		}
	}
	base, err := ucpBase(st.BaseURL)
	if err != nil {
		return nil, err
	}
	// A tenth of the hour at once: enough for an agent paging through a
	// search, not enough for one address to read the shop in a second.
	perHour := cfg.Int("ucp.requests.per_hour")
	return &ucp.Catalog{
		Base: base,
		// Read on every request, as /catalogue.json is, so a price
		// published a minute ago is the price an agent is told.
		Rows: func(max int) ([]listing.Row, int, error) {
			l, ok := st.Listings.Set.Get(st.Catalogue)
			if !ok {
				return nil, 0, fmt.Errorf("the catalogue listing %q is gone", st.Catalogue)
			}
			idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.At(), l.Collection)
			if err != nil {
				return nil, 0, err
			}
			return listing.Every(l, idx, nil, max)
		},
		Limit: rate.PerHour(perHour, max(perHour/10, 10)),
	}, nil
}

// ucpBase is the origin a UCP profile may name: https, as the spec requires
// of everything a platform fetches, or plain http to this machine for
// trying it out, where there is no certificate to have.
func ucpBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("ucp.catalogue needs the site's own address, as " +
			"https://shop.example with no path: set site.base_url or --base-url. " +
			"Every URL a platform is given is built from it, never from a request")
	}
	if u.Scheme == "https" {
		return "https://" + u.Host, nil
	}
	if u.Scheme == "http" {
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return "http://" + u.Host, nil
		}
	}
	return "", fmt.Errorf("ucp.catalogue needs an https site address; %q is not one. "+
		"Shopping platforms fetch only https, so a profile naming anything else "+
		"is one none of them will read", raw)
}
