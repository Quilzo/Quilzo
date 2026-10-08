// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package geo says roughly where an address is: which city and country,
// and the coordinates of that city.
//
// # Two sources, in this order
//
// Networks the organisation names itself come first: its offices, and its
// VPN's exit addresses. An office is a place it knows exactly; a VPN is a
// place it knows nothing about, because everybody on it appears to be
// wherever the provider's server is, and treating that as a location is
// the commonest false alarm impossible-travel detection raises. So a VPN
// network is a place of kind "vpn", which travel checks leave out.
//
// Then a city database in the MaxMind DB format: DB-IP's IP to City Lite,
// published monthly under Creative Commons Attribution 4.0, which a person
// downloads (quilzo geo fetch) — this package never fetches anything, and a
// lookup never leaves the machine, so no third party learns who signed in
// from where.
//
// A city-level guess for a residential or mobile address is often wrong
// by a region, sometimes by more, which is why the travel checks want a
// large distance as well as a high speed before they call it impossible.
package geo

import (
	"math"
	"net/netip"
	"strings"
)

// Place is where an address appears to be.
type Place struct {
	City    string  `json:"city,omitempty"`
	Region  string  `json:"region,omitempty"`
	Country string  `json:"country,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	// Network is the name of a network the organisation declared, when the
	// address is in one, and Kind what it is: "office" or "vpn".
	Network string `json:"network,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// Known reports whether there is anything to say.
func (p Place) Known() bool { return p.Country != "" || p.Network != "" }

// HasCoordinates reports whether a distance can be measured from it.
func (p Place) HasCoordinates() bool { return p.Lat != 0 || p.Lon != 0 }

// String is the place as somebody says it: "Sydney, AU".
func (p Place) String() string {
	var parts []string
	for _, s := range []string{p.City, p.Country} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	out := strings.Join(parts, ", ")
	if p.Network != "" {
		if out == "" {
			return p.Network
		}
		return p.Network + " (" + out + ")"
	}
	if out == "" {
		return "unknown"
	}
	return out
}

// Network is a range the organisation names.
type Network struct {
	Prefix string `json:"prefix"`
	Place
}

// Locator answers where an address is.
type Locator struct {
	Networks []Network
	DB       *DB
	// ASNDB is the network database and Tor the exit list; both optional.
	ASNDB *DB
	Tor   map[string]bool
}

// Locate finds an address, or reports that nothing is known.
func (l *Locator) Locate(addr string) (Place, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return Place{}, false
	}
	ip = ip.Unmap()
	// The most specific declared network wins.
	best, bits := Place{}, -1
	for _, n := range l.Networks {
		pfx, err := netip.ParsePrefix(n.Prefix)
		if err != nil || !pfx.Contains(ip) {
			continue
		}
		if pfx.Bits() > bits {
			// A range given a place and no name is just that place.
			best, bits = n.Place, pfx.Bits()
		}
	}
	if bits >= 0 {
		return best, true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return Place{}, false
	}
	if l.DB == nil {
		return Place{}, false
	}
	rec, err := l.DB.Lookup(ip)
	if err != nil || rec == nil {
		return Place{}, false
	}
	p := Place{}
	p.City = name(rec["city"])
	if c, ok := rec["country"].(map[string]any); ok {
		p.Country, _ = c["iso_code"].(string)
	}
	if subs, ok := rec["subdivisions"].([]any); ok && len(subs) > 0 {
		p.Region = name(subs[0])
	}
	if loc, ok := rec["location"].(map[string]any); ok {
		p.Lat, _ = loc["latitude"].(float64)
		p.Lon, _ = loc["longitude"].(float64)
	}
	return p, p.Known()
}

func name(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	names, ok := m["names"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := names["en"].(string)
	return s
}

// Km is the great-circle distance between two places, by the haversine
// formula on a sphere of the Earth's mean radius.
func Km(a, b Place) float64 {
	const r = 6371.0088
	rad := math.Pi / 180
	dlat, dlon := (b.Lat-a.Lat)*rad, (b.Lon-a.Lon)*rad
	h := math.Sin(dlat/2)*math.Sin(dlat/2) +
		math.Cos(a.Lat*rad)*math.Cos(b.Lat*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(h)))
}

// Network facts: which autonomous system an address belongs to, who runs
// it, and whether it is Tor or a hosting provider's.
//
// The ASN comes from a second MMDB file in GeoLite2-ASN's shape (DB-IP's
// ASN Lite is one, under CC BY 4.0). Tor exits come from the Tor Project's
// bulk exit list, a file of addresses. Hosting is judged from the name of
// whoever runs the network: the clouds and server renters a person does
// not sign in from, and phishing proxies and scripts do — an
// attacker-in-the-middle kit relays the victim's sign-in from a rented
// server. A company's own VPN or office on such a network is declared as
// such, and declared networks are never called hosting.

// NetInfo is what is known about an address's network.
type NetInfo struct {
	ASN  uint32
	Org  string
	Anon string // "tor", "hosting", or empty
}

// hostingNames are fragments of the names hosting providers' networks go
// by. Lower case; matched as substrings of the organisation name.
var hostingNames = []string{
	"amazon", "aws", "google cloud", "google llc", "microsoft corporation", "azure",
	"digitalocean", "linode", "akamai connected cloud", "vultr", "choopa", "ovh",
	"hetzner", "contabo", "scaleway", "online s.a.s", "leaseweb", "m247", "datacamp",
	"hostinger", "ionos", "oracle", "alibaba", "tencent", "kamatera", "upcloud",
	"hostwinds", "colocrossing", "psychz", "quadranet", "servers.com", "g-core",
	"cloudflare", "fastly", "zenlayer", "sharktech", "frantech", "buyvm",
}

// Hosting reports whether a network's name is a hosting provider's.
func Hosting(org string) bool {
	o := strings.ToLower(org)
	for _, h := range hostingNames {
		if strings.Contains(o, h) {
			return true
		}
	}
	return false
}

// Net says what is known about an address's network.
func (l *Locator) Net(addr string) NetInfo {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return NetInfo{}
	}
	ip = ip.Unmap()
	var n NetInfo
	if l.ASNDB != nil {
		if rec, err := l.ASNDB.Lookup(ip); err == nil && rec != nil {
			if v, ok := rec["autonomous_system_number"].(uint64); ok && v <= math.MaxUint32 {
				n.ASN = uint32(v)
			}
			n.Org, _ = rec["autonomous_system_organization"].(string)
		}
	}
	switch {
	case l.Tor[ip.String()]:
		n.Anon = "tor"
	case n.Org != "" && Hosting(n.Org):
		n.Anon = "hosting"
	}
	return n
}

// ParseTorExits reads the Tor Project's bulk exit list: one address a line.
func ParseTorExits(b []byte) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if ip, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil {
			out[ip.Unmap().String()] = true
		}
	}
	return out
}
