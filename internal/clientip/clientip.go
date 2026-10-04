// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package clientip decides who a request came from, once, for everything
// that keys on it: rate limits, sign-in placement, the audit log's source
// handle, and the shield's blocks.
//
// It used to be decided six ways. The admin and the public site each read
// X-Forwarded-For behind a yes/no setting, with Header.Get, which returns
// only the first header line; the API, forms, SCIM and studio read the
// connection. Behind a proxy that meant the limits keyed on the proxy (one
// bucket for the whole internet), and where the header was believed it was
// believed from anybody who could reach the port, so a caller chose their
// own address. A block keyed one way and a signal keyed another would never
// meet.
//
// # The rule
//
// A forwarded address is believed only when the connection itself comes
// from a proxy the operator named (nginx set_real_ip_from, Envoy
// xff_trusted_cidrs, Caddy trusted_proxies all do the same). The header
// lines are joined in order, because a proxy that appends a second line
// (HAProxy) would otherwise be read as the client's own first line; then the
// entries are walked from the right, skipping the named proxies, and the
// first one that is not a proxy is the client. Anything that does not parse
// before that point stops the walk: the address is unknown, never guessed
// from what is left.
//
// # The unit of a source
//
// One IPv4 address, or one IPv6 /64. A host owns its /64 (RFC 4291) and
// picks new addresses inside it daily (RFC 8981), so counting or blocking a
// single IPv6 address is counting something its owner changes at will.
package clientip

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// How an address was learnt.
const (
	Connection = "connection"
	Forwarded  = "x-forwarded-for"
)

// Limits on what a request may make this read.
const (
	maxHeader = 4096
	maxHops   = 16
)

// Client is who a request came from.
type Client struct {
	// Addr is the client's address; invalid when it could not be told.
	Addr netip.Addr
	// Peer is the address of the connection itself.
	Peer netip.Addr
	// Via says whether Addr is the connection's or a proxy's report of it.
	Via string
	// Internal marks a request every hop of which was a named proxy: one
	// from inside, which nothing should block.
	Internal bool
}

// Known reports whether the client's address could be told.
func (c Client) Known() bool { return c.Addr.IsValid() }

// Source is the client as a source: one IPv4 address or one IPv6 /64, as a
// string, for counting, limiting and the audit log. Empty when unknown.
func (c Client) Source() string { return Source(c.Addr) }

// Resolver decides clients for one deployment.
type Resolver struct {
	// Proxies are the peers whose forwarded addresses are believed. Empty
	// means none: the connection is the client.
	Proxies []netip.Prefix
}

// trusted reports whether an address is one of the named proxies.
func (r *Resolver) trusted(a netip.Addr) bool {
	if r == nil {
		return false
	}
	for _, p := range r.Proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// From decides who a request came from.
func (r *Resolver) From(req *http.Request) Client {
	peer, _ := Parse(req.RemoteAddr)
	c := Client{Addr: peer, Peer: peer, Via: Connection}
	if !peer.IsValid() || !r.trusted(peer) {
		return c
	}
	lines := req.Header.Values("X-Forwarded-For")
	if len(lines) == 0 {
		// A request a proxy made itself: a health check, or something on
		// the inside.
		c.Internal = true
		return c
	}
	joined := strings.Join(lines, ",")
	c.Via, c.Addr = Forwarded, netip.Addr{}
	if len(joined) > maxHeader {
		return c
	}
	entries := strings.Split(joined, ",")
	var last netip.Addr
	for i, hops := len(entries)-1, 0; i >= 0; i, hops = i-1, hops+1 {
		if hops == maxHops {
			return c
		}
		a, ok := Parse(strings.TrimSpace(entries[i]))
		if !ok {
			return c
		}
		if !r.trusted(a) {
			c.Addr = a
			return c
		}
		last = a
	}
	c.Addr, c.Internal = last, true
	return c
}

type ctxKey struct{}

// Middleware decides each request's client once, at the edge, and hands it
// on with the request; everything behind reads it with FromRequest. resolve
// is called per request so a changed setting holds without a restart; nil,
// or a nil resolver, believes no proxy.
func Middleware(resolve func() *Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var res *Resolver
		if resolve != nil {
			res = resolve()
		}
		next.ServeHTTP(w, With(r, res.From(r)))
	})
}

// With is a request carrying its client.
func With(r *http.Request, c Client) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, c))
}

// FromRequest is who a request came from: as the edge decided, or, for a
// request that did not pass one (a handler called directly), its
// connection.
func FromRequest(r *http.Request) Client {
	if c, ok := r.Context().Value(ctxKey{}).(Client); ok {
		return c
	}
	return (*Resolver)(nil).From(r)
}

// SourceFrom is a request's source, for limits and the audit log. When the
// client could not be told it is the connection's, which is what every
// limit keyed on before; when even that is not an address, the connection
// as written.
func SourceFrom(r *http.Request) string {
	c := FromRequest(r)
	if c.Known() {
		return c.Source()
	}
	if c.Peer.IsValid() {
		return Source(c.Peer)
	}
	return r.RemoteAddr
}

// AddrFrom is a request's client address itself, for placing it on a map;
// the connection's when the client could not be told.
func AddrFrom(r *http.Request) string {
	c := FromRequest(r)
	switch {
	case c.Known():
		return c.Addr.String()
	case c.Peer.IsValid():
		return c.Peer.String()
	}
	return r.RemoteAddr
}

// Parse reads an address as a connection or a proxy writes one: "IP",
// "IP:port", "[IPv6]" or "[IPv6]:port". The zone is dropped and an IPv4
// address carried in IPv6 is unwrapped, so one host has one spelling.
// Anything else ("unknown", an obfuscated identifier, a name) is not an
// address.
func Parse(s string) (netip.Addr, bool) {
	if s == "" || len(s) > 64 {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return clean(a)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil && a.Is6() {
			return clean(a)
		}
		return netip.Addr{}, false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || port == "" {
		return netip.Addr{}, false
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return netip.Addr{}, false
		}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	// "1.2.3.4:80" is IPv4 with a port; an IPv6 address with a port must
	// have been bracketed, and SplitHostPort insists on that already.
	return clean(a)
}

func clean(a netip.Addr) (netip.Addr, bool) {
	a = a.WithZone("").Unmap()
	if !a.IsValid() || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a, true
}

// Unit is the prefix a source stands for: the address itself for IPv4, its
// /64 for IPv6.
func Unit(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p
	}
	p, _ := a.Prefix(a.BitLen())
	return p
}

// Source is an address as a source: "203.0.113.9" or "2001:db8:1:2::/64".
// The IPv4 spelling is the plain address, the one the audit log has always
// recorded, so handles taken from older entries still match.
func Source(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	return Unit(a).String()
}

// SourceOf is Source for an address written as text, the way a hook hands
// one on; text that is not an address comes back as it was, so a caller
// that is handed something odd still has something to count.
func SourceOf(s string) string {
	if a, ok := Parse(s); ok {
		return Source(a)
	}
	return s
}

// local are the ranges IANA marks not globally reachable, and the ones a
// deployment's own network uses: an address in one of them is a machine on
// the inside, not somebody on the internet.
var local = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",      // this network
		"10.0.0.0/8",     // private
		"100.64.0.0/10",  // shared address space, carrier-grade NAT
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"172.16.0.0/12",  // private
		"192.0.0.0/24",   // IETF protocol assignments
		"192.168.0.0/16", // private
		"198.18.0.0/15",  // benchmarking
		"240.0.0.0/4",    // reserved
		"::1/128",        // loopback
		"::/128",         // unspecified
		"64:ff9b:1::/48", // local-use IPv4/IPv6 translation
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"2001:2::/48",    // benchmarking
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Local reports whether an address is on the inside: loopback, private,
// carrier-grade NAT, link-local or otherwise not reachable from the
// internet. netip's IsPrivate is not this; Go documents that it is not for
// access control, and it leaves out 100.64.0.0/10.
func Local(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range local {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Inside are the ranges Local covers, as prefixes: what a deployment that
// says "the proxy is on this machine or my network" trusts.
func Inside() []netip.Prefix { return append([]netip.Prefix(nil), local...) }

// ParseProxies reads a list of proxies as an operator writes them: CIDR
// ranges or single addresses, comma-separated.
func ParseProxies(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := ParseProxy(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseProxy reads one proxy range or address.
func ParseProxy(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, &ProxyError{Value: s}
		}
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr())).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ProxyError{Value: s}
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// unmapBits is how many leading bits an IPv4-mapped IPv6 prefix loses when
// it is written as IPv4.
func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

// ProxyError is a proxy that is not a range or an address.
type ProxyError struct{ Value string }

func (e *ProxyError) Error() string {
	return "\"" + e.Value + "\" is not an address or a range like 10.0.0.0/8 or 2001:db8::/32"
}
