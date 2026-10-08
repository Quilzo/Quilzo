// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func resolver(t *testing.T, proxies ...string) *Resolver {
	t.Helper()
	ps, err := ParseProxies(proxies)
	if err != nil {
		t.Fatal(err)
	}
	return &Resolver{Proxies: ps}
}

func from(r *Resolver, remote string, xff ...string) Client {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remote
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	return r.From(req)
}

func TestWithNoProxyTheConnectionIsTheClient(t *testing.T) {
	r := resolver(t)
	c := from(r, "203.0.113.9:4000", "127.0.0.1")
	if c.Addr.String() != "203.0.113.9" || c.Via != Connection || c.Internal {
		t.Fatalf("%+v", c)
	}
	// A nil resolver is the same: nothing is believed.
	if c := from(nil, "203.0.113.9:1", "10.0.0.1"); c.Addr.String() != "203.0.113.9" {
		t.Fatalf("%+v", c)
	}
}

func TestAClientCannotChooseItsAddressByReachingThePortDirectly(t *testing.T) {
	// The Mastodon shape (CVE-2023-49952): a direct caller claiming to be
	// loopback. The header is only read from a named proxy.
	r := resolver(t, "10.0.0.0/8")
	c := from(r, "198.51.100.7:5000", "127.0.0.1")
	if c.Addr.String() != "198.51.100.7" || c.Via != Connection {
		t.Fatalf("a direct caller chose its address: %+v", c)
	}
}

func TestTheRightmostAddressThatIsNotAProxyIsTheClient(t *testing.T) {
	r := resolver(t, "10.0.0.0/8", "192.0.2.10")
	cases := []struct {
		name string
		xff  []string
		want string
	}{
		{"one hop", []string{"203.0.113.9"}, "203.0.113.9"},
		{"client wrote some first", []string{"1.1.1.1, 2.2.2.2, 203.0.113.9"}, "203.0.113.9"},
		{"two proxies", []string{"203.0.113.9, 192.0.2.10"}, "203.0.113.9"},
		// HAProxy appends a header line of its own; Get would read the
		// client's line.
		{"a second line", []string{"1.1.1.1", "203.0.113.9"}, "203.0.113.9"},
		{"with a port", []string{"203.0.113.9:443"}, "203.0.113.9"},
		{"IPv6 with a port", []string{"[2001:db8::9]:443"}, "2001:db8::9"},
		{"IPv6 bracketed", []string{"[2001:db8::9]"}, "2001:db8::9"},
		{"IPv4 in IPv6", []string{"::ffff:203.0.113.9"}, "203.0.113.9"},
		{"zone dropped", []string{"fe80::1%eth0, 203.0.113.9"}, "203.0.113.9"},
		{"spaces", []string{" 203.0.113.9 ,10.1.2.3 "}, "203.0.113.9"},
	}
	for _, tc := range cases {
		c := from(r, "10.0.0.2:80", tc.xff...)
		if c.Addr.String() != tc.want || c.Via != Forwarded || c.Internal {
			t.Errorf("%s: got %+v, want %s", tc.name, c, tc.want)
		}
		if c.Peer.String() != "10.0.0.2" {
			t.Errorf("%s: peer %s", tc.name, c.Peer)
		}
	}
}

func TestWhatDoesNotParseIsUnknownNotGuessed(t *testing.T) {
	r := resolver(t, "10.0.0.0/8")
	for _, xff := range [][]string{
		{"garbage"},
		{"203.0.113.9, unknown"},
		{"203.0.113.9, _hidden"},
		{"203.0.113.9, example.com"},
		{"203.0.113.9, 203.0.113.10:http"},
		{"203.0.113.9,"},
		{"203.0.113.9, " + strings.Repeat("1", maxEntry+1)},
	} {
		c := from(r, "10.0.0.2:80", xff...)
		if c.Known() || c.Via != Forwarded || c.Internal {
			t.Errorf("%q: %+v", xff, c)
		}
	}
	// Garbage left of the client is not looked at.
	if c := from(r, "10.0.0.2:80", "garbage, 203.0.113.9"); c.Addr.String() != "203.0.113.9" {
		t.Errorf("%+v", c)
	}
}

func TestAChainOfOnlyProxiesIsFromInside(t *testing.T) {
	r := resolver(t, "10.0.0.0/8")
	if c := from(r, "10.0.0.2:80"); !c.Internal || c.Addr.String() != "10.0.0.2" {
		t.Fatalf("no header: %+v", c)
	}
	if c := from(r, "10.0.0.2:80", "10.9.9.9, 10.0.0.3"); !c.Internal || c.Addr.String() != "10.9.9.9" {
		t.Fatalf("all proxies: %+v", c)
	}
	long := strings.TrimSuffix(strings.Repeat("10.0.0.1,", maxHops+1), ",")
	if c := from(r, "10.0.0.2:80", long); c.Known() || c.Internal {
		t.Fatalf("past the hop limit: %+v", c)
	}
}

func TestAConnectionThatIsNotAnAddressIsUnknown(t *testing.T) {
	r := resolver(t, "10.0.0.0/8")
	if c := from(r, "@", "203.0.113.9"); c.Known() || c.Via != Connection {
		t.Fatalf("%+v", c)
	}
}

func TestASourceIsAnAddressOrAnIPv6Slash64(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":           "203.0.113.9",
		"::ffff:203.0.113.9":    "203.0.113.9",
		"2001:db8:1:2:3:4:5:6":  "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1":  "2001:db8:1:2::/64",
		"[2001:db8:1:2::9]:443": "2001:db8:1:2::/64",
	}
	for in, want := range cases {
		if got := SourceOf(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	if Source(netip.Addr{}) != "" || SourceOf("not an address") != "not an address" {
		t.Fatal("unknown")
	}
	c := Client{Addr: netip.MustParseAddr("2001:db8:1:2::7")}
	if c.Source() != "2001:db8:1:2::/64" {
		t.Fatal(c.Source())
	}
}

func TestLocalCoversWhatIsPrivateIsNot(t *testing.T) {
	in := []string{"127.0.0.1", "10.1.2.3", "172.31.0.1", "192.168.1.1", "100.64.0.1",
		"100.127.255.254", "169.254.1.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "0.1.2.3"}
	out := []string{"8.8.8.8", "203.0.113.9", "100.128.0.1", "172.32.0.1", "2001:4860::8888", "1.1.1.1"}
	for _, s := range in {
		if !Local(netip.MustParseAddr(s)) {
			t.Errorf("%s is inside", s)
		}
	}
	for _, s := range out {
		if Local(netip.MustParseAddr(s)) {
			t.Errorf("%s is not inside", s)
		}
	}
}

func TestProxiesAreRangesOrAddresses(t *testing.T) {
	ps, err := ParseProxies([]string{"10.0.0.0/8", " 192.0.2.10 ", "", "2001:db8::/32", "::ffff:198.51.100.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.10/32", "2001:db8::/32", "198.51.100.0/24"}
	if len(ps) != len(want) {
		t.Fatal(ps)
	}
	for i := range ps {
		if ps[i].String() != want[i] {
			t.Errorf("%d: %s, want %s", i, ps[i], want[i])
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "proxy.internal", "10.0.0"} {
		if _, err := ParseProxies([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"203.0.113.9", "[::1]:80", "fe80::1%eth0", "::ffff:1.2.3.4", "1.2.3.4:", "[", "]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, ok := Parse(s)
		if ok != a.IsValid() {
			t.Fatalf("%q: ok %v addr %v", s, ok, a)
		}
		if ok && (a.Zone() != "" || a.Is4In6() || a.IsUnspecified()) {
			t.Fatalf("%q: not clean: %v", s, a)
		}
		if ok && Source(a) == "" {
			t.Fatalf("%q: no source", s)
		}
	})
}

func TestTheEdgeDecidesOnceForEverythingBehindIt(t *testing.T) {
	var got []string
	h := Middleware(func() *Resolver { return resolver(t, "10.0.0.0/8") },
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = append(got, SourceFrom(r), AddrFrom(r))
		}))
	for _, tc := range []struct{ remote, xff string }{
		{"10.0.0.2:80", "2001:db8:1:2::9"},
		{"198.51.100.7:1", "127.0.0.1"},
		{"10.0.0.2:80", "nonsense"},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remote
		req.Header.Set("X-Forwarded-For", tc.xff)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	want := []string{"2001:db8:1:2::/64", "2001:db8:1:2::9", "198.51.100.7", "198.51.100.7", "10.0.0.2", "10.0.0.2"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// Called directly, with no edge: the connection, as before.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:4000"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	if SourceFrom(req) != "203.0.113.9" || AddrFrom(req) != "203.0.113.9" {
		t.Fatal(SourceFrom(req))
	}
	req.RemoteAddr = "@"
	if SourceFrom(req) != "@" {
		t.Fatal(SourceFrom(req))
	}
	// Nil everything believes nothing.
	Middleware(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := FromRequest(r); c.Via != Connection {
			t.Fatalf("%+v", c)
		}
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestPaddingTheHeaderCannotHideTheClient(t *testing.T) {
	// The proxy appends the real address after whatever the client wrote,
	// however much that is.
	r := resolver(t, "10.0.0.0/8")
	for _, junk := range []string{strings.Repeat("a", 5000), strings.Repeat("1.1.1.1,", 2000), strings.Repeat(",", 9000)} {
		c := from(r, "10.0.0.2:80", junk+", 203.0.113.9")
		if c.Addr.String() != "203.0.113.9" {
			t.Fatalf("padding hid the client: %+v", c)
		}
	}
	// And as a separate line, the way HAProxy appends.
	if c := from(r, "10.0.0.2:80", strings.Repeat("x", 9000), "203.0.113.9"); c.Addr.String() != "203.0.113.9" {
		t.Fatalf("%+v", c)
	}
}

func TestAForwardedAddressTheShieldCannotTrustIsMarked(t *testing.T) {
	// An unnamed peer that forwards: a CDN edge, or somebody writing a header.
	none := resolver(t)
	for _, h := range []string{"X-Forwarded-For", "Forwarded", "CF-Connecting-IP", "True-Client-IP"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "104.16.1.1:443"
		req.Header.Set(h, "203.0.113.9")
		if c := none.From(req); !c.Unverified || c.Addr.String() != "104.16.1.1" {
			t.Errorf("%s: %+v", h, c)
		}
	}
	if c := from(none, "104.16.1.1:443"); c.Unverified {
		t.Fatal("a plain connection was marked")
	}
	// Proxies assumed from "on the inside", not named.
	assumed := &Resolver{Proxies: Inside(), Assumed: true}
	if c := from(assumed, "10.0.0.2:80", "203.0.113.9"); !c.Unverified || c.Addr.String() != "203.0.113.9" {
		t.Fatalf("assumed: %+v", c)
	}
	named := resolver(t, "10.0.0.2")
	if c := from(named, "10.0.0.2:80", "203.0.113.9"); c.Unverified {
		t.Fatalf("named: %+v", c)
	}
}
