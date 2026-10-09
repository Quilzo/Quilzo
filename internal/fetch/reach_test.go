// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package fetch

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// -- declared reach -----------------------------------------------------------

// A range may be opened when it lies inside one private network or loopback,
// and is written as where it starts. Everything else is refused, and the
// refusal says why.
func TestOnlyPrivateRangesMayBeDeclared(t *testing.T) {
	for _, ok := range []string{
		"10.0.0.0/8", "10.20.0.0/16", "10.20.30.40/32", "172.16.0.0/12", "172.20.1.0/24",
		"192.168.0.0/16", "100.64.0.0/10", "127.0.0.1/32", "::1/128", "fd12:3456::/32",
	} {
		if why := Declarable(netip.MustParsePrefix(ok)); why != "" {
			t.Errorf("%s was refused: %s", ok, why)
		}
	}
	for raw, want := range map[string]string{
		"169.254.169.254/32":  "link-local",
		"169.254.0.0/16":      "link-local",
		"fe80::/10":           "link-local",
		"0.0.0.0/0":           "nothing may reach it",
		"10.0.0.0/7":          "wider than the private network",
		"172.0.0.0/8":         "wider than the private network",
		"8.8.8.0/24":          "public",
		"224.0.0.0/4":         "multicast",
		"64:ff9b::/96":        "NAT64",
		"::ffff:10.0.0.0/104": "write it as IPv4",
		"10.20.30.40/16":      "write 10.20.0.0/16",
	} {
		why := Declarable(netip.MustParsePrefix(raw))
		if !strings.Contains(why, want) {
			t.Errorf("%s: want a refusal mentioning %q, got %q", raw, want, why)
		}
	}
}

// The declared range opens exactly that range: the next one along is still
// refused, and the metadata address is refused whatever is declared.
func TestADeclaredRangeOpensOnlyItself(t *testing.T) {
	c := New()
	c.Reach = Within([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	for ip, open := range map[string]bool{
		"10.20.1.2":        true,
		"10.21.0.1":        false,
		"192.168.1.1":      false,
		"169.254.169.254":  false,
		"127.0.0.1":        false,
		"::ffff:10.20.1.2": true,
	} {
		if got := c.checkIP(net.ParseIP(ip)) == ""; got != open {
			t.Errorf("%s: open %v, want %v", ip, got, open)
		}
	}
	// A range that is not declarable is never opened, even if a caller
	// builds a client with one.
	c.Reach = Within([]netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("0.0.0.0/0")})
	for _, ip := range []string{"169.254.169.254", "10.20.1.2", "127.0.0.1"} {
		if c.checkIP(net.ParseIP(ip)) == "" {
			t.Errorf("%s was opened by a range nobody may declare", ip)
		}
	}
}

// Every answer a name resolves to has to fall inside the declaration, so a
// name that also answers with an address outside it is refused, as a split
// answer is everywhere else.
func TestADeclaredNameIsCheckedOnEveryAnswer(t *testing.T) {
	c := New()
	c.Reach = Within([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	c.Resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.20.1.2"), net.ParseIP("10.30.0.1")}, nil
	}
	_, err := c.Do(context.Background(), http.MethodPost, "https://tools.corp.example/mcp", []byte(`{}`), nil)
	if err == nil || !strings.Contains(err.Error(), "outside the ranges declared") {
		t.Fatalf("a name answering outside the declared range: %v", err)
	}
}

// With the range declared, the connection is made: what stops it here is the
// test server's certificate, which no system trusts, and not the address.
// Without it, the same request is refused before a packet is sent.
func TestADeclaredServerIsReached(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := New()
	_, err := c.Do(context.Background(), http.MethodPost, srv.URL+"/mcp", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("an undeclared loopback server: %v", err)
	}
	c.Reach = Within([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	_, err = c.Do(context.Background(), http.MethodPost, srv.URL+"/mcp", nil, nil)
	if err == nil || strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a declared loopback server was not reached: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("stopped by something other than its certificate: %v", err)
	}
}
