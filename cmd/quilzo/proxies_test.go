// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
)

func TestTheEdgeBelievesOnlyTheProxiesTheConfigurationNames(t *testing.T) {
	from := func(cfg *config.Config, inside, remote, xff string) string {
		var got string
		h := clientip.Middleware(func() *clientip.Resolver { return resolverFrom(cfg, inside) },
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = clientip.SourceFrom(r) }))
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr, req.Header["X-Forwarded-For"] = remote, []string{xff}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}
	cfg := config.New()
	// Nothing said: the connection, whatever the header claims.
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("believed with nothing configured: %s", got)
	}
	// "On the inside": a container gateway is believed, the internet is not.
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("the gateway was not believed: %s", got)
	}
	if got := from(cfg, "site.trusted_proxy", "198.51.100.7:80", "203.0.113.9"); got != "198.51.100.7" {
		t.Fatalf("a caller on the internet chose its address: %s", got)
	}
	// The other surface's switch is not this one's.
	if got := from(cfg, "admin.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("the site's setting opened the admin: %s", got)
	}
	// Named proxies replace "the inside".
	if err := cfg.Set("network.trusted_proxies", "192.0.2.10", "", "test"); err != nil {
		t.Fatal(err)
	}
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("the inside is still believed once proxies are named: %s", got)
	}
	if got := from(cfg, "admin.trusted_proxy", "192.0.2.10:80", "2001:db8:1:2::9"); got != "2001:db8:1:2::/64" {
		t.Fatalf("a named proxy was not believed: %s", got)
	}
}

func TestANamedProxyRangeOfMostOfTheInternetNeedsAReason(t *testing.T) {
	cfg := config.New()
	if err := cfg.Set("network.trusted_proxies", "0.0.0.0/0", "", "test"); err == nil {
		t.Fatal("0.0.0.0/0 was set without a reason")
	}
	if err := cfg.Set("network.trusted_proxies", "10.0.0.0/8,2001:db8::/32", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("network.trusted_proxies", "proxy.internal", "", "test"); err == nil {
		t.Fatal("a name was accepted as a proxy")
	}
}

func TestAnUnreadableConfigurationBelievesNoProxy(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := proxies(root, "site.trusted_proxy")(); r == nil || len(r.Proxies) != 0 {
		t.Fatalf("%+v", r)
	}
}
