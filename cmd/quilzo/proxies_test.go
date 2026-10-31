// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	// "On this machine": a reverse proxy on loopback is believed; a machine
	// on a private network, a container bridge or carrier-grade NAT is not,
	// and neither is the internet.
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	for _, remote := range []string{"127.0.0.1:80", "[::1]:80"} {
		if got := from(cfg, "site.trusted_proxy", remote, "203.0.113.9"); got != "203.0.113.9" {
			t.Fatalf("a proxy on this machine (%s) was not believed: %s", remote, got)
		}
	}
	for _, remote := range []string{"172.17.0.1:80", "10.0.0.5:80", "192.168.1.5:80", "100.64.0.1:80", "198.51.100.7:80"} {
		want := remote[:len(remote)-3]
		if got := from(cfg, "site.trusted_proxy", remote, "203.0.113.9"); got != want {
			t.Fatalf("%s chose its address without being named: %s", want, got)
		}
	}
	// The other surface's switch is not this one's.
	if got := from(cfg, "admin.trusted_proxy", "127.0.0.1:80", "203.0.113.9"); got != "127.0.0.1" {
		t.Fatalf("the site's setting opened the admin: %s", got)
	}
	// Named, a machine on the private network is believed, and loopback is
	// no longer assumed.
	if err := cfg.Set("network.trusted_proxies", "172.17.0.1", "", "test"); err != nil {
		t.Fatal(err)
	}
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("a named proxy on a private network was not believed: %s", got)
	}
	if got := from(cfg, "site.trusted_proxy", "127.0.0.1:80", "203.0.113.9"); got != "127.0.0.1" {
		t.Fatalf("loopback is still assumed once proxies are named: %s", got)
	}
	if err := cfg.Set("network.trusted_proxies", "192.0.2.10", "", "test"); err != nil {
		t.Fatal(err)
	}
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("a proxy that is no longer named is still believed: %s", got)
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

func TestAMachineOnTheNetworkThatForwardsIsToldHowToNameIt(t *testing.T) {
	cfg := config.New()
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	resolve := func() *clientip.Resolver { return resolverFrom(cfg, "site.trusted_proxy") }
	var out bytes.Buffer
	h := clientip.Middleware(resolve, unbelieved("site.trusted_proxy", resolve, &out, http.NotFoundHandler()))
	send := func(remote, xff string) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	send("172.17.0.1:80", "203.0.113.9")
	if !strings.Contains(out.String(), "172.17.0.1 sent X-Forwarded-For and is not believed") ||
		!strings.Contains(out.String(), "quilzo config set network.trusted_proxies 172.17.0.1") {
		t.Fatalf("%q", out.String())
	}
	// Once for each machine, and not for the proxy on this machine (it is
	// believed), a machine that forwards nothing, or the internet.
	n := out.Len()
	send("172.17.0.1:80", "203.0.113.9")
	send("127.0.0.1:80", "203.0.113.9")
	send("10.0.0.5:80", "")
	send("198.51.100.7:80", "203.0.113.9")
	if out.Len() != n {
		t.Fatalf("said again, or for the wrong machine: %q", out.String()[n:])
	}
	// A network full of machines writing the header cannot fill the log.
	for i := 0; i < maxUnbelieved*2; i++ {
		send(fmt.Sprintf("10.1.0.%d:80", i+1), "203.0.113.9")
	}
	if got := strings.Count(out.String(), "is not believed"); got != maxUnbelieved {
		t.Fatalf("named %d machines, want %d", got, maxUnbelieved)
	}
	// With proxies named, the deployment has said which they are.
	if err := cfg.Set("network.trusted_proxies", "192.0.2.10", "", "test"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	h = clientip.Middleware(resolve, unbelieved("site.trusted_proxy", resolve, &out, http.NotFoundHandler()))
	send("10.2.0.1:80", "203.0.113.9")
	if out.Len() != 0 {
		t.Fatalf("%q", out.String())
	}
}

func TestASurfaceThatAssumesItsProxySaysWhereItBelievesItFrom(t *testing.T) {
	root := t.TempDir()
	cfg := config.New()
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if line := assumedProxy(root, "site.trusted_proxy"); !strings.Contains(line, "this machine only") ||
		!strings.Contains(line, "network.trusted_proxies") {
		t.Fatalf("%q", line)
	}
	if line := assumedProxy(root, "admin.trusted_proxy"); line != "" {
		t.Fatalf("the admin, with no proxy, said %q", line)
	}
	if err := cfg.Set("network.trusted_proxies", "10.0.0.5", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if line := assumedProxy(root, "site.trusted_proxy"); line != "" {
		t.Fatalf("with its proxy named, the site said %q", line)
	}
}
