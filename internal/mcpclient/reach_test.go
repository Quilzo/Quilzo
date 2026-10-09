// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package mcpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// A server on the organisation's own network is reached when, and only
// when, its range is declared. Without it the refusal says what to do; with
// it the connection is made, and what stops this one is the test server's
// certificate, which nothing trusts.
func TestAServerOnTheOwnNetworkNeedsItsRangeDeclared(t *testing.T) {
	var asked int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { asked++ }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	in := integration("list_pages")
	in.Endpoint, in.Port, in.Path = "127.0.0.1", port, "/mcp"

	_, err := (&Client{}).Tools(context.Background(), in)
	if err == nil || !strings.Contains(err.Error(), "refusing") || !strings.Contains(err.Error(), "name its range") {
		t.Fatalf("an undeclared loopback server: %v", err)
	}

	in.Reach = []string{"127.0.0.1/32"}
	if err := in.Validate(); err != nil {
		t.Fatalf("a declared loopback server did not validate: %v", err)
	}
	_, err = (&Client{}).Tools(context.Background(), in)
	if err == nil || strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a declared loopback server was not reached: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("stopped by something other than its certificate: %v", err)
	}
	if asked != 0 {
		t.Errorf("a request reached a server whose certificate nothing trusts")
	}
}

// The ranges are applied to a client somebody supplied, too: a declaration
// is not a property of which constructor ran.
func TestTheRangesAreHeldOnEveryCall(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	in := integration("list_pages")
	in.Endpoint, in.Port = "127.0.0.1", port
	in.Reach = []string{"10.20.0.0/16"}
	_, err := (&Client{}).Tools(context.Background(), in)
	if err == nil || !strings.Contains(err.Error(), "outside the ranges declared") {
		t.Fatalf("a server outside its declared range: %v", err)
	}
}
