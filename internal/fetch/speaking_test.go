// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package fetch

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A redirect is refused rather than followed.
//
// None of the four protocols on the other end of these clients redirects, so
// following one is all risk and no function. For Telegram it is a credential
// leak and not an abstract risk: the bot token is a path segment of every
// call, so a redirect hands the credential to whoever the redirect names. Go
// strips the Authorization header across hosts and cannot strip a URL.
func TestAProtocolClientRefusesToFollowARedirect(t *testing.T) {
	var landed bool
	elsewhere := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			landed = true
			w.WriteHeader(http.StatusOK)
		}))
	defer elsewhere.Close()

	from := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/secret", http.StatusFound)
		}))
	defer from.Close()

	c := Speaking("chat", Anywhere, 5*time.Second)
	resp, err := c.Get(from.URL + "/bot12345:TOKEN/getMe")
	if err == nil {
		resp.Body.Close()
		t.Fatal("the redirect was followed")
	}
	if landed {
		t.Error("the request arrived at the redirect target, which for the " +
			"Bot API means the token in the path went with it")
	}
	if !strings.Contains(err.Error(), "not a protocol that redirects") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// The address rule runs at connect time, so it applies to an address no URL
// mentioned.
func TestAProtocolClientRefusesAnAddressTheRuleRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("the request was made; the rule did not run")
		}))
	defer srv.Close()

	// Public refuses loopback, which is what the test server is on.
	c := Speaking("timestamp", Public, 5*time.Second)
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("a loopback address was reached by a client whose rule is " +
			"Public")
	}
}

// And permits one it allows, so the rule is a rule rather than a wall.
//
// A check worth having has to let the correct case through; a client that
// refuses everything passes the test above and is useless.
func TestAProtocolClientReachesAnAddressTheRuleAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}))
	defer srv.Close()

	c := Speaking("telemetry", OnThisNetwork, 5*time.Second)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("a collector on loopback could not be reached: %v", err)
	}
	defer resp.Body.Close()
}

// What OnThisNetwork means, one address at a time.
func TestWhatCountsAsThisNetwork(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		allowed bool
		why     string
	}{
		{"127.0.0.1", true, "loopback is a collector on this machine"},
		{"::1", true, "the same, over v6"},
		{"10.0.0.5", true, "a private address is the network this is on"},
		{"192.168.1.20", true, "the same"},
		{"fc00::1", true, "the v6 private range"},
		{"169.254.169.254", false,
			"the cloud metadata endpoint, which hands out credentials"},
		{"fe80::1", false, "v6 link-local"},
		{"8.8.8.8", false,
			"public, and this rule is for an endpoint declared to be local"},
	} {
		why := OnThisNetwork(net.ParseIP(tc.addr))
		if tc.allowed && why != "" {
			t.Errorf("%s is refused (%s), and %s", tc.addr, why, tc.why)
		}
		if !tc.allowed && why == "" {
			t.Errorf("%s is permitted, and it is %s", tc.addr, tc.why)
		}
	}
}

// A client built with no rule refuses everything.
//
// The other way round is a client with no address rule at all and no symptom,
// which is the state this whole file exists to end.
func TestAClientWithNoRuleRefusesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	if _, err := Speaking("chat", nil, time.Second).Get(srv.URL); err == nil {
		t.Fatal("a client built with no address rule connected anyway, so " +
			"forgetting the argument is a silent hole rather than a failure")
	}
}

// An undeclared purpose is refused, which is what keeps the network report
// honest about every way this program can reach out.
func TestAnUndeclaredPurposeIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := Speaking("not-a-purpose", Anywhere, time.Second)
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("a connection was made for a purpose nothing declares, so " +
			"`quilzo network` cannot list what this program would connect to")
	}
}
