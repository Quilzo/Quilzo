// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package action

import (
	"io"
	"strings"
	"testing"
)

func suspend(t *testing.T) Action {
	t.Helper()
	c, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	a, err := c["okta-suspend-user"].For("", "acme")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEveryShippedActionSaysWhatItDoesAndHowItIsPutBack(t *testing.T) {
	c, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	if len(c) < 2 {
		t.Fatalf("%d actions ship", len(c))
	}
	for name, e := range c {
		for region := range e.Hosts {
			a, err := e.For(region, "acme")
			if err != nil {
				t.Errorf("%s/%s: %v", name, region, err)
				continue
			}
			if !strings.HasPrefix(a.Host, "acme.") {
				t.Errorf("%s/%s reaches %s", name, region, a.Host)
			}
		}
		if strings.TrimSpace(e.Credential) == "" || strings.TrimSpace(e.About) == "" {
			t.Errorf("%s does not explain its credential or itself", name)
		}
		if e.Action.Undo == nil && !strings.Contains(e.Action.Reverts, "cannot be undone") {
			t.Errorf("%s has no undo and does not say so", name)
		}
		for _, bad := range []string{"", "acme.evil.com", "a/b", "ACME..", "-x"} {
			if _, err := e.For("", bad); err == nil {
				t.Errorf("%s was installed for the organisation %q", name, bad)
			}
		}
		if _, err := e.For("mars", "acme"); err == nil {
			t.Errorf("%s was installed for a region it does not have", name)
		}
	}
}

// One identifier, of the platform's own shape, as one path segment. Nothing
// else reaches the request.
func TestTheRequestIsFixedButForOneCheckedIdentifier(t *testing.T) {
	a := suspend(t)
	req, err := a.Build("00u1a2b3c4d5e6f7", false)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL.String() !=
		"https://acme.okta.com/api/v1/users/00u1a2b3c4d5e6f7/lifecycle/suspend" {
		t.Errorf("%s %s", req.Method, req.URL)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("the package set a credential; whoever sends it does")
	}
	undo, err := a.Build("00u1a2b3c4d5e6f7", true)
	if err != nil || !strings.HasSuffix(undo.URL.Path, "/lifecycle/unsuspend") {
		t.Errorf("undo: %v %v", undo, err)
	}
	if got := a.Says("00u1a2b3c4d5e6f7", false); got !=
		"POST https://acme.okta.com/api/v1/users/00u1a2b3c4d5e6f7/lifecycle/suspend" {
		t.Errorf("says %q", got)
	}
	for _, bad := range []string{"", "00u1/../../groups", "00u1a2b3c4d5e6f7/lifecycle/activate",
		"00u1a2b3c4d5e6f7?x=1", "00u1a2b3c4d5e6f7#", "dana@acme.com", "../00u1a2b3c4d5e6f7",
		"00u1a2b3c4d5e6f7%2f..", "00u1a2b3c4d5e6f7\n", "me", "00g1a2b3c4d5e6f7"} {
		if req, err := a.Build(bad, false); err == nil {
			t.Errorf("a target of %q became %s", bad, req.URL)
		}
	}
	// An action with no undo says so instead of building one.
	c, _ := Catalogue()
	clear, _ := c["okta-clear-sessions"].For("", "acme")
	if _, err := clear.Build("00u1a2b3c4d5e6f7", true); err == nil ||
		!strings.Contains(err.Error(), "cannot be undone") {
		t.Errorf("an irreversible action built an undo: %v", err)
	}
	if req, _ := clear.Build("00u1a2b3c4d5e6f7", false); req.Method != "DELETE" {
		t.Errorf("clear sessions is a %s", req.Method)
	}
}

func TestAnActionThatCouldDoMoreThanItSaysIsRefused(t *testing.T) {
	ok := suspend(t)
	for name, change := range map[string]func(*Action){
		"a read":                     func(a *Action) { a.Does.Method = "GET" },
		"no place for the target":    func(a *Action) { a.Does.Path = "/api/v1/users/all/lifecycle/suspend" },
		"two places":                 func(a *Action) { a.Does.Path = "/api/v1/{target}/{target}" },
		"a second thing that varies": func(a *Action) { a.Does.Path = "/api/v1/users/{target}/{verb}" },
		"a query":                    func(a *Action) { a.Does.Path = "/api/v1/users/{target}?sendEmail=true" },
		"a path that climbs":         func(a *Action) { a.Does.Path = "/api/v1/../{target}" },
		"a body built from the target": func(a *Action) {
			a.Does.Body = `{"id":"{target}"}`
		},
		"a body that is not JSON":    func(a *Action) { a.Does.Body = "suspend=true" },
		"a host with a path":         func(a *Action) { a.Host = "acme.okta.com/x" },
		"an address for a host":      func(a *Action) { a.Host = "10.0.0.5" },
		"a wildcard host":            func(a *Action) { a.Host = "*.okta.com" },
		"the connector's credential": func(a *Action) { a.Secret = "okta-api-token" },
		"a pattern open at the end":  func(a *Action) { a.Target.Pattern = "^00u" },
		"nothing about its effect":   func(a *Action) { a.Effect = " " },
		"nothing about undoing":      func(a *Action) { a.Reverts = "" },
		"an undo that reads":         func(a *Action) { a.Undo = &Request{Method: "GET", Path: "/x/{target}"} },
	} {
		bad := ok
		if ok.Undo != nil {
			u := *ok.Undo
			bad.Undo = &u
		}
		change(&bad)
		if bad.Validate() == nil {
			t.Errorf("an action with %s was accepted", name)
		}
	}
	// A constant body is sent as written.
	with := ok
	with.Does.Body = `{"accountEnabled":false}`
	req, err := with.Build("00u1a2b3c4d5e6f7", false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(req.Body)
	if string(b) != `{"accountEnabled":false}` || req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("body %q", b)
	}
}
